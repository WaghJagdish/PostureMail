"""Forensic analysis execution pipeline with Celery canvas orchestration.

Pipeline Topology:
  chord(
    group(parse_and_score_shard_task),  # Flow-safe sharded parallel parsing & scoring
    finalize_corpus_task.s()            # Merge + Corpus-level detectors (D1, D8, beaconing)
  ) | ml_scoring_task.s() | index_and_persist_task.s()

Key Constraints:
- Flow-safe sharding: Packets partitioned by hash of canonical 4-tuple flow key.
- Bounded memory & idempotent persistence on (analysis_id, session_id).
- Progress reporting every 50k packets via Celery custom states.
"""

from __future__ import annotations

import logging
import zlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from celery import chord, group

from pecff.api.deps import StorageService
from pecff.api.routers.analyses import register_analysis
from pecff.api.routers.tasks import update_task_state
from pecff.api.schemas import (
    AnalysisDetailResponse,
    FindingSchema,
    MLAnomalyResultSchema,
    RiskResultSchema,
    SessionDetailSchema,
    TemporalBehaviorSchema,
)
import struct
from pecff.config import settings
from pecff.crypto.cipher_db import cipher_db
from pecff.crypto.risk_engine import NISTDeterministicRiskScorer, SessionCryptoParameters
from pecff.crypto.x509_parser import X509Parser
from pecff.ingest.reader import PcapReader
from pecff.ingest.reassembly import StreamReassembler
from pecff.engine.corpus_correlator import run_corpus_correlation
from pecff.ml.features import FeatureStore, SessionFeatureExtractor, SessionFeatureVectorizer
from pecff.ml.fingerprints import calculate_ja3, calculate_ja4
from pecff.parse.classify import ProtocolClassifier
from pecff.parse.starttls_fsm import Direction, StarttlsFSM
from pecff.parse.tls_decoder import (
    ClientHelloInfo,
    ExtensionType,
    ServerHelloInfo,
    TLSExtension,
    TLSHandshakeDecoder,
    TLSHandshakeSummary,
    is_grease,
)
from pecff.tasks.celery_app import celery_app, get_preloaded_ml_model, get_preloaded_vectorizer

logger = logging.getLogger("pecff.pipeline")


class TransientError(Exception):
    """Recoverable network/I/O transient error triggering automated retry."""

    pass


TLS_VERSION_MAP: Final[dict[int, str]] = {
    0x0200: "SSL 2.0",
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

NAMED_GROUP_MAP: Final[dict[int, str]] = {
    0x0015: "secp192r1",
    0x0016: "secp224r1",
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001D: "x25519",
    0x001E: "x448",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x0102: "ffdhe4096",
}


def resolve_protocol_version(tls_summary: TLSHandshakeSummary, fsm: StarttlsFSM) -> str:
    """Resolve standard or explicit unknown TLS protocol version representation."""
    if tls_summary.server_hello and tls_summary.server_hello.selected_version:
        ver = tls_summary.server_hello.selected_version
        return TLS_VERSION_MAP.get(ver, f"UNKNOWN (0x{ver:04X})")
    if tls_summary.client_hello and tls_summary.client_hello.legacy_version:
        ver = tls_summary.client_hello.legacy_version
        return TLS_VERSION_MAP.get(ver, f"UNKNOWN (0x{ver:04X})")
    return "NONE"


def serialize_handshake_summary(summary: TLSHandshakeSummary | None) -> dict[str, Any] | None:
    """Serialize TLSHandshakeSummary into JSON-serializable primitives for Celery transit."""
    if summary is None or (summary.client_hello is None and summary.server_hello is None):
        return None

    ch_dict = None
    if summary.client_hello:
        ch = summary.client_hello
        ch_dict = {
            "legacy_version": ch.legacy_version,
            "random": ch.random.hex() if ch.random else "",
            "session_id": ch.session_id.hex() if ch.session_id else "",
            "cipher_suites": list(ch.cipher_suites),
            "compression_methods": list(ch.compression_methods),
            "extensions": [
                {
                    "ext_type": ext.ext_type,
                    "name": ext.name,
                    "length": ext.length,
                    "data": ext.data.hex() if ext.data else "",
                    "parsed_value": ext.parsed_value,
                }
                for ext in ch.extensions.values()
            ],
            "supported_groups": list(ch.supported_groups),
            "ec_point_formats": list(ch.ec_point_formats),
            "signature_algorithms": list(ch.signature_algorithms),
            "alpn_protocols": list(ch.alpn_protocols),
            "server_name": ch.server_name,
        }

    sh_dict = None
    if summary.server_hello:
        sh = summary.server_hello
        sh_dict = {
            "legacy_version": sh.legacy_version,
            "selected_version": sh.selected_version,
            "random": sh.random.hex() if sh.random else "",
            "session_id_echo": sh.session_id_echo.hex() if sh.session_id_echo else "",
            "selected_cipher": sh.selected_cipher,
            "selected_compression": sh.selected_compression,
            "extensions": [
                {
                    "ext_type": ext.ext_type,
                    "name": ext.name,
                    "length": ext.length,
                    "data": ext.data.hex() if ext.data else "",
                    "parsed_value": ext.parsed_value,
                }
                for ext in sh.extensions.values()
            ],
            "selected_alpn": sh.selected_alpn,
        }

    return {
        "client_hello": ch_dict,
        "server_hello": sh_dict,
        "certificates_der": [c.hex() for c in summary.certificates_der],
        "cert_analysis_possible": summary.cert_analysis_possible,
        "handshake_completed": summary.handshake_completed,
    }


def deserialize_handshake_summary(data: dict[str, Any] | None) -> TLSHandshakeSummary | None:
    """Reconstruct TLSHandshakeSummary from serialized primitives."""
    if not data:
        return None

    ch = None
    if data.get("client_hello"):
        d_ch = data["client_hello"]
        ch_exts: dict[int, TLSExtension] = {}
        for ed in d_ch.get("extensions", []):
            ext = TLSExtension(
                ext_type=ed["ext_type"],
                name=ed["name"],
                length=ed["length"],
                data=bytes.fromhex(ed["data"]) if ed.get("data") else b"",
                parsed_value=ed.get("parsed_value"),
            )
            ch_exts[ext.ext_type] = ext

        ch = ClientHelloInfo(
            legacy_version=d_ch.get("legacy_version", 0x0303),
            random=bytes.fromhex(d_ch.get("random", "")),
            session_id=bytes.fromhex(d_ch.get("session_id", "")),
            cipher_suites=d_ch.get("cipher_suites", []),
            compression_methods=d_ch.get("compression_methods", [0]),
            extensions=ch_exts,
            supported_groups=d_ch.get("supported_groups", []),
            ec_point_formats=d_ch.get("ec_point_formats", []),
            signature_algorithms=d_ch.get("signature_algorithms", []),
            alpn_protocols=d_ch.get("alpn_protocols", []),
            server_name=d_ch.get("server_name"),
        )

    sh = None
    if data.get("server_hello"):
        d_sh = data["server_hello"]
        sh_exts: dict[int, TLSExtension] = {}
        for ed in d_sh.get("extensions", []):
            ext = TLSExtension(
                ext_type=ed["ext_type"],
                name=ed["name"],
                length=ed["length"],
                data=bytes.fromhex(ed["data"]) if ed.get("data") else b"",
                parsed_value=ed.get("parsed_value"),
            )
            sh_exts[ext.ext_type] = ext

        sh = ServerHelloInfo(
            legacy_version=d_sh.get("legacy_version", 0x0303),
            selected_version=d_sh.get("selected_version", 0x0303),
            random=bytes.fromhex(d_sh.get("random", "")),
            session_id_echo=bytes.fromhex(d_sh.get("session_id_echo", "")),
            selected_cipher=d_sh.get("selected_cipher", 0),
            selected_compression=d_sh.get("selected_compression", 0),
            extensions=sh_exts,
            selected_alpn=d_sh.get("selected_alpn"),
        )

    certs_der = [bytes.fromhex(c) for c in data.get("certificates_der", [])]
    return TLSHandshakeSummary(
        client_hello=ch,
        server_hello=sh,
        certificates_der=certs_der,
        cert_analysis_possible=bool(data.get("cert_analysis_possible", True)),
        handshake_completed=bool(data.get("handshake_completed", False)),
    )


def compute_canonical_flow_hash(payload: memoryview | bytes, vlan_id: int | None) -> int | None:
    """Compute canonical 5-tuple + VLAN flow hash identical to StreamReassembler FlowKey."""
    if len(payload) < 20:
        return None
    ip_v = payload[0] >> 4
    if ip_v == 4:
        ihl = (payload[0] & 0x0F) * 4
        if len(payload) < ihl + 4:
            return None
        proto = payload[9]
        src_ip = bytes(payload[12:16])
        dst_ip = bytes(payload[16:20])
        src_port, dst_port = struct.unpack_from(">HH", payload, ihl)
    elif ip_v == 6:
        if len(payload) < 40 + 4:
            return None
        proto = payload[6]
        src_ip = bytes(payload[8:24])
        dst_ip = bytes(payload[24:40])
        src_port, dst_port = struct.unpack_from(">HH", payload, 40)
    else:
        return None

    ep_a = (src_ip, src_port)
    ep_b = (dst_ip, dst_port)
    first_ep, second_ep = min(ep_a, ep_b), max(ep_a, ep_b)
    key_bytes = (
        first_ep[0]
        + struct.pack(">H", first_ep[1])
        + second_ep[0]
        + struct.pack(">H", second_ep[1])
        + bytes([proto])
        + (struct.pack(">H", vlan_id) if vlan_id is not None else b"\x00\x00")
    )
    return zlib.crc32(key_bytes) & 0xFFFFFFFF


@celery_app.task(
    bind=True,
    name="pecff.tasks.pipeline.run_forensic_pipeline",
    max_retries=3,
    autoretry_for=(TransientError,),
    retry_backoff=True,
)
def run_forensic_pipeline(
    self: Any,
    analysis_id: str,
    object_name: str,
    filename: str,
    file_sha256: str,
    total_bytes: int,
    num_shards: int = 1,
) -> str:
    """Dispatches the flow-safe sharded Celery canvas pipeline."""
    task_id = self.request.id or f"task-{analysis_id}"
    update_task_state(
        task_id=task_id,
        state="PARSING",
        progress=0.05,
        stage_detail=f"Dispatching {num_shards} parallel flow-safe shards",
        analysis_id=analysis_id,
    )

    # 1. Create Shard Tasks
    shard_tasks = [
        parse_and_score_shard_task.s(analysis_id, object_name, shard_idx, num_shards)
        for shard_idx in range(num_shards)
    ]

    # 2. Assemble Canvas: chord(group(shards), finalize) | ml_task | index_task
    workflow = (
        chord(
            group(shard_tasks),
            finalize_corpus_task.s(analysis_id, object_name, filename, file_sha256),
        )
        | ml_scoring_task.s()
        | index_and_persist_task.s()
    )

    workflow.apply_async()
    return str(task_id)


@celery_app.task(
    bind=True,
    name="pecff.tasks.pipeline.parse_and_score_shard_task",
    max_retries=3,
    autoretry_for=(TransientError,),
)
def parse_and_score_shard_task(
    self: Any,
    analysis_id: str,
    object_name: str,
    shard_index: int,
    num_shards: int,
) -> dict[str, Any]:
    """Parse, reassemble, and score TCP flows assigned to this shard index."""
    task_id = f"task-{analysis_id}"
    logger.info("Starting shard %d/%d for analysis %s", shard_index, num_shards, analysis_id)

    storage = StorageService()
    pcap_path = storage.local_dir / settings.minio_bucket_pcaps / object_name

    # If file is not in local fallback, read from MinIO or disk
    if not pcap_path.exists():
        alt_path = Path("data/storage") / settings.minio_bucket_pcaps / object_name
        if alt_path.exists():
            pcap_path = alt_path

    sessions_collected: list[dict[str, Any]] = []
    findings_collected: list[dict[str, Any]] = []
    total_packets = 0

    if pcap_path.exists():
        try:
            reader = PcapReader(pcap_path)
            reassembler = StreamReassembler()
            classifier = ProtocolClassifier()
            risk_scorer = NISTDeterministicRiskScorer()

            for pkt in reader:
                total_packets += 1
                if total_packets % 50000 == 0:
                    # Update progress every 50,000 packets
                    update_task_state(
                        task_id=task_id,
                        state="PARSING",
                        progress=min(0.70, 0.10 + (total_packets / 500000.0)),
                        stage_detail=f"Parsed {total_packets:,} packets in shard {shard_index}",
                        packets_processed=total_packets,
                        analysis_id=analysis_id,
                    )

                # Flow-safe sharding check using canonical 5-tuple + VLAN key
                if num_shards > 1:
                    flow_hash = compute_canonical_flow_hash(pkt.payload, pkt.vlan_id)
                    if flow_hash is not None and (flow_hash % num_shards) != shard_index:
                        continue

                reassembler.process_packet(pkt)

            # Finalize sessions in this shard
            completed_streams = reassembler.flush_all()
            for stream in completed_streams:
                c2s_bytes = stream.c2s_payload
                s2c_bytes = stream.s2c_payload

                classification = classifier.classify_stream(
                    server_port=stream.server_port,
                    s2c_initial_bytes=s2c_bytes[:64],
                    c2s_initial_bytes=c2s_bytes[:64],
                )

                # Process STARTTLS transitions
                fsm = StarttlsFSM(protocol=classification.protocol, mode=classification.mode)
                if (
                    classification.protocol in ("SMTP", "IMAP", "POP3")
                    and classification.mode == "EXPLICIT"
                ):
                    if s2c_bytes:
                        fsm.feed(Direction.S2C, s2c_bytes, 0, stream.first_seen)
                    if c2s_bytes:
                        fsm.feed(Direction.C2S, c2s_bytes, 0, stream.first_seen)

                # Decode TLS
                tls_decoder = TLSHandshakeDecoder()
                if c2s_bytes:
                    tls_decoder.process_c2s_record_bytes(c2s_bytes)
                if s2c_bytes:
                    tls_decoder.process_s2c_record_bytes(s2c_bytes)
                tls_summary = tls_decoder.summary

                # Protocol version resolution
                ver_str = resolve_protocol_version(tls_summary, fsm)

                # Cipher resolution
                cipher_id = None
                cipher_info = None
                if tls_summary.server_hello and tls_summary.server_hello.selected_cipher:
                    cipher_id = f"0x{tls_summary.server_hello.selected_cipher:04X}"
                    cipher_info = cipher_db.get(cipher_id)

                # Key exchange and named group resolution
                kex_alg = "ECDHE"
                if cipher_info and cipher_info.kex and cipher_info.kex != "UNKNOWN":
                    kex_alg = cipher_info.kex
                elif ver_str == "TLS 1.3":
                    kex_alg = "ECDHE"

                named_grp = None
                if tls_summary.server_hello and 51 in tls_summary.server_hello.extensions:
                    ext_51 = tls_summary.server_hello.extensions[51]
                    if ext_51.parsed_value and isinstance(ext_51.parsed_value, int):
                        named_grp = NAMED_GROUP_MAP.get(ext_51.parsed_value, f"group_0x{ext_51.parsed_value:04x}")
                    elif len(ext_51.data) >= 2:
                        gid = struct.unpack(">H", ext_51.data[0:2])[0]
                        named_grp = NAMED_GROUP_MAP.get(gid, f"group_0x{gid:04x}")

                if not named_grp and tls_summary.client_hello and tls_summary.client_hello.supported_groups:
                    for gid in tls_summary.client_hello.supported_groups:
                        if not is_grease(gid):
                            named_grp = NAMED_GROUP_MAP.get(gid, f"group_0x{gid:04x}")
                            break

                # Session hygiene extension flags
                sh_exts = tls_summary.server_hello.extensions if tls_summary.server_hello else {}
                ch_exts = tls_summary.client_hello.extensions if tls_summary.client_hello else {}
                encrypt_then_mac = (22 in sh_exts) or (22 in ch_exts)
                extended_master_sec = (23 in sh_exts) or (23 in ch_exts)
                secure_reneg = (65281 in sh_exts) or (65281 in ch_exts)
                if tls_summary.client_hello and 0x00FF in tls_summary.client_hello.cipher_suites:
                    secure_reneg = True

                # Parse leaf certificate if present
                leaf_cert = None
                if tls_summary.certificates_der:
                    try:
                        leaf_cert = X509Parser.parse_der(tls_summary.certificates_der[0])
                    except Exception as cert_err:
                        logger.debug("Failed parsing leaf certificate: %s", cert_err)

                # STARTTLS credential observation & auth
                cleartext_creds = getattr(fsm, "credentials_in_cleartext", False)
                has_auth = bool(getattr(fsm, "auth_mechanisms_used", [])) or cleartext_creds

                crypto_params = SessionCryptoParameters(
                    protocol_version=ver_str,
                    dst_port=stream.server_port,
                    has_auth=has_auth,
                    cleartext_credentials_observed=cleartext_creds,
                    handshake_completed=tls_summary.handshake_completed,
                    cert_analysis_possible=tls_summary.cert_analysis_possible,
                    cipher_id=cipher_id,
                    cipher_info=cipher_info,
                    encrypt_then_mac=encrypt_then_mac,
                    extended_master_secret=extended_master_sec,
                    secure_renegotiation=secure_reneg,
                    kex_algorithm=kex_alg,
                    named_group=named_grp,
                    leaf_certificate=leaf_cert,
                )
                risk_res = risk_scorer.score_session(crypto_params)

                # Fingerprints
                ja3_h, ja4_h = "", ""
                if tls_summary.client_hello:
                    _, ja3_h = calculate_ja3(tls_summary.client_hello)
                    ja4_h = calculate_ja4(tls_summary.client_hello)

                sessions_collected.append(
                    {
                        "id": f"sess-{analysis_id}-{shard_index}-{len(sessions_collected)}",
                        "analysis_id": analysis_id,
                        "client_ip": stream.client_ip,
                        "client_port": stream.client_port,
                        "server_ip": stream.server_ip,
                        "server_port": stream.server_port,
                        "protocol": classification.protocol,
                        "mode": classification.mode,
                        "starttls_state": fsm.state.value
                        if hasattr(fsm.state, "value")
                        else str(fsm.state),
                        "risk_score": float(risk_res.score),
                        "risk_band": risk_res.band,
                        "ja3": ja3_h or None,
                        "ja4": ja4_h or None,
                        "sni": tls_summary.client_hello.server_name
                        if tls_summary.client_hello
                        else None,
                        "first_seen": stream.first_seen,
                        "duration_sec": stream.last_seen - stream.first_seen,
                        "is_anomaly": False,
                        "c2s_bytes": stream.c2s_bytes,
                        "s2c_bytes": stream.s2c_bytes,
                        "tls_handshake": serialize_handshake_summary(tls_summary),
                        "server_banner": fsm.server_banner,
                        "ehlo_domain": fsm.ehlo_domain,
                        "cleartext_credentials_observed": cleartext_creds,
                        "has_auth": has_auth,
                        "risk_breakdown": {
                            "score": float(risk_res.score),
                            "band": risk_res.band,
                            "context_multiplier": float(risk_res.context_multiplier),
                            "component_scores": {
                                k: float(v) for k, v in risk_res.component_scores.items()
                            },
                            "component_weights": {
                                k: float(v) for k, v in risk_res.component_weights.items()
                            },
                            "vetoes": [
                                {
                                    "rule_id": v.rule_id,
                                    "floor_score": v.floor_score,
                                    "evidence": v.evidence,
                                    "nist_reference": v.nist_reference,
                                }
                                for v in risk_res.vetoes
                            ],
                            "effective_security_bits": risk_res.effective_security_bits,
                            "weight_redistributed": risk_res.weight_redistributed,
                            "provenance": [
                                {
                                    "component": p.component,
                                    "rule_id": p.rule_id,
                                    "penalty": p.penalty,
                                    "evidence": p.evidence,
                                    "nist_reference": p.nist_reference,
                                }
                                for p in risk_res.provenance
                            ],
                        },
                    }
                )
        except Exception as err:
            logger.warning("Error in shard %d: %s", shard_index, err)

    return {
        "shard_index": shard_index,
        "packets_processed": total_packets,
        "sessions": sessions_collected,
        "findings": findings_collected,
    }


@celery_app.task(name="pecff.tasks.pipeline.finalize_corpus_task")
def finalize_corpus_task(
    shard_results: list[dict[str, Any]],
    analysis_id: str,
    object_name: str,
    filename: str,
    file_sha256: str,
) -> dict[str, Any]:
    """Merge shard outputs and execute corpus-wide detectors (D1, D8, beaconing)."""
    task_id = f"task-{analysis_id}"
    update_task_state(
        task_id=task_id,
        state="SCORING",
        progress=0.75,
        stage_detail="Executing corpus-level correlation and beaconing detection",
        analysis_id=analysis_id,
    )

    all_sessions: list[dict[str, Any]] = []
    all_findings: list[dict[str, Any]] = []
    total_pkts = 0

    for res in shard_results:
        total_pkts += res.get("packets_processed", 0)
        all_sessions.extend(res.get("sessions", []))
        all_findings.extend(res.get("findings", []))

    # -----------------------------------------------------------------------
    # Corpus-level correlation pass (CB1-CB4)
    # -----------------------------------------------------------------------
    corpus_beacon_count = 0
    try:
        corpus_result = run_corpus_correlation(all_sessions, all_findings)

        # Extend findings with corpus-level detections
        all_findings.extend(corpus_result.new_findings)

        # Stamp each session with corpus-computed auxiliary fields so that
        # Stamp each session with corpus-computed auxiliary fields and temporal behavior
        for s in all_sessions:
            sid = s["id"]
            s["is_periodic"] = corpus_result.session_is_periodic.get(sid, False)
            s["src_session_count"] = corpus_result.session_src_count.get(sid, 1)
            s["distinct_sni_count"] = corpus_result.session_distinct_sni.get(sid, 1)

            # Explainable temporal behavior (§2, §16, §17)
            temp_data = corpus_result.session_temporal.get(sid)
            if temp_data:
                s["temporal_classification"] = temp_data.get("temporal_classification")
                s["temporal_behavior"] = {
                    "classification": temp_data.get("temporal_classification", "INSUFFICIENT_DATA"),
                    "behavior_score": temp_data.get("temporal_behavior_score", 0),
                    "mean_interval": temp_data.get("temporal_mean_interval"),
                    "std_interval": None,
                    "cv": temp_data.get("temporal_cv"),
                    "jitter_pct": temp_data.get("temporal_jitter_pct"),
                    "duration": temp_data.get("temporal_duration", 0.0),
                    "event_count": temp_data.get("temporal_event_count", 0),
                    "explanation": [],
                    "analyst_note": temp_data.get("temporal_analyst_note", ""),
                }
            else:
                s["temporal_classification"] = "INSUFFICIENT_DATA"
                s["temporal_behavior"] = None

        corpus_beacon_count = len(corpus_result.beacon_groups)
        temporal_summary = corpus_result.temporal_summary

        logger.info(
            "Corpus correlation complete for %s: %d beacon groups, %d temporal groups, %d new findings",
            analysis_id,
            corpus_beacon_count,
            len(corpus_result.temporal_groups),
            len(corpus_result.new_findings),
        )
    except Exception as err:
        logger.warning("Corpus correlation error for %s: %s", analysis_id, err)
        temporal_summary = {}

    # -----------------------------------------------------------------------
    # Overall risk aggregation
    # -----------------------------------------------------------------------
    scores = [s.get("risk_score", 0.0) for s in all_sessions]
    overall_score = float(max(scores, default=0.0))

    if overall_score <= 19:
        overall_band = "SECURE"
    elif overall_score <= 39:
        overall_band = "ACCEPTABLE"
    elif overall_score <= 59:
        overall_band = "WEAK"
    elif overall_score <= 79:
        overall_band = "HIGH"
    else:
        overall_band = "CRITICAL"

    return {
        "analysis_id": analysis_id,
        "pcap_filename": filename,
        "pcap_sha256": file_sha256,
        "total_packets": total_pkts,
        "total_sessions": len(all_sessions),
        "overall_risk_score": overall_score,
        "overall_risk_band": overall_band,
        "summary_data": {
            "session_count": len(all_sessions),
            "findings_count": len(all_findings),
            "beacon_groups": corpus_beacon_count,
            "temporal_summary": temporal_summary,
            "temporal_groups": getattr(corpus_result, "temporal_groups", []),
        },
        "sessions": all_sessions,
        "findings": all_findings,
    }


@celery_app.task(name="pecff.tasks.pipeline.ml_scoring_task")
def ml_scoring_task(corpus_data: dict[str, Any]) -> dict[str, Any]:
    """Perform 94-dimensional feature vectorization and unsupervised anomaly scoring."""
    analysis_id = corpus_data["analysis_id"]
    task_id = f"task-{analysis_id}"
    update_task_state(
        task_id=task_id,
        state="SCORING_ML",
        progress=0.88,
        stage_detail="Evaluating pre-trained ML anomaly model on 94-dim feature vectors",
        analysis_id=analysis_id,
    )

    sessions = corpus_data.get("sessions", [])
    if not sessions:
        return corpus_data

    model = get_preloaded_ml_model()
    vectorizer = get_preloaded_vectorizer()

    # Explicit degradation check (never silently return anomaly_score=0 or pretend success)
    if model is None or vectorizer is None:
        logger.warning(
            "ML anomaly scoring DEGRADED for analysis %s: model=%s, vectorizer=%s",
            analysis_id,
            "loaded" if model is not None else "missing/unfitted",
            "loaded" if vectorizer is not None else "missing/unfitted",
        )
        update_task_state(
            task_id=task_id,
            state="SCORING_ML",
            progress=0.88,
            stage_detail="ML anomaly scoring DEGRADED: pre-trained model or vectorizer artifact unavailable",
            analysis_id=analysis_id,
        )
        for s in sessions:
            s["is_anomaly"] = False
            s["ml_result"] = None
        return corpus_data

    try:
        extractor = SessionFeatureExtractor()
        raw_features = []
        for s in sessions:
            hs = deserialize_handshake_summary(s.get("tls_handshake"))
            leaf_cert = None
            if hs and hs.certificates_der:
                try:
                    leaf_cert = X509Parser.parse_der(hs.certificates_der[0])
                except Exception:
                    leaf_cert = None

            feat = extractor.extract_features(
                handshake_summary=hs,
                leaf_cert=leaf_cert,
                risk_score=float(s.get("risk_score", 0.0)),
                starttls_state=s.get("starttls_state", "S0_TCP_EST"),
                dst_port=s.get("server_port", 25),
                c2s_bytes=s.get("c2s_bytes", 0),
                s2c_bytes=s.get("s2c_bytes", 0),
                duration_sec=s.get("duration_sec", 0.0),
                is_periodic=bool(s.get("is_periodic", False)),
                src_ip_session_count=int(s.get("src_session_count", 1)),
                distinct_sni_count=int(s.get("distinct_sni_count", 1)),
            )
            raw_features.append(feat)

        matrix = vectorizer.transform(raw_features)
        assert matrix.shape == (len(sessions), 94), f"Feature matrix shape mismatch: {matrix.shape}"

        # Persist features partitioned Parquet
        FeatureStore.save_features(
            analysis_id=analysis_id,
            features_matrix=matrix,
            feature_names=vectorizer.ordered_feature_names,
        )

        anomaly_scores = -model.score_samples(matrix)
        preds = model.predict(matrix)

        for i, s in enumerate(sessions):
            is_anom = bool(preds[i] == -1)
            s["is_anomaly"] = is_anom
            s["ml_result"] = {
                "is_anomaly": is_anom,
                "anomaly_score": float(anomaly_scores[i]),
                "anomaly_percentile": float(
                    min(100.0, max(0.0, (anomaly_scores[i] + 0.5) * 100.0))
                ),
                "top_feature_explanations": [],
                "is_experimental": True,
            }
        logger.info(
            "ML anomaly scoring completed for %s: %d sessions, %d anomalies detected",
            analysis_id,
            len(sessions),
            sum(1 for s in sessions if s.get("is_anomaly")),
        )
    except Exception as err:
        logger.error("ML anomaly scoring execution failure for %s: %s", analysis_id, err, exc_info=True)
        for s in sessions:
            s["is_anomaly"] = False
            s["ml_result"] = None

    return corpus_data


@celery_app.task(name="pecff.tasks.pipeline.index_and_persist_task")
def index_and_persist_task(corpus_data: dict[str, Any]) -> str:
    """Idempotent database and search index persistence on (analysis_id, session_id)."""
    analysis_id = corpus_data["analysis_id"]
    task_id = f"task-{analysis_id}"

    # Build Pydantic response models
    analysis_resp = AnalysisDetailResponse(
        schema_version="1.0.0",
        analysis_id=analysis_id,
        created_at=datetime.now(UTC),
        pcap_filename=corpus_data["pcap_filename"],
        pcap_sha256=corpus_data["pcap_sha256"],
        status="COMPLETED",
        total_packets=corpus_data["total_packets"],
        total_sessions=corpus_data["total_sessions"],
        overall_risk_score=corpus_data["overall_risk_score"],
        overall_risk_band=corpus_data["overall_risk_band"],
        summary_data=corpus_data.get("summary_data", {}),
        sessions=[
            SessionDetailSchema(
                id=s["id"],
                analysis_id=analysis_id,
                client_ip=s["client_ip"],
                client_port=s["client_port"],
                server_ip=s["server_ip"],
                server_port=s["server_port"],
                protocol=s["protocol"],
                mode=s["mode"],
                starttls_state=s["starttls_state"],
                risk_score=s["risk_score"],
                risk_band=s["risk_band"],
                ja3=s.get("ja3"),
                ja4=s.get("ja4"),
                sni=s.get("sni"),
                first_seen=s.get("first_seen", 0.0),
                duration_sec=s.get("duration_sec", 0.0),
                is_anomaly=s.get("is_anomaly", False),
                temporal_classification=s.get("temporal_classification"),
                temporal_behavior=TemporalBehaviorSchema(**s["temporal_behavior"])
                if s.get("temporal_behavior")
                else None,
                c2s_bytes=s.get("c2s_bytes", 0),
                s2c_bytes=s.get("s2c_bytes", 0),
                risk_breakdown=RiskResultSchema(**s["risk_breakdown"])
                if s.get("risk_breakdown")
                else None,
                ml_result=MLAnomalyResultSchema(**s["ml_result"]) if s.get("ml_result") else None,
            )
            for s in corpus_data.get("sessions", [])
        ],
        findings=[
            FindingSchema(
                id=f["id"],
                session_id=f.get("session_id", ""),
                rule_id=f["rule_id"],
                title=f["title"],
                description=f["description"],
                severity=f.get("severity", "MEDIUM"),
                standards_ref=f.get("standards_ref", ""),
                evidence=f.get("evidence", {}),
            )
            for f in corpus_data.get("findings", [])
        ],
    )

    # Register in active analysis store
    register_analysis(analysis_resp)

    # Mark task SUCCESS
    update_task_state(
        task_id=task_id,
        state="SUCCESS",
        progress=1.0,
        stage_detail="Forensic analysis pipeline completed successfully",
        packets_processed=corpus_data["total_packets"],
        analysis_id=analysis_id,
    )

    logger.info("Pipeline completed successfully for analysis %s", analysis_id)
    return str(analysis_id)
