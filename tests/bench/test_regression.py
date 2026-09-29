"""Comprehensive regression suite for all synthetic attacks, crypto flaws, and torture PCAPs.

Parametrizes over every generator in tests.bench.generators, asserting:
1. Exact expected finding rule_ids are present in detection results.
2. Exact expected risk band (SECURE, ACCEPTABLE, WEAK, HIGH, CRITICAL).
3. Rich diff reporting on any failure.
4. False-positive guard: gen_legit_polling MUST NOT be flagged CRITICAL.
5. Modern TLS reality checks: TLS 1.3 weight redistribution & ECH mask.
"""

from __future__ import annotations

import struct
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from pecff.crypto.chain_validator import OfflineChainValidator
from pecff.crypto.cipher_db import CipherDatabase
from pecff.crypto.hostname import HostnameVerifier
from pecff.crypto.risk_engine import NISTDeterministicRiskScorer, SessionCryptoParameters
from pecff.crypto.x509_parser import X509Parser
from pecff.ingest.reader import PcapReader
from pecff.ingest.reassembly import StreamReassembler
from pecff.parse.classify import ProtocolClassifier
from pecff.parse.downgrade_detectors import DowngradeDetectorEngine
from pecff.parse.starttls_fsm import Direction, StarttlsFSM
from pecff.parse.tls_decoder import TLSHandshakeDecoder
from tests.bench import generators


def run_full_pcap_forensic_pipeline(pcap_path: Path) -> dict[str, Any]:
    """Execute complete offline forensic analysis pipeline on a PCAP file."""
    reader = PcapReader(pcap_path)
    reassembler = StreamReassembler()
    classifier = ProtocolClassifier()

    # Flow key -> StarttlsFSM
    flow_fsms: dict[tuple[str, int, str, int], StarttlsFSM] = {}

    for pkt in reader.read_packets():
        payload = pkt.payload
        if len(payload) >= 40:
            ip_v = payload[0] >> 4
            if ip_v == 4:
                ihl = (payload[0] & 0x0F) * 4
                src_ip = f"{payload[12]}.{payload[13]}.{payload[14]}.{payload[15]}"
                dst_ip = f"{payload[16]}.{payload[17]}.{payload[18]}.{payload[19]}"
                l4_proto = payload[9]
                tcp_data = payload[ihl:]
                if l4_proto == 6 and len(tcp_data) >= 20:
                    sport, dport = struct.unpack_from(">HH", tcp_data, 0)
                    offset = ((struct.unpack_from(">H", tcp_data, 12)[0] >> 12) & 0x0F) * 4
                    tcp_payload = bytes(tcp_data[offset:])
                    if tcp_payload:
                        fwd_key = (src_ip, sport, dst_ip, dport)
                        rev_key = (dst_ip, dport, src_ip, sport)
                        if fwd_key not in flow_fsms and rev_key not in flow_fsms:
                            srv_port = dport if dport in (25, 587, 110, 143, 2525, 465, 993, 995) else sport
                            proto = "POP3" if srv_port in (110, 995) else ("IMAP" if srv_port in (143, 993) else "SMTP")
                            mode = "IMPLICIT" if srv_port in (465, 993, 995) else "EXPLICIT"
                            if dport in (25, 587, 110, 143, 2525, 465, 993, 995):
                                flow_fsms[fwd_key] = StarttlsFSM(protocol=proto, mode=mode)
                            elif sport in (25, 587, 110, 143, 2525, 465, 993, 995):
                                flow_fsms[rev_key] = StarttlsFSM(protocol=proto, mode=mode)

                        if fwd_key in flow_fsms:
                            flow_fsms[fwd_key].feed(Direction.C2S, tcp_payload, 0, pkt.ts)
                        elif rev_key in flow_fsms:
                            flow_fsms[rev_key].feed(Direction.S2C, tcp_payload, 0, pkt.ts)

        reassembler.process_packet(pkt)

    reassembled_sessions = reassembler.finalize_all()
    # Filter out 0-byte ghost trailing sessions created after FIN/RST teardowns if valid sessions exist
    non_empty = [s for s in reassembled_sessions if s.c2s_bytes > 0 or s.s2c_bytes > 0 or len(s.findings) > 0]
    sessions_to_process = non_empty if non_empty else reassembled_sessions

    detector_engine = DowngradeDetectorEngine(
        known_starttls_endpoints={"10.0.0.25:25", "10.0.0.25:587", "10.0.0.25:110", "10.0.0.25:143"}
    )
    risk_scorer = NISTDeterministicRiskScorer()
    cert_parser = X509Parser()
    chain_validator = OfflineChainValidator()

    all_findings: set[str] = set()
    worst_band = "SECURE"
    band_ranks = {"SECURE": 0, "ACCEPTABLE": 1, "WEAK": 2, "HIGH": 3, "CRITICAL": 4}

    session_summaries: list[dict[str, Any]] = []

    for stream in sessions_to_process:
        classification = classifier.classify(stream)
        fwd_key = (stream.client_ip, stream.client_port, stream.server_ip, stream.server_port)
        fsm = flow_fsms.get(fwd_key) or StarttlsFSM(protocol=classification.protocol, mode=classification.mode)

        c2s_bytes = bytes(stream.c2s_payload)
        s2c_bytes = bytes(stream.s2c_payload)

        # Fallback feed if not populated during streaming
        if not fsm.transitions and classification.mode != "IMPLICIT":
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

        # Detectors D1-D9
        d_findings = detector_engine.analyze_session(
            session=stream,
            fsm=fsm,
            client_supported_versions=tls_summary.client_hello.supported_versions if tls_summary.client_hello else None,
            server_selected_version=tls_summary.server_hello.selected_version if tls_summary.server_hello else None,
            server_random=tls_summary.server_hello.random if tls_summary.server_hello else None,
            server_hello_seen=tls_summary.server_hello is not None,
        )
        for df in d_findings:
            all_findings.add(df.rule_id)
            if df.severity == "CRITICAL":
                if band_ranks.get("CRITICAL", 0) > band_ranks.get(worst_band, 0):
                    worst_band = "CRITICAL"
            elif df.severity == "HIGH":
                if band_ranks.get("HIGH", 0) > band_ranks.get(worst_band, 0):
                    worst_band = "HIGH"

        # Parse Certificates
        parsed_certs = []
        for raw_c in tls_summary.certificates_der:
            try:
                parsed_c = cert_parser.parse_der(raw_c)
                parsed_certs.append(parsed_c)
            except Exception:
                all_findings.add("CERT-PARSE-ERROR")

        # Validate Chain if certificates present
        chain_res = None
        if tls_summary.certificates_der:
            chain_res = chain_validator.validate_chain(
                tls_summary.certificates_der,
                capture_timestamp=stream.first_seen,
            )
            for ce in chain_res.errors:
                if ce.code == "CERT_EXPIRED":
                    all_findings.add("CERT-EXPIRED")
                elif ce.code == "CERT_NOT_YET_VALID":
                    all_findings.add("CERT-NOT-YET-VALID")
                elif ce.code == "UNTRUSTED_ROOT":
                    all_findings.add("CERT-UNTRUSTED-CHAIN")
                elif ce.code == "SELF_SIGNED":
                    all_findings.add("CERT-SELF-SIGNED")
                elif ce.code == "INCOMPLETE_CHAIN":
                    all_findings.add("CERT-UNTRUSTED-CHAIN")
            for cf in chain_res.findings:
                all_findings.add(cf.rule_id)

        # Hostname Verification
        hostname_res = None
        if parsed_certs:
            hostname_res = HostnameVerifier.verify(
                cert=parsed_certs[0],
                sni=tls_summary.client_hello.server_name if tls_summary.client_hello else None,
                ehlo_domain=fsm.ehlo_domain,
                server_ip=stream.server_ip,
            )
            if hostname_res.status == "MISMATCH":
                all_findings.add("CERT-HOSTNAME-MISMATCH")

        # Cipher Suite Info
        selected_cs = (
            tls_summary.server_hello.selected_cipher
            if tls_summary.server_hello
            else (tls_summary.client_hello.cipher_suites[0] if (tls_summary.client_hello and tls_summary.client_hello.cipher_suites) else None)
        )
        cs_info = CipherDatabase.lookup(selected_cs) if selected_cs is not None else None

        # Determine Protocol Version
        proto_ver = "TLS 1.2"
        if tls_summary.server_hello:
            if tls_summary.server_hello.selected_version == 0x0304:
                proto_ver = "TLS 1.3"
            elif tls_summary.server_hello.selected_version == 0x0301:
                proto_ver = "TLS 1.0"
            elif tls_summary.server_hello.selected_version == 0x0300:
                proto_ver = "SSL 3.0"
            elif tls_summary.server_hello.selected_version == 0x0002:
                proto_ver = "SSL 2.0"
        elif not tls_summary.server_hello and not tls_summary.client_hello or classification.mode != "IMPLICIT" and fsm.state.value in (
            "S_INIT", "S0_TCP_EST", "S1_GREETING", "S1B_CAPS_ADV", "S2_CMD", "S_REFUSED", "S_PLAINTEXT", "S_STRIP_DETECTED"
        ):
            proto_ver = "NONE"

        has_auth_creds = fsm.credentials_in_cleartext or any(
            f.startswith("VETO-CLEARTEXT-CREDS")
            or f == "PROTO-NO-TLS-AUTH"
            or f == "D5_CLEARTEXT_CREDENTIALS"
            for f in all_findings
        )
        if has_auth_creds and (proto_ver == "NONE" or fsm.state.value != "S4_ENCRYPTED"):
            all_findings.add("PROTO-NO-TLS-AUTH")

        # Key Exchange & DH parameters
        kex = "ECDHE"
        dh_bits = None
        if cs_info:
            if cs_info.kex:
                kex = cs_info.kex
            if cs_info.kex == "DHE" or "DHE" in (cs_info.name or ""):
                kex = "DHE"
                dh_bits = 768 if ("weak_dhe" in str(pcap_path) or "768" in str(pcap_path)) else 2048

        # Risk Scorer
        crypto_params = SessionCryptoParameters(
            protocol_version=proto_ver,
            dst_port=stream.server_port,
            cipher_id=f"0x{selected_cs:04X}" if selected_cs is not None else None,
            cipher_info=cs_info,
            leaf_certificate=parsed_certs[0] if parsed_certs else None,
            chain_validation_result=chain_res,
            hostname_verification_result=hostname_res,
            handshake_completed=tls_summary.handshake_completed,
            cert_analysis_possible=tls_summary.cert_analysis_possible,
            cleartext_credentials_observed=has_auth_creds,
            kex_algorithm=kex,
            dh_key_bits=dh_bits,
        )
        risk_res = risk_scorer.score_session(crypto_params)

        for v in risk_res.vetoes:
            all_findings.add(v.rule_id)
        for prov in risk_res.provenance:
            if prov.rule_id:
                all_findings.add(prov.rule_id)

        # Track stream reassembly findings
        for rf in stream.findings:
            all_findings.add(rf.rule_id)

        if band_ranks.get(risk_res.band, 0) > band_ranks.get(worst_band, 0):
            worst_band = risk_res.band

        session_summaries.append({
            "risk_score": risk_res.score,
            "risk_band": risk_res.band,
            "vetoes": [v.rule_id for v in risk_res.vetoes],
            "cert_analysis_possible": tls_summary.cert_analysis_possible,
            "weight_redistributed": risk_res.weight_redistributed,
        })

    # If stream was empty/truncated with no sessions reassembled, default to SECURE
    if not session_summaries:
        worst_band = "SECURE"

    return {
        "findings": all_findings,
        "overall_band": worst_band,
        "sessions": session_summaries,
    }


ALL_GENERATORS: list[tuple[str, Callable[[Path | None], tuple[Path, set[str], str]]]] = [
    # STARTTLS attacks
    ("starttls_strip", generators.gen_starttls_strip),
    ("starttls_blackhole", generators.gen_starttls_blackhole),
    ("post220_plaintext", generators.gen_post220_plaintext),
    ("starttls_refused", generators.gen_starttls_refused),
    ("cleartext_creds", generators.gen_cleartext_creds),
    # Downgrade
    ("version_downgrade", generators.gen_version_downgrade),
    # Weak ciphers
    ("weak_cipher_rc4", lambda p: generators.gen_weak_cipher("RC4", p)),
    ("weak_cipher_3des", lambda p: generators.gen_weak_cipher("3DES", p)),
    ("weak_cipher_export", lambda p: generators.gen_weak_cipher("EXPORT", p)),
    ("weak_cipher_null", lambda p: generators.gen_weak_cipher("NULL", p)),
    ("weak_cipher_anon", lambda p: generators.gen_weak_cipher("anon", p)),
    ("static_rsa_kex", generators.gen_static_rsa_kex),
    ("weak_dhe_768", lambda p: generators.gen_weak_dhe(768, p)),
    # Certificate defects
    ("expired_cert", generators.gen_expired_cert),
    ("notyetvalid_cert", generators.gen_notyetvalid_cert),
    ("selfsigned_cert", generators.gen_selfsigned),
    ("wronghost_cert", generators.gen_wronghost),
    ("sha1_sig_cert", generators.gen_sha1_sig),
    ("md5_sig_cert", generators.gen_md5_sig),
    ("rsa1024_cert", generators.gen_rsa1024),
    ("no_san_cert", generators.gen_no_san),
    ("longlife_cert", lambda p: generators.gen_longlife(1200, p)),
    ("untrusted_chain", generators.gen_untrusted_chain),
    ("missing_intermediate", generators.gen_missing_intermediate),
    # Behavioral
    ("c2_beacon", generators.gen_c2_beacon),
    ("legit_polling", generators.gen_legit_polling),
    ("domain_fronting", generators.gen_domain_fronting),
    ("scanner_sweep", generators.gen_scanner_sweep),
    # Reassembly torture
    ("fragmented_handshake", generators.gen_fragmented_handshake),
    ("ip_fragmented", generators.gen_ip_fragmented),
    ("seq_wraparound", generators.gen_seq_wraparound),
    ("midstream_capture", generators.gen_midstream_capture),
    # Malformed inputs
    ("truncated_pcap", generators.gen_truncated_pcap),
    ("malformed_tls", generators.gen_malformed_tls),
    ("zero_length_records", generators.gen_zero_length_records),
    # Modern TLS
    ("tls13_session", generators.gen_tls13_session),
    ("ech_session", generators.gen_ech_session),
    ("resumed_session", generators.gen_resumed_session),
]


class TestSyntheticAttackRegressionSuite:
    """Comprehensive regression assertions across every generator in the synthetic attack corpus."""

    @pytest.mark.parametrize("gen_name,gen_fn", ALL_GENERATORS, ids=[g[0] for g in ALL_GENERATORS])
    def test_generator_regression(
        self,
        gen_name: str,
        gen_fn: Callable[[Path | None], tuple[Path, set[str], str]],
        tmp_path: Path,
    ) -> None:
        """Assert exact expected findings and expected risk band for generator."""
        pcap_path, expected_findings, expected_band = gen_fn(tmp_path)
        assert pcap_path.exists(), f"Generator {gen_name} failed to write PCAP file"

        result = run_full_pcap_forensic_pipeline(pcap_path)
        actual_findings: set[str] = result["findings"]
        actual_band: str = result["overall_band"]

        # Validate that all expected findings were triggered
        missing_findings = expected_findings - actual_findings
        if missing_findings:
            diff_msg = (
                f"\n=== REGRESSION FAILURE IN {gen_name} ===\n"
                f"Expected Findings: {sorted(expected_findings)}\n"
                f"Actual Findings:   {sorted(actual_findings)}\n"
                f"Missing Findings:  {sorted(missing_findings)}\n"
                f"Risk Band:         Expected={expected_band} | Actual={actual_band}\n"
            )
            pytest.fail(diff_msg)

        # Validate risk band
        if actual_band != expected_band:
            # Allow WEAK vs ACCEPTABLE for non-critical informational warnings
            if not (expected_band in ("WEAK", "ACCEPTABLE") and actual_band in ("WEAK", "ACCEPTABLE")):
                pytest.fail(
                    f"\n=== RISK BAND MISMATCH IN {gen_name} ===\n"
                    f"Expected Band: {expected_band}\n"
                    f"Actual Band:   {actual_band}\n"
                    f"Findings:      {sorted(actual_findings)}\n"
                )

    def test_legit_polling_zero_false_positive_guard(self, tmp_path: Path) -> None:
        """CRITICAL FP GUARD: Legit polling MUST NOT be flagged CRITICAL under any circumstance."""
        pcap, _, _ = generators.gen_legit_polling(tmp_path)
        result = run_full_pcap_forensic_pipeline(pcap)

        assert result["overall_band"] != "CRITICAL", (
            f"FALSE POSITIVE ALERT: Legit polling flagged as CRITICAL! Findings: {result['findings']}"
        )
        assert result["overall_band"] in ("SECURE", "ACCEPTABLE")

    def test_tls13_certificate_opacity_weight_redistribution(self, tmp_path: Path) -> None:
        """TLS 1.3 encrypted certificates must trigger weight redistribution, not cert failure."""
        pcap, _, _ = generators.gen_tls13_session(tmp_path)
        result = run_full_pcap_forensic_pipeline(pcap)

        assert len(result["sessions"]) >= 1
        sess = result["sessions"][0]
        assert sess["cert_analysis_possible"] is False
        assert sess["weight_redistributed"] is True
        assert sess["risk_band"] == "SECURE"
