"""PECFF Command Line Interface (CLI) for passive mail cryptographic forensics."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import struct
from pecff.api.schemas import (
    AnalysisDetailResponse,
    FindingSchema,
    MLAnomalyResultSchema,
    RiskResultSchema,
    SessionDetailSchema,
    TemporalBehaviorSchema,
)
from pecff.engine.temporal_detector import TemporalClassification, analyze_temporal_behavior
from pecff.crypto.cipher_db import CipherDatabase, cipher_db
from pecff.crypto.risk_engine import NISTDeterministicRiskScorer, SessionCryptoParameters
from pecff.crypto.x509_parser import X509Parser
from pecff.ingest.reader import PcapReader
from pecff.ingest.reassembly import StreamReassembler
from pecff.ml.features import FeatureStore, SessionFeatureExtractor, SessionFeatureVectorizer
from pecff.ml.fingerprints import calculate_ja3, calculate_ja4
from pecff.parse.classify import ProtocolClassifier
from pecff.parse.starttls_fsm import Direction, StarttlsFSM
from pecff.parse.tls_decoder import (
    TLSHandshakeDecoder,
    TLSHandshakeSummary,
    is_grease,
)
from pecff.report.generator import ForensicReportGenerator
from pecff.tasks.celery_app import get_preloaded_ml_model, get_preloaded_vectorizer
from pecff.tasks.pipeline import (
    NAMED_GROUP_MAP,
    resolve_protocol_version,
    serialize_handshake_summary,
)

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="pecff")
def main() -> None:
    """PECFF: Passive Email Cryptographic Forensics Framework."""
    pass


@main.command(name="analyze")
@click.argument("pcap_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "-f",
    "--format",
    "report_format",
    type=click.Choice(["text", "json", "html", "pdf"], case_sensitive=False),
    default="text",
    help="Output report format.",
)
@click.option(
    "-o",
    "--output",
    "output_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="File path to save the generated report.",
)
def analyze_command(pcap_path: Path, report_format: str, output_path: Path | None) -> None:
    """Analyze a network capture file for mail cryptographic flaws and forensic risks."""
    console.print(
        f"[bold cyan]PECFF Forensics Engine[/bold cyan] analyzing capture: [yellow]{pcap_path.name}[/yellow]"
    )

    reader = PcapReader(pcap_path)
    metadata = reader.get_metadata()
    reassembler = StreamReassembler()
    classifier = ProtocolClassifier()
    risk_scorer = NISTDeterministicRiskScorer()

    with console.status("[bold green]Streaming and reassembling packets...[/bold green]"):
        packet_count = 0
        for pkt in reader:
            packet_count += 1
            reassembler.process_packet(pkt)

    completed_streams = reassembler.flush_all()
    analysis_id = f"cli-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"

    sessions_collected: list[dict[str, Any]] = []
    findings_collected: list[dict[str, Any]] = []
    session_tls_data: list[tuple[TLSHandshakeSummary, Any]] = []

    with console.status("[bold green]Executing forensic analysis and risk scoring...[/bold green]"):
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
            sh_exts: dict[int, Any] = tls_summary.server_hello.extensions if tls_summary.server_hello else {}
            ch_exts: dict[int, Any] = tls_summary.client_hello.extensions if tls_summary.client_hello else {}
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
                except Exception:
                    leaf_cert = None

            # STARTTLS credential observation & auth
            cleartext_creds = getattr(fsm, "credentials_in_cleartext", False)
            has_auth = bool(getattr(fsm, "auth_mechanisms_used", [])) or cleartext_creds

            # Risk score
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

            # Collect finding items
            for v in risk_res.vetoes:
                findings_collected.append(
                    {
                        "id": f"find-{len(findings_collected)}",
                        "session_id": f"sess-{len(sessions_collected)}",
                        "rule_id": v.rule_id,
                        "title": f"Cryptographic Veto: {v.rule_id}",
                        "description": v.evidence,
                        "severity": "CRITICAL",
                        "standards_ref": v.nist_reference,
                        "evidence": {"detail": v.evidence},
                    }
                )

            sessions_collected.append(
                {
                    "id": f"sess-{len(sessions_collected)}",
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
                        "tls_handshake": serialize_handshake_summary(tls_summary) if "serialize_handshake_summary" in globals() else None,
                        "server_banner": fsm.server_banner,
                        "ehlo_domain": fsm.ehlo_domain,
                    },
                }
            )
            session_tls_data.append((tls_summary, leaf_cert))

    # ML Anomaly Scoring
    model = get_preloaded_ml_model()
    vectorizer = get_preloaded_vectorizer()

    if sessions_collected and model is not None and vectorizer is not None:
        try:
            extractor = SessionFeatureExtractor()
            raw_features = [
                extractor.extract_features(
                    handshake_summary=tls_data[0],
                    leaf_cert=tls_data[1],
                    risk_score=float(s["risk_score"]),
                    starttls_state=s.get("starttls_state", "S0_TCP_EST"),
                    dst_port=s["server_port"],
                    c2s_bytes=s["c2s_bytes"],
                    s2c_bytes=s["s2c_bytes"],
                    duration_sec=s["duration_sec"],
                )
                for s, tls_data in zip(sessions_collected, session_tls_data)
            ]
            matrix = vectorizer.transform(raw_features)

            FeatureStore.save_features(
                analysis_id=analysis_id,
                features_matrix=matrix,
                feature_names=vectorizer.ordered_feature_names,
            )

            anomaly_scores = -model.score_samples(matrix)
            preds = model.predict(matrix)
            for i, s in enumerate(sessions_collected):
                is_anom = bool(preds[i] == -1)
                s["is_anomaly"] = is_anom
                s["ml_result"] = {
                    "is_anomaly": is_anom,
                    "anomaly_score": float(anomaly_scores[i]),
                    "anomaly_percentile": float(
                        min(100.0, max(0.0, (anomaly_scores[i] + 0.5) * 100.0))
                    ),
                    "top_feature_explanations": list[dict[str, Any]](),
                    "is_experimental": True,
                }
        except Exception as err:
            console.print(f"[yellow]ML Anomaly scoring warning:[/yellow] {err}")
    elif sessions_collected:
        console.print("[yellow]ML Anomaly scoring DEGRADED: Pre-trained model or vectorizer artifact unavailable.[/yellow]")

    # Temporal behavioral analysis (§2, §16, §18)
    temporal_res = analyze_temporal_behavior(sessions_collected)
    session_temporal_map = temporal_res.get("session_enrichments", {})

    for grp in temporal_res.get("groups", []):
        if grp.get("classification") == TemporalClassification.BEACON_CANDIDATE.value:
            sids = grp.get("session_ids", [])
            primary_sid = sids[0] if sids else ""
            findings_collected.append(
                {
                    "id": f"find-temporal-{len(findings_collected)}",
                    "session_id": primary_sid,
                    "rule_id": "TEMPORAL_BEACON_CANDIDATE",
                    "title": "Automated Timing Beacon Candidate (Behavioral)",
                    "description": (
                        f"Repeated communication pattern between {grp.get('src_ip')} and "
                        f"{grp.get('dst_ip')}:{grp.get('dst_port')} shows high timing regularity "
                        f"(mean interval={grp.get('mean_interval')}s, jitter={grp.get('jitter_pct')}%, "
                        f"CV={grp.get('cv')}, score={grp.get('behavior_score')}/100 across {grp.get('event_count')} events). "
                        "Requires investigation; timing alone does not establish malicious activity."
                    ),
                    "severity": "MEDIUM",
                    "standards_ref": "MITRE ATT&CK T1071",
                    "evidence": grp,
                }
            )

    # Compute overall risk score
    scores = [s["risk_score"] for s in sessions_collected]
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

    analysis_resp = AnalysisDetailResponse(
        schema_version="1.0.0",
        analysis_id=analysis_id,
        created_at=datetime.now(UTC),
        pcap_filename=metadata.filename,
        pcap_sha256=metadata.sha256,
        status="COMPLETED",
        total_packets=packet_count,
        total_sessions=len(sessions_collected),
        overall_risk_score=overall_score,
        overall_risk_band=overall_band,
        summary_data={
            "session_count": len(sessions_collected),
            "findings_count": len(findings_collected),
            "temporal_summary": temporal_res.get("summary", {}),
            "temporal_groups": temporal_res.get("groups", []),
        },
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
                temporal_classification=session_temporal_map.get(s["id"], {}).get("temporal_classification"),
                temporal_behavior=TemporalBehaviorSchema(
                    classification=session_temporal_map.get(s["id"], {}).get("temporal_classification", "INSUFFICIENT_DATA"),
                    behavior_score=session_temporal_map.get(s["id"], {}).get("temporal_behavior_score", 0),
                    mean_interval=session_temporal_map.get(s["id"], {}).get("temporal_mean_interval"),
                    cv=session_temporal_map.get(s["id"], {}).get("temporal_cv"),
                    jitter_pct=session_temporal_map.get(s["id"], {}).get("temporal_jitter_pct"),
                    duration=session_temporal_map.get(s["id"], {}).get("temporal_duration", 0.0),
                    event_count=session_temporal_map.get(s["id"], {}).get("temporal_event_count", 0),
                    analyst_note=session_temporal_map.get(s["id"], {}).get("temporal_analyst_note", ""),
                ) if s["id"] in session_temporal_map else None,
                c2s_bytes=s.get("c2s_bytes", 0),
                s2c_bytes=s.get("s2c_bytes", 0),
                risk_breakdown=RiskResultSchema(**s["risk_breakdown"])
                if s.get("risk_breakdown")
                else None,
                ml_result=MLAnomalyResultSchema(**s["ml_result"]) if s.get("ml_result") else None,
            )
            for s in sessions_collected
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
            for f in findings_collected
        ],
    )

    generator = ForensicReportGenerator()

    # Handle requested format
    if report_format == "json":
        json_out = generator.generate_json(analysis_resp, output_path=output_path)
        if not output_path:
            click.echo(json_out)
        else:
            console.print(f"[bold green]Saved JSON report to:[/bold green] {output_path}")
        return

    if report_format == "html":
        generator.generate_html(analysis_resp, output_path=output_path or "report.html")
        console.print(
            f"[bold green]Saved HTML report to:[/bold green] {output_path or 'report.html'}"
        )
        return

    if report_format == "pdf":
        generator.generate_pdf(analysis_resp, output_path=output_path or "report.pdf")
        console.print(
            f"[bold green]Saved PDF report to:[/bold green] {output_path or 'report.pdf'}"
        )
        return

    # Default Text Console Output
    band_styles = {
        "CRITICAL": "bold red",
        "HIGH": "bold orange3",
        "WEAK": "bold yellow",
        "ACCEPTABLE": "bold green",
        "SECURE": "bold cyan",
    }
    score_style = band_styles.get(overall_band, "bold white")

    console.print(
        Panel.fit(
            f"[bold]Capture:[/bold] {metadata.filename}\n"
            f"[bold]SHA-256:[/bold] {metadata.sha256}\n"
            f"[bold]Total Packets:[/bold] {packet_count:,} | [bold]Sessions:[/bold] {len(sessions_collected)}\n"
            f"[bold]Overall Risk Score:[/bold] [{score_style}]{overall_score:.1f} / 100 ({overall_band})[/{score_style}]",
            title="PECFF Analysis Summary",
            border_style="cyan",
        )
    )

    # Sessions Table
    if sessions_collected:
        t_sess = Table(title="Reconstructed Mail Sessions", header_style="bold magenta")
        t_sess.add_column("Session ID", style="dim")
        t_sess.add_column("Client Endpoint")
        t_sess.add_column("Server Endpoint")
        t_sess.add_column("Protocol")
        t_sess.add_column("Mode")
        t_sess.add_column("STARTTLS State")
        t_sess.add_column("Risk Score")
        t_sess.add_column("Anomaly")

        for s in sessions_collected[:20]:
            s_style = band_styles.get(s["risk_band"], "white")
            t_sess.add_row(
                s["id"],
                f"{s['client_ip']}:{s['client_port']}",
                f"{s['server_ip']}:{s['server_port']}",
                s["protocol"],
                s["mode"],
                s["starttls_state"],
                f"[{s_style}]{s['risk_score']:.1f} ({s['risk_band']})[/{s_style}]",
                "[red]YES[/red]" if s["is_anomaly"] else "[dim]No[/dim]",
            )
        console.print(t_sess)

    if output_path:
        generator.generate_html(analysis_resp, output_path=output_path)
        console.print(f"[bold green]Saved audit report to:[/bold green] {output_path}")


@main.command(name="serve")
@click.option("--host", default="0.0.0.0", help="Host IP to bind FastAPI server.")
@click.option("--port", default=8000, type=int, help="Port to listen on.")
@click.option("--reload", is_flag=True, default=False, help="Enable uvicorn hot reloading.")
def serve_command(host: str, port: int, reload: bool) -> None:
    """Start the PECFF REST and WebSocket API server."""
    import uvicorn

    console.print(f"[bold cyan]Starting PECFF API server on[/bold cyan] http://{host}:{port}")
    uvicorn.run("pecff.api.app:app", host=host, port=port, reload=reload)


@main.command(name="worker")
@click.option("-c", "--concurrency", default=4, type=int, help="Number of worker child processes.")
@click.option("-l", "--loglevel", default="INFO", help="Logging level.")
@click.option(
    "-Q",
    "--queues",
    default="pecff.ingest,pecff.score,pecff.ml,pecff.report,pecff.dlq",
    help="Comma-separated queue list.",
)
def worker_command(concurrency: int, loglevel: str, queues: str) -> None:
    """Start the Celery asynchronous processing worker."""
    from pecff.tasks.celery_app import celery_app

    console.print(
        f"[bold cyan]Starting Celery Worker[/bold cyan] (concurrency={concurrency}, queues={queues})"
    )
    argv = [
        "worker",
        f"--concurrency={concurrency}",
        f"--loglevel={loglevel}",
        "-Q",
        queues,
    ]
    celery_app.worker_main(argv)


@main.command(name="cipher")
@click.argument("identifier", type=str)
def cipher_command(identifier: str) -> None:
    """Look up cipher suite details from IANA / curated knowledge base."""
    db = CipherDatabase()
    info = db.get(identifier)

    t = Table(title=f"Cipher Suite: {info.name}", header_style="bold cyan")
    t.add_column("Property", style="bold")
    t.add_column("Value")

    t.add_row("Hex ID", info.id)
    t.add_row("Standard Name", info.name)
    t.add_row("Key Exchange", info.kex)
    t.add_row("Authentication", info.auth)
    t.add_row("Encryption", f"{info.enc} ({info.enc_bits} bits)")
    t.add_row("MAC / Hash", f"{info.mac} / {info.hash}")
    t.add_row("AEAD", "[green]YES[/green]" if info.aead else "[red]NO[/red]")
    t.add_row("PFS (Forward Secrecy)", "[green]YES[/green]" if info.pfs else "[yellow]NO[/yellow]")
    t.add_row("NIST Status", info.nist_status)

    console.print(t)


@main.command(name="export-schema")
@click.option(
    "-o",
    "--output-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default="schema",
    help="Target directory to export schemas.",
)
def export_schema_command(output_dir: Path) -> None:
    """Export JSON Schema and OpenAPI specifications to disk."""
    from pecff.api.schemas import export_json_schema

    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = export_json_schema(output_dir / "pecff-analysis-1.0.0.json")
    console.print(f"[bold green]Exported JSON Schema:[/bold green] {json_path}")


if __name__ == "__main__":
    main()
