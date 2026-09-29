"""Flat CSV session exporter for high-speed spreadsheet triage and forensic review."""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Any

CSV_FIELDNAMES = [
    "session_id",
    "first_seen_iso",
    "duration_sec",
    "client_ip",
    "client_port",
    "server_ip",
    "server_port",
    "sni",
    "protocol",
    "mode",
    "starttls_state",
    "risk_score",
    "risk_band",
    "is_anomaly",
    "anomaly_score",
    "effective_security_bits",
    "ja3",
    "ja4",
    "c2s_bytes",
    "s2c_bytes",
    "veto_count",
    "finding_count",
]


def export_csv(
    analysis_dict: dict[str, Any],
    output_path: Path | str | None = None,
) -> str:
    """Render flattened CSV spreadsheet data from analysis sessions."""
    sessions = analysis_dict.get("sessions", [])

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=CSV_FIELDNAMES, lineterminator="\n")
    writer.writeheader()

    for s in sessions:
        rb = s.get("risk_breakdown") or {}
        ml = s.get("ml_result") or {}
        vetoes = rb.get("vetoes") or []
        findings = s.get("findings") or []

        row = {
            "session_id": s.get("id", ""),
            "first_seen_iso": s.get("first_seen", 0.0),
            "duration_sec": s.get("duration_sec", 0.0),
            "client_ip": s.get("client_ip", ""),
            "client_port": s.get("client_port", 0),
            "server_ip": s.get("server_ip", ""),
            "server_port": s.get("server_port", 0),
            "sni": s.get("sni", "") or "",
            "protocol": s.get("protocol", ""),
            "mode": s.get("mode", ""),
            "starttls_state": s.get("starttls_state", ""),
            "risk_score": s.get("risk_score", 0),
            "risk_band": s.get("risk_band", "SECURE"),
            "is_anomaly": s.get("is_anomaly", False),
            "anomaly_score": ml.get("anomaly_score", 0.0) if ml else 0.0,
            "effective_security_bits": rb.get("effective_security_bits", 128),
            "ja3": s.get("ja3", "") or "",
            "ja4": s.get("ja4", "") or "",
            "c2s_bytes": s.get("c2s_bytes", 0),
            "s2c_bytes": s.get("s2c_bytes", 0),
            "veto_count": len(vetoes),
            "finding_count": len(findings),
        }
        writer.writerow(row)

    csv_text = output.getvalue()
    if output_path:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(csv_text, encoding="utf-8")

    return csv_text
