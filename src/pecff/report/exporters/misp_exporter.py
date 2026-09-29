"""MISP (Malware Information Sharing Platform) Event JSON exporter.

Generates structured MISP Event JSON payloads with typed attributes:
- ip-src, ip-dst, port, ja3-fingerprint-md5, ja4, x509-fingerprint-sha256, hostname
- Appropriate taxonomy tags (tlp:amber, pecff:risk_band="critical", nist-800-52r2:non-compliant)
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def export_misp_event(
    analysis_dict: dict[str, Any],
    output_path: Path | str | None = None,
) -> str:
    """Render structured MISP Event JSON from forensic analysis document."""
    analysis_id = analysis_dict.get("analysis_id", str(uuid.uuid4()))
    created_at = analysis_dict.get("created_at") or datetime.now(UTC).isoformat()
    overall_band = analysis_dict.get("overall_risk_band", "SECURE")
    pcap_filename = analysis_dict.get("pcap_filename", "capture.pcap")

    # Threat level mapping: 1 (High/Critical), 2 (Medium), 3 (Low), 4 (Undefined)
    threat_level = "1" if overall_band in ("HIGH", "CRITICAL") else "3"

    attributes: list[dict[str, Any]] = []

    # Add PCAP SHA-256 attribute
    if "pcap_sha256" in analysis_dict:
        attributes.append({
            "category": "Payload delivery",
            "type": "sha256",
            "value": analysis_dict["pcap_sha256"],
            "comment": f"Original capture file digest ({pcap_filename})",
            "to_ids": False,
        })

    # Add Session Attributes
    for s in analysis_dict.get("sessions", []):
        server_ip = s.get("server_ip")
        ja3 = s.get("ja3")
        ja4 = s.get("ja4")
        sni = s.get("sni")
        risk_band = s.get("risk_band", "SECURE")
        is_risky = risk_band in ("HIGH", "CRITICAL") or s.get("starttls_state") == "S_STRIP_DETECTED"

        if server_ip and is_risky:
            attributes.append({
                "category": "Network activity",
                "type": "ip-dst",
                "value": server_ip,
                "comment": f"Server endpoint with {risk_band} posture in {s.get('protocol')} flow {s.get('id')}",
                "to_ids": True,
            })

        if ja3 and is_risky:
            attributes.append({
                "category": "Network activity",
                "type": "ja3-fingerprint-md5",
                "value": ja3,
                "comment": f"Client TLS JA3 fingerprint (Session {s.get('id')})",
                "to_ids": True,
            })

        if ja4 and is_risky:
            attributes.append({
                "category": "Network activity",
                "type": "text",
                "value": f"JA4:{ja4}",
                "comment": f"Client TLS JA4 fingerprint (Session {s.get('id')})",
                "to_ids": False,
            })

        if sni and is_risky:
            attributes.append({
                "category": "Network activity",
                "type": "hostname",
                "value": sni,
                "comment": f"SNI / Target host in {s.get('id')}",
                "to_ids": True,
            })

        # Add Certificate Fingerprints
        for cert in s.get("certificates", []):
            if "fingerprint_sha256" in cert:
                attributes.append({
                    "category": "Network activity",
                    "type": "x509-fingerprint-sha256",
                    "value": cert["fingerprint_sha256"],
                    "comment": f"X.509 Certificate SHA-256 for CN={cert.get('subject_dn', '')}",
                    "to_ids": False,
                })

    tags = [
        {"name": "tlp:amber+strict", "colour": "#f59e0b"},
        {"name": f"pecff:risk_band=\"{overall_band.lower()}\"", "colour": "#ef4444" if overall_band == "CRITICAL" else "#06b6d4"},
        {"name": "pecff:forensic-source=\"passive-email-cryptographic-forensics\"", "colour": "#38bdf8"},
    ]
    if overall_band in ("HIGH", "CRITICAL"):
        tags.append({"name": "nist-800-52r2:non-compliant", "colour": "#ef4444"})

    misp_payload = {
        "Event": {
            "uuid": str(uuid.uuid5(uuid.NAMESPACE_DNS, analysis_id)),
            "info": f"PECFF Cryptographic Forensics Audit - {pcap_filename} ({overall_band})",
            "date": created_at[:10] if isinstance(created_at, str) else datetime.now(UTC).strftime("%Y-%m-%d"),
            "threat_level_id": threat_level,
            "analysis": "2",  # Completed
            "distribution": "1",  # This community only
            "Tag": tags,
            "Attribute": attributes,
        }
    }

    misp_json = json.dumps(misp_payload, indent=2, sort_keys=True)

    if output_path:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(misp_json, encoding="utf-8")

    return misp_json
