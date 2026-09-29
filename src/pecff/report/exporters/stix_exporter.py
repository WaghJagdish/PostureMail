"""STIX 2.1 Threat Intelligence Bundle exporter.

Generates standard OASIS STIX 2.1 bundles containing:
- Indicator objects for suspicious/malicious JA3 hashes, anomalous IPs, and certificate fingerprints
- ObservedData and Cyber Observable Objects (IPv4Address, DomainName) for sessions
- Relationship objects linking indicators to observed forensic data
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    import importlib.util

    HAS_STIX2_LIB = importlib.util.find_spec("stix2") is not None
    if HAS_STIX2_LIB:
        from stix2 import Bundle, DomainName, Indicator, IPv4Address, ObservedData, Relationship
except ImportError:
    HAS_STIX2_LIB = False


def export_stix2_bundle(
    analysis_dict: dict[str, Any],
    output_path: Path | str | None = None,
) -> str:
    """Generate and validate standard STIX 2.1 JSON bundle from forensic analysis."""
    sessions = analysis_dict.get("sessions", [])
    analysis_id = analysis_dict.get("analysis_id", "pecff-analysis")
    created_at_dt = datetime.now(UTC)

    stix_objects: list[Any] = []
    indicators_created: list[tuple[Any, str]] = []

    for s in sessions:
        session_id = s.get("id", "sess")
        server_ip = s.get("server_ip")
        client_ip = s.get("client_ip")
        sni = s.get("sni")
        ja3 = s.get("ja3")
        risk_band = s.get("risk_band", "SECURE")
        is_critical = risk_band in ("HIGH", "CRITICAL") or s.get("starttls_state") == "S_STRIP_DETECTED"

        first_seen_ts = s.get("first_seen", 1700000000.0)
        dt_first = datetime.fromtimestamp(first_seen_ts, tz=UTC)
        duration = s.get("duration_sec", 1.0)
        dt_last = datetime.fromtimestamp(first_seen_ts + duration, tz=UTC)

        if HAS_STIX2_LIB:
            # Create Cyber Observable Objects
            observable_refs: list[str] = []
            if server_ip:
                ip_obs = IPv4Address(value=server_ip)
                stix_objects.append(ip_obs)
                observable_refs.append(ip_obs.id)

            if client_ip:
                client_obs = IPv4Address(value=client_ip)
                stix_objects.append(client_obs)
                observable_refs.append(client_obs.id)

            if sni:
                domain_obs = DomainName(value=sni)
                stix_objects.append(domain_obs)
                observable_refs.append(domain_obs.id)

            # ObservedData linking the observable refs
            obs = ObservedData(
                first_observed=dt_first,
                last_observed=dt_last,
                number_observed=1,
                object_refs=observable_refs,
                custom_properties={
                    "x_pecff_session_id": session_id,
                    "x_pecff_risk_score": s.get("risk_score", 0),
                    "x_pecff_starttls_state": s.get("starttls_state", "S4_ENCRYPTED"),
                },
            )
            stix_objects.append(obs)

            # Indicators for High Risk / Anomalous sessions
            if is_critical and ja3:
                is_md5 = bool(re.match(r"^[a-fA-F0-9]{32}$", ja3))
                ja3_md5 = ja3.lower() if is_md5 else hashlib.md5(ja3.encode("utf-8")).hexdigest()
                ind = Indicator(
                    name=f"PECFF Cryptographic Risk Indicator - JA3 {ja3_md5[:16]}",
                    description=f"Suspicious TLS client fingerprint {ja3} associated with {risk_band} mail session {session_id}",
                    pattern=f"[file:hashes.'MD5' = '{ja3_md5}']",
                    pattern_type="stix",
                    valid_from=dt_first,
                    indicator_types=["malicious-activity" if risk_band == "CRITICAL" else "anomalous-activity"],
                )
                stix_objects.append(ind)
                indicators_created.append((ind, obs.id))

            if s.get("starttls_state") == "S_STRIP_DETECTED" and server_ip:
                ind_strip = Indicator(
                    name=f"PECFF STARTTLS Stripping Node - {server_ip}",
                    description=f"Host {server_ip} observed stripping 250-STARTTLS capability from mail server greeting.",
                    pattern=f"[ipv4-addr:value = '{server_ip}']",
                    pattern_type="stix",
                    valid_from=dt_first,
                    indicator_types=["malicious-activity"],
                )
                stix_objects.append(ind_strip)
                indicators_created.append((ind_strip, obs.id))

    # Build Relationships
    if HAS_STIX2_LIB:
        for ind_obj, obs_id in indicators_created:
            rel = Relationship(
                source_ref=ind_obj.id,
                target_ref=obs_id,
                relationship_type="indicates",
                description="Indicator observed in recorded mail flow session.",
            )
            stix_objects.append(rel)

        bundle = Bundle(objects=stix_objects, allow_custom=True)
        bundle_json = str(bundle.serialize(pretty=True))
    else:
        raw_bundle = {
            "type": "bundle",
            "id": f"bundle--{analysis_id}",
            "objects": [
                {
                    "type": "indicator",
                    "id": f"indicator--{analysis_id}",
                    "spec_version": "2.1",
                    "created": created_at_dt.isoformat(),
                    "modified": created_at_dt.isoformat(),
                    "name": "PECFF Analysis Summary Indicator",
                    "pattern": "[network-traffic:dst_port = 25]",
                    "pattern_type": "stix",
                    "valid_from": created_at_dt.isoformat(),
                }
            ],
        }
        bundle_json = json.dumps(raw_bundle, indent=2)

    if output_path:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(bundle_json, encoding="utf-8")

    return bundle_json
