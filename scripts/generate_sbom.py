#!/usr/bin/env python3
"""CycloneDX JSON Software Bill of Materials (SBOM) Generator.

Complies with CycloneDX v1.5 specification for forensic reproducibility and
supply-chain security auditing without external network access.
"""

from __future__ import annotations

import argparse
import datetime
import importlib.metadata
import json
import sys
import uuid
from pathlib import Path
from typing import Any


def generate_cyclonedx_sbom(output_path: Path | str = "sbom.cyclonedx.json") -> Path:
    """Generate a CycloneDX v1.5 JSON SBOM for the current Python environment."""
    out = Path(output_path)
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    serial_uuid = str(uuid.uuid4())

    components: list[dict[str, Any]] = []
    dependencies: list[dict[str, Any]] = []

    # Enumerate all installed distributions via importlib.metadata
    dists = list(importlib.metadata.distributions())
    dists_sorted = sorted(dists, key=lambda d: (d.metadata["Name"] or "").lower())

    for dist in dists_sorted:
        name = dist.metadata["Name"]
        version = dist.version
        if not name:
            continue

        purl = f"pkg:pypi/{name.lower()}@{version}"
        bom_ref = f"{name}@{version}"

        license_str = dist.metadata.get("License") or dist.metadata.get("License-Expression")
        licenses_list = []
        if license_str:
            licenses_list.append({"license": {"name": str(license_str)}})

        author = dist.metadata.get("Author") or dist.metadata.get("Author-email")
        description = dist.metadata.get("Summary") or ""

        component = {
            "type": "library",
            "bom-ref": bom_ref,
            "name": name,
            "version": version,
            "description": description,
            "purl": purl,
        }
        if licenses_list:
            component["licenses"] = licenses_list
        if author:
            component["author"] = str(author)

        components.append(component)

        # Direct dependencies
        requires = dist.requires or []
        dep_refs: list[str] = []
        for req in requires:
            req_name = req.split(";")[0].split()[0].replace(">", "").replace("<", "").replace("=", "").replace("~", "").strip()
            if req_name:
                dep_refs.append(req_name)

        dependencies.append({
            "ref": bom_ref,
            "dependsOn": sorted(list(set(dep_refs))),
        })

    sbom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial_uuid}",
        "version": 1,
        "metadata": {
            "timestamp": now_iso,
            "tools": [
                {
                    "vendor": "PECFF",
                    "name": "pecff-sbom-generator",
                    "version": "1.0.0",
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": "pecff@0.1.0",
                "name": "pecff",
                "version": "0.1.0",
                "description": "Passive Email Cryptography Forensic Framework",
            },
        },
        "components": components,
        "dependencies": dependencies,
    }

    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2, sort_keys=False)

    print(f"CycloneDX SBOM generated successfully: {out.resolve()} ({len(components)} components)")
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate CycloneDX JSON SBOM for PECFF.")
    parser.add_argument(
        "-o",
        "--output",
        default="sbom.cyclonedx.json",
        help="Target output path for the CycloneDX JSON SBOM (default: sbom.cyclonedx.json)",
    )
    args = parser.parse_args()
    generate_cyclonedx_sbom(args.output)


if __name__ == "__main__":
    main()
