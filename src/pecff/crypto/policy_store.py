"""Offline MTA-STS and DANE TLSA policy storage and verification engine.

Provides strictly offline lookup of pre-synced MTA-STS policies (RFC 8461)
and DANE TLSA records (RFC 6698 / RFC 7672) for cryptographic enforcement
and downgrade detection (Detector D9).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from pecff.config import settings


@dataclass(frozen=True, slots=True)
class MTASTSPolicy:
    """MTA-STS policy representation (RFC 8461)."""

    domain: str
    mode: str  # "enforce", "testing", "none"
    max_age: int
    mx: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class TLSARecord:
    """DANE TLSA DNS record representation (RFC 6698)."""

    domain: str
    port: int
    protocol: str  # "tcp", "udp"
    usage: int  # 0=PKIX-TA, 1=PKIX-EE, 2=DANE-TA, 3=DANE-EE
    selector: int  # 0=Full Cert, 1=SubjectPublicKeyInfo
    matching_type: int  # 0=Exact, 1=SHA-256, 2=SHA-512
    cert_association_data: str  # Hex string


class PolicyStore:
    """Offline repository for operator-synced MTA-STS and DANE TLSA records."""

    def __init__(
        self,
        mta_sts_dir: Path | None = None,
        dane_dir: Path | None = None,
    ) -> None:
        self.mta_sts_dir = mta_sts_dir or settings.mta_sts_cache_dir
        self.dane_dir = dane_dir or Path("data/dane_cache")
        self._mta_sts_policies: dict[str, MTASTSPolicy] = {}
        self._tlsa_records: dict[str, list[TLSARecord]] = {}

        self._load_policies()

    def _load_policies(self) -> None:
        """Load offline policies from disk."""
        # 1. MTA-STS policies
        if self.mta_sts_dir and self.mta_sts_dir.exists():
            if self.mta_sts_dir.is_file():
                self._load_mta_sts_file(self.mta_sts_dir)
            else:
                for json_file in self.mta_sts_dir.glob("*.json"):
                    self._load_mta_sts_file(json_file)

        # 2. DANE TLSA records
        if self.dane_dir and self.dane_dir.exists():
            if self.dane_dir.is_file():
                self._load_tlsa_file(self.dane_dir)
            else:
                for json_file in self.dane_dir.glob("*.json"):
                    self._load_tlsa_file(json_file)

    def _load_mta_sts_file(self, file_path: Path) -> None:
        try:
            with open(file_path, encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    if "domain" in data and "mode" in data:
                        p = MTASTSPolicy(
                            domain=data["domain"].lower().strip(),
                            mode=data.get("mode", "none").lower().strip(),
                            max_age=data.get("max_age", 86400),
                            mx=data.get("mx", []),
                        )
                        self._mta_sts_policies[p.domain] = p
                    else:
                        for domain, pol_data in data.items():
                            if isinstance(pol_data, dict):
                                p = MTASTSPolicy(
                                    domain=domain.lower().strip(),
                                    mode=pol_data.get("mode", "none").lower().strip(),
                                    max_age=pol_data.get("max_age", 86400),
                                    mx=pol_data.get("mx", []),
                                )
                                self._mta_sts_policies[p.domain] = p
                            elif isinstance(pol_data, str):
                                p = MTASTSPolicy(
                                    domain=domain.lower().strip(),
                                    mode=pol_data.lower().strip(),
                                    max_age=86400,
                                    mx=[],
                                )
                                self._mta_sts_policies[p.domain] = p
        except Exception:
            pass

    def _load_tlsa_file(self, file_path: Path) -> None:
        try:
            with open(file_path, encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    for domain_key, records in data.items():
                        norm_domain = domain_key.lower().strip()
                        if norm_domain not in self._tlsa_records:
                            self._tlsa_records[norm_domain] = []
                        if isinstance(records, list):
                            for r in records:
                                tlsa = TLSARecord(
                                    domain=norm_domain,
                                    port=int(r.get("port", 25)),
                                    protocol=str(r.get("protocol", "tcp")).lower(),
                                    usage=int(r.get("usage", 3)),
                                    selector=int(r.get("selector", 1)),
                                    matching_type=int(r.get("matching_type", 1)),
                                    cert_association_data=str(r.get("data", ""))
                                    .lower()
                                    .replace(" ", "")
                                    .replace(":", ""),
                                )
                                self._tlsa_records[norm_domain].append(tlsa)
        except Exception:
            pass

    def add_mta_sts_policy(
        self, domain: str, mode: str, max_age: int = 86400, mx: list[str] | None = None
    ) -> None:
        """Register an in-memory MTA-STS policy."""
        domain_clean = domain.lower().strip()
        self._mta_sts_policies[domain_clean] = MTASTSPolicy(
            domain=domain_clean,
            mode=mode.lower().strip(),
            max_age=max_age,
            mx=mx or [],
        )

    def add_tlsa_record(
        self,
        domain: str,
        port: int = 25,
        protocol: str = "tcp",
        usage: int = 3,
        selector: int = 1,
        matching_type: int = 1,
        cert_association_data: str = "",
    ) -> None:
        """Register an in-memory TLSA record."""
        domain_clean = domain.lower().strip()
        record = TLSARecord(
            domain=domain_clean,
            port=port,
            protocol=protocol.lower().strip(),
            usage=usage,
            selector=selector,
            matching_type=matching_type,
            cert_association_data=cert_association_data.lower().replace(" ", "").replace(":", ""),
        )
        if domain_clean not in self._tlsa_records:
            self._tlsa_records[domain_clean] = []
        self._tlsa_records[domain_clean].append(record)

    def get_mta_sts_policy(self, domain: str) -> MTASTSPolicy | None:
        """Lookup MTA-STS policy for a given domain."""
        return self._mta_sts_policies.get(domain.lower().strip())

    def get_tlsa_records(
        self, domain: str, port: int = 25, protocol: str = "tcp"
    ) -> list[TLSARecord]:
        """Lookup DANE TLSA records for a domain, port, and protocol."""
        domain_clean = domain.lower().strip()
        records = self._tlsa_records.get(domain_clean, [])
        return [r for r in records if r.port == port and r.protocol == protocol.lower()]

    def verify_dane_record(
        self,
        record: TLSARecord,
        cert_der: bytes,
        spki_der: bytes,
    ) -> bool:
        """Evaluate a single TLSA record match against candidate certificate data."""
        if record.selector == 0:  # Full certificate
            target_data = cert_der
        elif record.selector == 1:  # SubjectPublicKeyInfo
            target_data = spki_der
        else:
            return False

        if record.matching_type == 0:  # Exact
            computed_hex = target_data.hex().lower()
        elif record.matching_type == 1:  # SHA-256
            computed_hex = hashlib.sha256(target_data).hexdigest().lower()
        elif record.matching_type == 2:  # SHA-512
            computed_hex = hashlib.sha512(target_data).hexdigest().lower()
        else:
            return False

        return computed_hex == record.cert_association_data.lower()
