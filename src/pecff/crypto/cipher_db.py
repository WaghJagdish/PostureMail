"""IANA TLS Cipher Suite database and cryptographic classification engine.

Loads static definitions from `data/ciphers.json` and evaluates NIST SP 800-52r2
compliance posture, Perfect Forward Secrecy (PFS), Authenticated Encryption (AEAD),
and weakness flags (NULL, EXPORT, RC4, 3DES, anonymous DH).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

DEFAULT_CIPHERS_PATH: Final[Path] = (
    Path(__file__).resolve().parent.parent.parent.parent / "data" / "ciphers.json"
)


@dataclass(frozen=True, slots=True)
class CipherSuiteInfo:
    """Cryptographic properties and NIST status of a TLS cipher suite."""

    id: str  # e.g., "0x1301"
    name: str  # e.g., "TLS_AES_128_GCM_SHA256"
    kex: str  # "ECDHE", "DHE", "RSA", "DH_anon", "UNKNOWN"
    auth: str  # "RSA", "ECDSA", "any", "anon", "UNKNOWN"
    enc: str  # "AES-128-GCM", "CHACHA20-POLY1305", "3DES-EDE-CBC", "NULL"
    enc_bits: int  # 128, 256, 112, 56, 40, 0
    mac: str  # "AEAD", "HMAC-SHA256", "HMAC-SHA1", "HMAC-MD5"
    hash: str  # "SHA256", "SHA384", "SHA1", "MD5", "UNKNOWN"
    pfs: bool  # Perfect Forward Secrecy
    aead: bool  # Authenticated Encryption with Associated Data
    export: bool  # Export-grade cipher (weakened)
    anon: bool  # Anonymous key exchange (no authentication)
    null_enc: bool  # Plaintext / NULL encryption
    nist_status: str  # "approved", "legacy", "prohibited", "unknown"

    @property
    def is_approved(self) -> bool:
        return self.nist_status == "approved"

    @property
    def is_legacy(self) -> bool:
        return self.nist_status == "legacy"

    @property
    def is_prohibited(self) -> bool:
        return self.nist_status == "prohibited"


class CipherDatabase:
    """Lookup repository for TLS cipher suites with unknown-safe resolution."""

    def __init__(self, data_path: Path | None = None) -> None:
        self._ciphers: dict[str, CipherSuiteInfo] = {}
        target_path = data_path or DEFAULT_CIPHERS_PATH
        self._load_database(target_path)

    def _load_database(self, path: Path) -> None:
        """Load cipher suite records from JSON."""
        if not path.exists():
            return

        try:
            with open(path, encoding="utf-8") as f:
                data: dict[str, dict[str, Any]] = json.load(f)
                for hex_id, c in data.items():
                    info = CipherSuiteInfo(
                        id=c["id"],
                        name=c["name"],
                        kex=c["kex"],
                        auth=c["auth"],
                        enc=c["enc"],
                        enc_bits=c["enc_bits"],
                        mac=c["mac"],
                        hash=c["hash"],
                        pfs=c["pfs"],
                        aead=c["aead"],
                        export=c["export"],
                        anon=c["anon"],
                        null_enc=c["null_enc"],
                        nist_status=c["nist_status"],
                    )
                    self._ciphers[hex_id.lower()] = info
                    self._ciphers[hex_id.upper()] = info
        except Exception:
            pass

    def get(self, cipher_id: int | str) -> CipherSuiteInfo:
        """Retrieve cipher suite metadata, resolving unknown IDs to a safe record."""
        if isinstance(cipher_id, int):
            hex_str = f"0x{cipher_id:04x}"
        else:
            hex_str = str(cipher_id).lower()
            if not hex_str.startswith("0x"):
                hex_str = f"0x{hex_str}"

        if hex_str.lower() in self._ciphers:
            return self._ciphers[hex_str.lower()]

        # Safe unknown fallback: scores as moderately risky rather than crashing or 0
        return CipherSuiteInfo(
            id=hex_str,
            name=f"TLS_UNKNOWN_CIPHER_{hex_str}",
            kex="UNKNOWN",
            auth="UNKNOWN",
            enc="UNKNOWN",
            enc_bits=0,
            mac="UNKNOWN",
            hash="UNKNOWN",
            pfs=False,
            aead=False,
            export=False,
            anon=False,
            null_enc=False,
            nist_status="unknown",
        )

    @classmethod
    def lookup(cls, cipher_id: int | str) -> CipherSuiteInfo:
        """Classmethod lookup via global singleton."""
        return cipher_db.get(cipher_id)


# Global singleton instance for framework-wide lookup
cipher_db = CipherDatabase()
