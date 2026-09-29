"""Forensic PII scrubbing, salted pseudorandom redaction, and retention policy manager.

Requirements:
- Email addresses and cleartext credentials are SHA-256 + deployment-salt hashed by default.
- Raw values require settings.retain_pii plus an audit-logged justification string.
- Reports must visibly mark when PII is present vs redacted.
- Implement configurable retention TTL sweeper for PCAP capture blobs.
"""

from __future__ import annotations

import copy
import hashlib
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pecff.config import get_settings

EMAIL_REGEX = re.compile(r"([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)")
AUTH_CRED_REGEX = re.compile(
    r"(?i)\b(AUTH\s+(?:PLAIN|LOGIN)\s+[A-Za-z0-9+/=]+|PASS(?:WORD)?\s+[^\r\n]+)"
)


@dataclass
class PIIScrubResult:
    """Result payload from forensic privacy scrubber."""

    sanitized_data: dict[str, Any]
    pii_redacted: bool
    redaction_count: int
    salt_hash: str
    retained_with_justification: str | None = None


def hash_email_with_salt(email: str, salt: str) -> str:
    """Hash localpart with salt while keeping partial domain context for routing forensics."""
    match = EMAIL_REGEX.match(email)
    if not match:
        digest = hashlib.sha256((salt + email).encode("utf-8")).hexdigest()[:12]
        return f"redacted_{digest}@redacted.local"

    local, domain = match.groups()
    local_digest = hashlib.sha256((salt + local.lower()).encode("utf-8")).hexdigest()[:12]
    return f"u_{local_digest}@{domain}"


def hash_credentials_with_salt(raw_text: str, salt: str) -> str:
    """Detect and securely salt-hash cleartext authentication credentials in string dumps."""

    def replace_cred(m: re.Match[str]) -> str:
        matched = m.group(0)
        digest = hashlib.sha256((salt + matched).encode("utf-8")).hexdigest()[:16]
        return f"[REDACTED_CREDENTIAL_SHA256_{digest}]"

    return AUTH_CRED_REGEX.sub(replace_cred, raw_text)


def scrub_pii_from_analysis(
    analysis_data: dict[str, Any],
    retain_pii: bool = False,
    justification: str | None = None,
    deployment_salt: str | None = None,
) -> PIIScrubResult:
    """Scrub all email addresses and credential payloads across analysis session tree.

    If retain_pii is False (default), emails are salted-hashed and credentials replaced.
    If retain_pii is True, justification is verified and an audit flag is recorded.
    """
    settings = get_settings()
    salt: str = (
        deployment_salt
        if deployment_salt is not None
        else str(getattr(settings, "deployment_salt", "pecff_default_deployment_salt_2026"))
    )
    salt_hash = hashlib.sha256(salt.encode("utf-8")).hexdigest()[:16]

    allow_retention = retain_pii and bool(justification and justification.strip())

    if allow_retention:
        # PII retained per explicit operational justification
        data_copy = copy.deepcopy(analysis_data)
        data_copy["pii_retained"] = True
        data_copy["pii_justification"] = justification
        data_copy["pii_redacted"] = False
        return PIIScrubResult(
            sanitized_data=data_copy,
            pii_redacted=False,
            redaction_count=0,
            salt_hash=salt_hash,
            retained_with_justification=justification,
        )

    # Deep scrub
    data_copy = copy.deepcopy(analysis_data)
    redaction_count = 0

    def scrub_value(val: Any) -> Any:
        nonlocal redaction_count
        if isinstance(val, str):
            orig = val
            # Scrub credentials first
            val = hash_credentials_with_salt(val, salt)
            # Scrub emails
            def replace_email(m: re.Match[str]) -> str:
                return hash_email_with_salt(m.group(0), salt)

            val = EMAIL_REGEX.sub(replace_email, val)
            if val != orig:
                redaction_count += 1
            return val
        elif isinstance(val, dict):
            return {k: scrub_value(v) for k, v in val.items()}
        elif isinstance(val, list):
            return [scrub_value(item) for item in val]
        return val

    scrubbed = scrub_value(data_copy)
    scrubbed["pii_redacted"] = True
    scrubbed["pii_salt_fingerprint"] = salt_hash
    scrubbed["pii_retained"] = False

    return PIIScrubResult(
        sanitized_data=scrubbed,
        pii_redacted=True,
        redaction_count=redaction_count,
        salt_hash=salt_hash,
        retained_with_justification=None,
    )


class PCAPRetentionSweeper:
    """Automated retention policy sweeper for raw PCAP capture artifacts."""

    def __init__(self, storage_dir: Path | str, retention_ttl_hours: int = 72) -> None:
        self.storage_dir = Path(storage_dir)
        self.retention_ttl_seconds = retention_ttl_hours * 3600

    def sweep_expired_captures(self) -> list[Path]:
        """Find and remove capture files that have exceeded the retention TTL."""
        removed: list[Path] = []
        if not self.storage_dir.exists():
            return removed

        now = time.time()
        for file_path in self.storage_dir.glob("*.pcap*"):
            if not file_path.is_file():
                continue
            try:
                mtime = file_path.stat().st_mtime
                if (now - mtime) > self.retention_ttl_seconds:
                    file_path.unlink()
                    removed.append(file_path)
            except OSError:
                continue

        return removed
