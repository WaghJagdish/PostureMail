"""RFC 6125 compliant X.509 hostname and SAN verification engine.

Enforces RFC 6125 §6.4.3 domain verification rules:
- Strictly matches against Subject Alternative Name (SAN) dNSName and iPAddress.
- CN fallback is DISABLED (RFC 6125 / CA/B Forum deprecation). If CN would have
  matched but SAN does not, emits `CERT_CN_ONLY_MATCH` for auditable provenance.
- Wildcards are permitted ONLY in the leftmost label and must comprise the ENTIRE
  label (e.g., `*.example.com`). Partial wildcards (`f*.example.com`) are rejected.
- Wildcards never match a bare apex domain or multiple subdomain levels.
- IDNA 2008 A-label normalization for internationalized domain names.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Final

import idna

from pecff.crypto.x509_parser import ParsedCertificate
from pecff.ingest.reassembly import ReassemblyFinding

RE_IPV4: Final[re.Pattern[str]] = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


@dataclass(frozen=True, slots=True)
class HostnameVerificationResult:
    """Result of RFC 6125 hostname matching."""

    matched: bool
    status: str  # "MATCH", "MISMATCH", "INDETERMINATE"
    method: str  # "sni", "alpn", "ehlo", "reverse_dns", "none"
    reference_identifier: str | None
    matched_san: str | None = None
    findings: list[ReassemblyFinding] = field(default_factory=list)


def normalize_domain(domain: str) -> str:
    """Normalize a domain string to IDNA 2008 lowercase ASCII (A-label)."""
    clean = domain.strip().lower().rstrip(".")
    if not clean:
        return ""
    labels = clean.split(".")
    encoded_labels: list[str] = []
    for lbl in labels:
        if lbl == "*":
            encoded_labels.append("*")
        else:
            try:
                encoded_labels.append(idna.encode(lbl).decode("ascii"))
            except Exception:
                encoded_labels.append(lbl)
    return ".".join(encoded_labels)


def is_valid_wildcard_pattern(pattern: str) -> bool:
    """Validate that wildcard pattern complies with RFC 6125 §6.4.3."""
    labels = pattern.split(".")
    # Must have at least 3 labels for a valid wildcard (e.g. *.example.com, not *.com or *)
    if len(labels) < 3:
        return False

    # Wildcard must be ONLY in leftmost label
    if labels[0] != "*":
        return False

    # No wildcards allowed in subsequent labels
    return all("*" not in lbl for lbl in labels[1:])


def match_wildcard_pattern(pattern: str, hostname: str) -> bool:
    """Match single-level wildcard against hostname strictly per RFC 6125 §6.4.3."""
    norm_pattern = normalize_domain(pattern)
    norm_host = normalize_domain(hostname)

    if not is_valid_wildcard_pattern(norm_pattern):
        return False

    pattern_labels = norm_pattern.split(".")
    host_labels = norm_host.split(".")

    # Exact label count match required: *.a.com (3 labels) only matches x.a.com (3 labels),
    # never bare apex a.com (2 labels) or sub-subdomains x.y.a.com (4 labels).
    if len(pattern_labels) != len(host_labels):
        return False

    # Suffix labels must match exactly
    return pattern_labels[1:] == host_labels[1:]


def match_dns_name(san_entry: str, hostname: str) -> bool:
    """Match a single SAN entry against a target hostname."""
    norm_san = normalize_domain(san_entry)
    norm_host = normalize_domain(hostname)

    if not norm_san or not norm_host:
        return False

    if norm_san.startswith("*"):
        return match_wildcard_pattern(norm_san, norm_host)

    return norm_san == norm_host


class HostnameVerifier:
    """RFC 6125 compliant certificate hostname verifier."""

    @classmethod
    def verify(
        cls,
        cert: ParsedCertificate,
        sni: str | None = None,
        alpn_host: str | None = None,
        ehlo_domain: str | None = None,
        reverse_dns_cache: dict[str, str] | None = None,
        server_ip: str | None = None,
    ) -> HostnameVerificationResult:
        """Verify certificate SAN against reference identifier with prioritized fallback."""
        findings: list[ReassemblyFinding] = []

        # 1. Determine Reference Identifier in strict priority order
        ref_id: str | None = None
        method = "none"

        if sni:
            ref_id = sni.strip()
            method = "sni"
        elif alpn_host:
            ref_id = alpn_host.strip()
            method = "alpn"
        elif ehlo_domain:
            ref_id = ehlo_domain.strip()
            method = "ehlo"
        elif server_ip and reverse_dns_cache and server_ip in reverse_dns_cache:
            ref_id = reverse_dns_cache[server_ip].strip()
            method = "reverse_dns"

        if not ref_id:
            return HostnameVerificationResult(
                matched=False,
                status="INDETERMINATE",
                method="none",
                reference_identifier=None,
                matched_san=None,
                findings=[],
            )

        # 2. Check if Reference Identifier is an IP address
        is_ip = False
        try:
            ipaddress.ip_address(ref_id)
            is_ip = True
        except ValueError:
            is_ip = False

        matched_san: str | None = None

        if is_ip:
            # IP Address matching against san_ip
            for san in cert.san_ip:
                if san.strip() == ref_id:
                    matched_san = san
                    break
        else:
            # Domain matching against san_dns
            norm_ref = normalize_domain(ref_id)
            for san in cert.san_dns:
                if match_dns_name(san, norm_ref):
                    matched_san = san
                    break

        if matched_san:
            return HostnameVerificationResult(
                matched=True,
                status="MATCH",
                method=method,
                reference_identifier=ref_id,
                matched_san=matched_san,
                findings=[],
            )

        # 3. Check deprecated Common Name (CN) fallback
        cn_match = False
        if not is_ip and cert.subject_dn:
            # Extract CN= from subject_dn
            m_cn = re.search(r"CN=([^,]+)", cert.subject_dn)
            if m_cn:
                cn_val = m_cn.group(1).strip()
                if match_dns_name(cn_val, ref_id):
                    cn_match = True

        if cn_match:
            findings.append(
                ReassemblyFinding(
                    rule_id="CERT_CN_ONLY_MATCH",
                    rule_name="Deprecated CommonName Matching Without SAN",
                    severity="MEDIUM",
                    description=(
                        f"Hostname '{ref_id}' matches certificate CommonName '{cn_val}', "
                        "but Subject Alternative Name (SAN) extension does not contain a matching entry. "
                        "RFC 6125 and CA/Browser Forum require valid SAN entries."
                    ),
                    evidence={
                        "reference_identifier": ref_id,
                        "common_name": cn_val,
                        "san_dns": cert.san_dns,
                    },
                )
            )

        return HostnameVerificationResult(
            matched=False,
            status="MISMATCH",
            method=method,
            reference_identifier=ref_id,
            matched_san=None,
            findings=findings,
        )
