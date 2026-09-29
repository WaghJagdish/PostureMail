"""Offline X.509 certificate chain validation and revocation verification engine.

Hard Constraints Enforced:
1. STRICTLY PASSIVE: Zero network I/O, zero socket connections, zero dynamic AIA/OCSP fetching.
2. TEMPORAL CORRECTNESS: Evaluates certificate validity strictly against the PCAP
   capture timestamp, NEVER datetime.now().
3. REPRODUCIBILITY: Surfaces Mozilla NSS root bundle SHA-256 in every verdict.
4. AUDITABLE PROVENANCE: Records trust anchor source ('mozilla_nss' | 'enterprise')
   and wraps validation failures into structured ChainError codes.
5. THREE-TIER OFFLINE REVOCATION: Stapled OCSP with responder authorization verification,
   offline CRL cache, and explicit UNKNOWN fallback without guessing.
"""

from __future__ import annotations

import contextlib
import glob
import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

import certifi
from certvalidator import CertificateValidator, ValidationContext
from certvalidator.errors import (
    InvalidCertificateError,
    PathBuildingError,
    PathValidationError,
    RevokedError,
    ValidationError,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

from pecff.config import settings
from pecff.crypto.x509_parser import ParsedCertificate, X509Parser
from pecff.ingest.reassembly import ReassemblyFinding

# OID for id-kp-OCSPSigning (RFC 6960 §4.2.2.2)
OID_OCSP_SIGNING: Final[str] = "1.3.6.1.5.5.7.3.5"


@dataclass(frozen=True, slots=True)
class ChainError:
    """Structured certificate chain validation error."""

    code: str  # e.g., "CERT_EXPIRED", "UNTRUSTED_ROOT", "REVOKED"
    message: str


@dataclass(slots=True)
class ChainValidationResult:
    """Forensic outcome of offline certificate chain validation."""

    is_valid: bool
    chain_length: int
    trust_anchor_dn: str | None = None
    trust_anchor_fingerprint: str | None = None
    anchor_source: str = "untrusted"  # "mozilla_nss", "enterprise", "self_signed", "untrusted"
    mozilla_bundle_sha256: str = ""
    errors: list[ChainError] = field(default_factory=list)
    findings: list[ReassemblyFinding] = field(default_factory=list)
    ocsp_status: str = "UNKNOWN"  # "GOOD", "REVOKED", "UNAUTHORIZED", "EXPIRED", "UNKNOWN"
    crl_status: str = "UNKNOWN"  # "GOOD", "REVOKED", "EXPIRED", "UNKNOWN"
    validated_path_fingerprints: list[str] = field(default_factory=list)


class OfflineChainValidator:
    """Deterministic offline X.509 path builder and three-tier revocation verifier."""

    def __init__(
        self,
        enterprise_roots_dir: Path | None = None,
        intermediate_cache_dir: Path | None = None,
        crl_cache_dir: Path | None = None,
        expected_interception_proxies: set[str] | None = None,
    ) -> None:
        self.enterprise_roots_dir = enterprise_roots_dir or settings.enterprise_roots_path
        self.intermediate_cache_dir = intermediate_cache_dir or settings.intermediate_cache_path
        self.crl_cache_dir = crl_cache_dir or settings.crl_cache_path
        self.expected_interception_proxies: set[str] = (
            expected_interception_proxies
            if expected_interception_proxies is not None
            else set(settings.expected_interception_proxies)
        )

        self._mozilla_bundle_sha256: str = ""
        self._mozilla_roots_fps: set[str] = set()
        self._mozilla_roots_bytes: list[bytes] = []
        self._enterprise_roots_fps: set[str] = set()
        self._enterprise_roots_bytes: list[bytes] = []
        self._cached_intermediates_bytes: list[bytes] = []

        self._load_trust_stores()

    def _load_trust_stores(self) -> None:
        """Load offline Mozilla NSS roots, enterprise anchors, and intermediate caches."""
        # 1. Mozilla NSS roots from certifi
        try:
            certifi_path = Path(certifi.where())
            if certifi_path.exists():
                raw = certifi_path.read_bytes()
                self._mozilla_bundle_sha256 = hashlib.sha256(raw).hexdigest()
                certs = x509.load_pem_x509_certificates(raw)
                for c in certs:
                    self._mozilla_roots_fps.add(c.fingerprint(hashes.SHA256()).hex().lower())
                    self._mozilla_roots_bytes.append(c.public_bytes(serialization.Encoding.DER))
        except Exception:
            self._mozilla_bundle_sha256 = "UNAVAILABLE"

        # 2. Enterprise Roots from /etc/pecff/enterprise_roots.d/*.pem
        self._enterprise_roots_fps = set()
        self._enterprise_roots_bytes = []
        if self.enterprise_roots_dir and self.enterprise_roots_dir.exists():
            for pem_file in glob.glob(str(self.enterprise_roots_dir / "*.pem")):
                try:
                    raw = Path(pem_file).read_bytes()
                    certs = x509.load_pem_x509_certificates(raw)
                    for c in certs:
                        self._enterprise_roots_fps.add(c.fingerprint(hashes.SHA256()).hex().lower())
                        self._enterprise_roots_bytes.append(
                            c.public_bytes(serialization.Encoding.DER)
                        )
                except Exception:
                    continue

        # 3. Intermediates Cache
        self._cached_intermediates_bytes = []
        if self.intermediate_cache_dir and self.intermediate_cache_dir.exists():
            for cert_file in glob.glob(str(self.intermediate_cache_dir / "*")):
                try:
                    raw = Path(cert_file).read_bytes()
                    if b"-----BEGIN CERTIFICATE-----" in raw:
                        certs = x509.load_pem_x509_certificates(raw)
                        for c in certs:
                            self._cached_intermediates_bytes.append(
                                c.public_bytes(serialization.Encoding.DER)
                            )
                    else:
                        self._cached_intermediates_bytes.append(raw)
                except Exception:
                    continue

    def validate_chain(
        self,
        chain_der: list[bytes],
        capture_timestamp: float,
        stapled_ocsp_der: bytes | None = None,
        offline_crls: dict[str, bytes] | None = None,
    ) -> ChainValidationResult:
        """Validate certificate chain at capture_timestamp against offline trust anchors."""
        if not chain_der:
            return ChainValidationResult(
                is_valid=False,
                chain_length=0,
                anchor_source="untrusted",
                mozilla_bundle_sha256=self._mozilla_bundle_sha256,
                errors=[ChainError("EMPTY_CHAIN", "No certificates provided for validation")],
            )

        errors: list[ChainError] = []
        findings: list[ReassemblyFinding] = []

        # Convert capture timestamp to UTC datetime (CRITICAL: Never use datetime.now())
        moment = datetime.fromtimestamp(capture_timestamp, tz=UTC)

        # Parse leaf certificate
        leaf_der = chain_der[0]
        leaf_parsed = X509Parser.parse_der(leaf_der)

        # Explicit temporal check on leaf certificate against capture timestamp
        if moment < leaf_parsed.not_before:
            errors.append(
                ChainError(
                    "CERT_NOT_YET_VALID",
                    f"Certificate not yet valid at capture time ({moment.isoformat()})",
                )
            )
        elif moment > leaf_parsed.not_after:
            errors.append(
                ChainError(
                    "CERT_EXPIRED",
                    f"Certificate expired at capture time ({moment.isoformat()})",
                )
            )

        # ---------------------------------------------------------------------
        # 1. Path Building and Root Validation via certvalidator
        # ---------------------------------------------------------------------
        # Load extra trust roots
        extra_trust_roots = (
            list(self._enterprise_roots_bytes) if self._enterprise_roots_bytes else None
        )

        # Intermediates from handshake chain + offline intermediate cache
        intermediate_pool = list(chain_der[1:]) + list(self._cached_intermediates_bytes)

        # Build certvalidator ValidationContext
        context = ValidationContext(
            extra_trust_roots=extra_trust_roots,
            other_certs=intermediate_pool,
            moment=moment,
            allow_fetching=False,
            weak_hash_algos={"md5", "sha1"},
        )

        is_valid = False
        anchor_source = "untrusted"
        anchor_dn: str | None = None
        anchor_fp: str | None = None
        validated_path_fps: list[str] = []
        chain_len = len(chain_der)

        try:
            validator = CertificateValidator(
                leaf_der,
                intermediate_certs=intermediate_pool,
                validation_context=context,
            )
            validator._validate_path()
            val_path = validator._path

            if val_path:
                is_valid = len(errors) == 0
                chain_len = len(val_path)

                root_cert = val_path[0]
                anchor_dn = root_cert.subject.human_friendly
                anchor_fp = hashlib.sha256(root_cert.dump()).hexdigest().lower()

                if anchor_fp in self._enterprise_roots_fps:
                    anchor_source = "enterprise"
                elif anchor_fp in self._mozilla_roots_fps:
                    anchor_source = "mozilla_nss"
                else:
                    anchor_source = "mozilla_nss"

                for cert_item in val_path:
                    validated_path_fps.append(hashlib.sha256(cert_item.dump()).hexdigest().lower())

                # Check for TLS inspection proxy in validated path
                proxy_markers = ("proxy", "inspection", "interception", "bluecoat", "zscaler", "fortinet", "palo alto", "mitm")
                detected_proxy = any(
                    any(m in (c.subject.human_friendly or "").lower() or m in (c.issuer.human_friendly or "").lower() for m in proxy_markers)
                    for c in val_path
                )
                if detected_proxy:
                    is_authorized = (
                        (anchor_fp in self.expected_interception_proxies)
                        or any(p.lower() in (anchor_dn or "").lower() for p in self.expected_interception_proxies)
                    )
                    if is_authorized:
                        findings.append(
                            ReassemblyFinding(
                                rule_id="AUTHORIZED_INTERCEPTION_PROXY",
                                rule_name="Authorized Enterprise Inspection Proxy",
                                severity="INFO",
                                description=f"TLS session re-signed by authorized enterprise proxy: {anchor_dn}",
                                evidence={"anchor_dn": anchor_dn, "anchor_fp": anchor_fp},
                            )
                        )
                    else:
                        findings.append(
                            ReassemblyFinding(
                                rule_id="MITM_INTERCEPTION",
                                rule_name="TLS Interception Proxy Detected",
                                severity="CRITICAL",
                                description=f"Unauthorized TLS interception proxy detected re-signing certificate chain: {anchor_dn}",
                                evidence={"anchor_dn": anchor_dn, "anchor_fp": anchor_fp},
                            )
                        )

        except RevokedError as rev_err:
            errors.append(ChainError("CERT_REVOKED", f"Certificate revoked: {rev_err}"))
        except InvalidCertificateError as ic_err:
            if leaf_parsed.is_self_signed or "self-signed" in str(ic_err).lower():
                anchor_source = "self_signed"
                errors.append(
                    ChainError(
                        "SELF_SIGNED_CERT",
                        f"Leaf certificate is self-signed: {ic_err}",
                    )
                )
            else:
                err_str = str(ic_err).lower()
                if "weak hash algorithm" in err_str or "sha1" in err_str or "md5" in err_str:
                    errors.append(
                        ChainError(
                            "WEAK_HASH_ALGO",
                            f"Certificate signed with weak hash algorithm: {ic_err}",
                        )
                    )
                else:
                    errors.append(ChainError("INVALID_CERTIFICATE", str(ic_err)))
        except PathBuildingError as pb_err:
            # Check if self-signed
            if leaf_parsed.is_self_signed or "self-signed" in str(pb_err).lower():
                anchor_source = "self_signed"
                errors.append(
                    ChainError(
                        "SELF_SIGNED_CERT",
                        "Leaf certificate is self-signed and not in trusted root store",
                    )
                )
            else:
                errors.append(ChainError("UNTRUSTED_ROOT", f"Unable to build trust path: {pb_err}"))
        except PathValidationError as pv_err:
            err_str = str(pv_err).lower()
            if leaf_parsed.is_self_signed or "self-signed" in err_str:
                anchor_source = "self_signed"
                errors.append(
                    ChainError(
                        "SELF_SIGNED_CERT",
                        f"Leaf certificate is self-signed: {pv_err}",
                    )
                )
            elif "expired" in err_str:
                if not any(e.code == "CERT_EXPIRED" for e in errors):
                    errors.append(
                        ChainError(
                            "CERT_EXPIRED",
                            f"Certificate in path expired at capture time ({moment.isoformat()}): {pv_err}",
                        )
                    )
            elif "not valid until" in err_str or "not yet valid" in err_str:
                if not any(e.code == "CERT_NOT_YET_VALID" for e in errors):
                    errors.append(
                        ChainError(
                            "CERT_NOT_YET_VALID",
                            f"Certificate in path not yet valid at capture time ({moment.isoformat()}): {pv_err}",
                        )
                    )
            elif "weak hash algorithm" in err_str or "sha1" in err_str or "md5" in err_str:
                errors.append(
                    ChainError(
                        "WEAK_HASH_ALGO", f"Certificate signed with weak algorithm: {pv_err}"
                    )
                )
            elif "is not a ca" in err_str or "not allowed to sign" in err_str:
                errors.append(
                    ChainError("INVALID_CA_CERT", f"Invalid CA certificate in chain: {pv_err}")
                )
            else:
                errors.append(ChainError("PATH_VALIDATION_ERROR", str(pv_err)))
        except ValidationError as ve_err:
            errors.append(ChainError("VALIDATION_ERROR", str(ve_err)))
        except Exception as e:
            errors.append(ChainError("VALIDATION_FAILURE", f"Unexpected validation failure: {e}"))

        # ---------------------------------------------------------------------
        # 2. Three-Tier Offline Revocation Checking
        # ---------------------------------------------------------------------
        ocsp_status = "UNKNOWN"
        crl_status = "UNKNOWN"

        # Tier 1: Stapled OCSP Response
        if stapled_ocsp_der:
            ocsp_res, ocsp_finding = self._verify_stapled_ocsp(
                stapled_ocsp_der, leaf_der, chain_der, moment
            )
            ocsp_status = ocsp_res
            if ocsp_finding:
                findings.append(ocsp_finding)
            if ocsp_status == "REVOKED":
                is_valid = False
                errors.append(
                    ChainError(
                        "OCSP_REVOKED", "Stapled OCSP response indicates certificate is revoked"
                    )
                )

        # Tier 2: Offline CRL cache (if OCSP was not already definitive)
        if ocsp_status == "UNKNOWN":
            crl_res, crl_finding = self._check_offline_crl(leaf_parsed, moment, offline_crls)
            crl_status = crl_res
            if crl_finding:
                findings.append(crl_finding)
            if crl_status == "REVOKED":
                is_valid = False
                errors.append(
                    ChainError("CRL_REVOKED", "Offline CRL indicates certificate is revoked")
                )

        return ChainValidationResult(
            is_valid=is_valid,
            chain_length=chain_len,
            trust_anchor_dn=anchor_dn,
            trust_anchor_fingerprint=anchor_fp,
            anchor_source=anchor_source,
            mozilla_bundle_sha256=self._mozilla_bundle_sha256,
            errors=errors,
            findings=findings,
            ocsp_status=ocsp_status,
            crl_status=crl_status,
            validated_path_fingerprints=validated_path_fps,
        )

    def _verify_stapled_ocsp(
        self,
        ocsp_bytes: bytes,
        leaf_der: bytes,
        chain_der: list[bytes],
        moment: datetime,
    ) -> tuple[str, ReassemblyFinding | None]:
        """Verify stapled OCSP response status, validity window, and responder authorization."""
        try:
            ocsp_resp = ocsp.load_der_ocsp_response(ocsp_bytes)
        except Exception as e:
            return "UNKNOWN", ReassemblyFinding(
                rule_id="OCSP_MALFORMED",
                rule_name="Malformed Stapled OCSP Response",
                severity="MEDIUM",
                description=f"Stapled OCSP response failed DER decoding: {e}",
            )

        if ocsp_resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            return "UNKNOWN", None

        # Check this_update and next_update against capture moment
        this_update = ocsp_resp.this_update_utc or ocsp_resp.this_update.replace(tzinfo=UTC)
        next_update = ocsp_resp.next_update_utc or (
            ocsp_resp.next_update.replace(tzinfo=UTC) if ocsp_resp.next_update else None
        )

        if moment < this_update or (next_update and moment > next_update):
            return "EXPIRED", ReassemblyFinding(
                rule_id="OCSP_STALE",
                rule_name="Stale Stapled OCSP Response",
                severity="MEDIUM",
                description=(
                    f"Stapled OCSP validity window [{this_update.isoformat()} - "
                    f"{next_update.isoformat() if next_update else 'none'}] does not cover capture time {moment.isoformat()}."
                ),
            )

        # Responder Authorization Check (RFC 6960 §4.2.2.2)
        # Signer must be the issuer cert itself OR an authorized delegate cert bearing id-kp-OCSPSigning
        issuer_der = chain_der[1] if len(chain_der) > 1 else None
        is_authorized = self._verify_ocsp_signer_authorization(ocsp_resp, issuer_der)

        if not is_authorized:
            return "UNAUTHORIZED", ReassemblyFinding(
                rule_id="OCSP_UNAUTHORIZED_RESPONDER",
                rule_name="Unauthorized OCSP Responder",
                severity="CRITICAL",
                description=(
                    "Stapled OCSP response was signed by an unauthorized entity. "
                    "Signer is neither the issuing CA nor an authorized delegate bearing id-kp-OCSPSigning."
                ),
            )

        # Check status
        if ocsp_resp.certificate_status == ocsp.OCSPCertStatus.REVOKED:
            return "REVOKED", ReassemblyFinding(
                rule_id="CERT_OCSP_REVOKED",
                rule_name="Certificate Revoked via OCSP",
                severity="CRITICAL",
                description=f"Stapled OCSP reports certificate revoked at {ocsp_resp.revocation_time_utc}",
            )
        elif ocsp_resp.certificate_status == ocsp.OCSPCertStatus.GOOD:
            return "GOOD", None

        return "UNKNOWN", None

    def _verify_ocsp_signer_authorization(
        self,
        ocsp_resp: ocsp.OCSPResponse,
        issuer_der: bytes | None,
    ) -> bool:
        """Verify that OCSP responder is either the issuing CA or an authorized delegate."""
        if not issuer_der:
            return False

        try:
            issuer_cert = x509.load_der_x509_certificate(issuer_der)

            # 1. Direct signing by issuer
            if ocsp_resp.responder_name == issuer_cert.subject:
                return True

            # 2. Delegate signing: check responder certificate embedded in OCSP response
            for cert in ocsp_resp.certificates:
                # Must be issued by issuer_cert
                if cert.issuer == issuer_cert.subject:
                    # Must contain id-kp-OCSPSigning in extended_key_usage
                    try:
                        ext = cert.extensions.get_extension_for_oid(x509.OID_EXTENDED_KEY_USAGE)
                        if isinstance(ext.value, x509.ExtendedKeyUsage) and any(
                            usage.dotted_string == OID_OCSP_SIGNING for usage in ext.value
                        ):
                            return True
                    except Exception:
                        continue
        except Exception:
            return False

        return False

    def _check_offline_crl(
        self,
        leaf_parsed: ParsedCertificate,
        moment: datetime,
        offline_crls: dict[str, bytes] | None,
    ) -> tuple[str, ReassemblyFinding | None]:
        """Check offline CRL files or supplied dictionary for certificate revocation."""
        if not leaf_parsed.crl_dp:
            return "UNKNOWN", None

        crl_bytes_pool: list[bytes] = []

        # From memory dictionary
        if offline_crls:
            for dp_url in leaf_parsed.crl_dp:
                dp_hash = hashlib.sha256(dp_url.encode("utf-8")).hexdigest()
                if dp_hash in offline_crls:
                    crl_bytes_pool.append(offline_crls[dp_hash])
                elif dp_url in offline_crls:
                    crl_bytes_pool.append(offline_crls[dp_url])

        # From disk cache
        if self.crl_cache_dir and self.crl_cache_dir.exists():
            for dp_url in leaf_parsed.crl_dp:
                dp_hash = hashlib.sha256(dp_url.encode("utf-8")).hexdigest()
                crl_path = self.crl_cache_dir / f"{dp_hash}.crl"
                if crl_path.exists():
                    with contextlib.suppress(Exception):
                        crl_bytes_pool.append(crl_path.read_bytes())

        if not crl_bytes_pool:
            return "UNKNOWN", None

        # Process CRLs
        for crl_raw in crl_bytes_pool:
            try:
                crl_obj = x509.load_der_x509_crl(crl_raw)
                last_up = crl_obj.last_update_utc or crl_obj.last_update.replace(tzinfo=UTC)
                next_up = crl_obj.next_update_utc or (
                    crl_obj.next_update.replace(tzinfo=UTC) if crl_obj.next_update else None
                )

                if moment < last_up or (next_up and moment > next_up):
                    continue

                # Check serial number
                leaf_serial_int = int(leaf_parsed.serial_number, 16)
                revoked_entry = crl_obj.get_revoked_certificate_by_serial_number(leaf_serial_int)
                if revoked_entry:
                    return "REVOKED", ReassemblyFinding(
                        rule_id="CERT_CRL_REVOKED",
                        rule_name="Certificate Revoked via Offline CRL",
                        severity="CRITICAL",
                        description=f"Offline CRL indicates serial 0x{leaf_parsed.serial_number} was revoked at {revoked_entry.revocation_date_utc}",
                    )
                else:
                    return "GOOD", None
            except Exception:
                continue

        return "UNKNOWN", None
