"""Application startup cryptographic verification and environment initialization.

Applied once at import time before FastAPI routers are registered.
Ensures certvalidator, oscrypto, and libcrypto are functionally operational
without any degraded modes or silent fallbacks.
"""

from __future__ import annotations

import logging
import os
import pathlib
import sys

logger = logging.getLogger("pecff.startup")

TARGET_BLOCK = r"""version_match = re.search(r"\b(\d+\.\d+\.\d+[a-z]*)\b", version_string)
if not version_match:
    version_match = re.search(r"(?<=LibreSSL )(\d+\.\d+(\.\d+)?)\b", version_string)
if not version_match:
    raise LibraryNotFoundError("Error detecting the version of libcrypto")
version = version_match.group(1)
version_parts = re.sub(r"(\d+)([a-z]+)", r"\1.\2", version).split(".")
version_info = tuple(int(part) if part.isdigit() else part for part in version_parts)"""


def _patch_oscrypto_module_files() -> None:
    """Ensure both _libcrypto_cffi.py and _libcrypto_ctypes.py have the OpenSSL 3.x fix.

    oscrypto 1.3.0 ships with regex \\b(\\d\\.\\d\\.\\d[a-z]*)\\b which fails to
    match OpenSSL 3.0.10+ (like 3.0.11, 3.0.13, 3.0.14 on Linux/Debian Bookworm/Render).
    This applies the official upstream commit d5f3437 from wbond to both files.
    """
    for mod_name in ("oscrypto._openssl._libcrypto_cffi", "oscrypto._openssl._libcrypto_ctypes"):
        if mod_name in sys.modules:
            continue

        try:
            import importlib.util

            spec = importlib.util.find_spec(mod_name)
            if spec is None or spec.origin is None:
                continue

            src_path = pathlib.Path(spec.origin)
            if not src_path.exists():
                continue

            text = src_path.read_text(encoding="utf-8")
            if r'version_match = re.search(r"\b(\d+\.\d+\.\d+[a-z]*)\b"' in text:
                continue  # already patched

            idx_start = text.find("version_match = re.search")
            if idx_start == -1:
                continue

            idx_end = text.find("version_info = tuple(", idx_start)
            if idx_end == -1:
                continue

            idx_end = text.find("\n", idx_end)
            if idx_end == -1:
                idx_end = len(text)

            new_text = text[:idx_start] + TARGET_BLOCK + text[idx_end:]
            src_path.write_text(new_text, encoding="utf-8")

            # Remove any pyc cache
            for pyc in src_path.parent.glob(f"__pycache__/{src_path.stem}*.pyc"):
                try:
                    pyc.unlink(missing_ok=True)
                except Exception:
                    pass

            logger.info("Applied OpenSSL 3.x compatibility patch to %s", src_path.name)
        except Exception as patch_err:
            logger.debug("Startup patch check on %s: %s", mod_name, patch_err)


def _verify_crypto_subsystem() -> None:
    """Verify that oscrypto and certvalidator can perform real X.509 operations.

    Raises RuntimeError if certificate validation is non-functional.
    Never degrades silently.
    """
    _patch_oscrypto_module_files()

    try:
        import oscrypto
        backend_name = oscrypto.backend()
    except Exception as err:
        raise RuntimeError(f"Fatal: oscrypto failed to initialize backend: {err}") from err

    try:
        import certvalidator
        from certvalidator import CertificateValidator, ValidationContext
    except Exception as err:
        raise RuntimeError(f"Fatal: certvalidator import failed: {err}") from err

    # Perform functional verification using local trust root
    try:
        import certifi
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        with open(certifi.where(), "rb") as f:
            certs = x509.load_pem_x509_certificates(f.read())
        first_der = certs[0].public_bytes(serialization.Encoding.DER)
        ctx = ValidationContext(trust_roots=[first_der])
        val = CertificateValidator(first_der, validation_context=ctx)
        val.validate_usage(set())
    except Exception as err:
        raise RuntimeError(
            f"Fatal: X.509 certificate validation self-test failed with backend '{backend_name}': {err}"
        ) from err

    logger.info("certvalidator import successful")
    logger.info("oscrypto initialization successful (backend: %s)", backend_name)


def apply_all_patches() -> None:
    """Verify and initialize the cryptographic subsystem on app startup."""
    _verify_crypto_subsystem()
