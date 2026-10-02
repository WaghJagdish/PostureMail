"""Application startup patches.

Applied once at import time before FastAPI app is created.
Fixes known compatibility issues with the deployed environment.

Patches applied:
1. oscrypto libcrypto: On OpenSSL 3.x (Debian Bookworm / Render), oscrypto 1.3.0
   fails in two ways:
   a) The version regex only matches single-digit patch versions, not multi-digit like 3.0.11.
   b) get_library('crypto', ...) may fail to find libcrypto.so on Debian Bookworm.
   Fix: (a) patch the regex file in-place before import, (b) pre-configure the libcrypto path
   via oscrypto.use() before certvalidator is first imported.
"""

from __future__ import annotations

import logging
import os
import sys

logger = logging.getLogger("pecff.startup")


def _patch_oscrypto_version_regex() -> None:
    """Monkey-patch the oscrypto version regex BEFORE it runs at module load.

    oscrypto 1.3.0 uses a regex that only matches single-digit patch versions
    (e.g., 3.0.1 matches but 3.0.11 does not). On Debian Bookworm with OpenSSL 3.x,
    this causes LibraryNotFoundError: Error detecting the version of libcrypto.

    We patch the installed .py file in-place and invalidate the .pyc cache
    so the next import loads the fixed version.

    This must be called before any import of certvalidator or oscrypto._openssl.
    """
    try:
        # If already imported, we cannot re-patch (module is cached)
        if "oscrypto._openssl._libcrypto_ctypes" in sys.modules:
            return

        import importlib.util
        import pathlib

        spec = importlib.util.find_spec("oscrypto._openssl._libcrypto_ctypes")
        if spec is None or spec.origin is None:
            return

        src_path = pathlib.Path(spec.origin)
        if not src_path.exists():
            return

        text = src_path.read_text(encoding="utf-8")

        # The old pattern uses literal string with escaped chars matching only \d\.\d\.\d
        OLD_PATTERN = "version_match = re.search('\\\\b(\\\\d\\\\.\\\\d\\\\.\\\\d[a-z]*)\\\\b', version_string)"
        # New pattern matches full multi-digit patch versions like 3.0.11
        NEW_PATTERN = "version_match = re.search(r'\\b(\\d+\\.\\d+\\.\\d+[a-z]*)\\b', version_string)"

        if OLD_PATTERN in text:
            patched = text.replace(OLD_PATTERN, NEW_PATTERN)
            src_path.write_text(patched, encoding="utf-8")
            # Remove cached .pyc to force recompilation
            import glob
            for pyc in glob.glob(str(src_path.parent / "__pycache__" / "_libcrypto_ctypes*.pyc")):
                try:
                    os.unlink(pyc)
                except Exception:
                    pass
            logger.info("oscrypto: patched version regex in %s", src_path)
        else:
            # Check alternate known encodings of the same pattern
            # (the string as stored on disk may differ slightly by Python version)
            if "r'\\b(\\d+" in text or "r\"\\b(\\d+" in text:
                logger.debug("oscrypto: version regex already uses extended pattern — skipping")
            else:
                logger.debug("oscrypto: could not find version regex pattern to patch (version may differ)")
    except Exception as err:
        logger.debug("oscrypto version regex patch encountered error: %s", err)


def _patch_oscrypto_libcrypto() -> None:
    """Ensure oscrypto can find and load libcrypto on the deployed platform.

    Strategy (in order of preference):
    1. If PECFF_LIBCRYPTO_PATH env var is set, use it directly.
    2. Find libcrypto via ctypes.util.find_library (works on macOS/Linux).
    3. Try well-known Debian Bookworm / Ubuntu Jammy paths for OpenSSL 3.x.
    4. Fall through gracefully: log a warning but do not crash startup.
       The certvalidator call sites already catch all exceptions and log them
       as warnings without failing the analysis pipeline.
    """
    # If already loaded, nothing to do
    try:
        import oscrypto
        if oscrypto.backend():
            return  # already configured
    except Exception:
        pass

    lib_path: str | None = None

    # 1. Operator override via environment variable
    env_path = os.environ.get("PECFF_LIBCRYPTO_PATH")
    if env_path and os.path.exists(env_path):
        lib_path = env_path
        logger.info("oscrypto: using PECFF_LIBCRYPTO_PATH=%s", lib_path)

    # 2. ctypes.util.find_library
    if lib_path is None:
        try:
            from ctypes.util import find_library
            found = find_library("crypto")
            if found:
                lib_path = found
                logger.info("oscrypto: find_library('crypto') -> %s", lib_path)
        except Exception:
            pass

    # 3. Well-known Debian Bookworm / Ubuntu Jammy / macOS Homebrew paths
    if lib_path is None:
        candidates = [
            "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
            "/usr/lib/aarch64-linux-gnu/libcrypto.so.3",
            "/usr/lib/libcrypto.so.3",
            "/usr/lib/x86_64-linux-gnu/libcrypto.so",
            "/usr/lib/libcrypto.so",
            "/opt/homebrew/opt/openssl@3/lib/libcrypto.dylib",
            "/usr/local/opt/openssl@3/lib/libcrypto.dylib",
            "/usr/lib/libcrypto.dylib",
        ]
        for candidate in candidates:
            if os.path.exists(candidate):
                lib_path = candidate
                logger.info("oscrypto: resolved libcrypto from candidate path: %s", lib_path)
                break

    if lib_path is None:
        logger.warning(
            "oscrypto: could not locate libcrypto — certvalidator certificate chain "
            "validation will be DEGRADED. Set PECFF_LIBCRYPTO_PATH env var to fix."
        )
        return

    # Apply oscrypto backend configuration before certvalidator is first imported
    try:
        import oscrypto
        oscrypto.use("openssl", {"libcrypto_path": lib_path})
        logger.info("oscrypto: configured openssl backend with libcrypto=%s", lib_path)
    except Exception as err:
        logger.warning(
            "oscrypto: backend configuration failed (%s) — chain validation may be degraded", err
        )


def _import_certvalidator_safely() -> None:
    """Trigger certvalidator import so we fail fast and log rather than crash on first use."""
    try:
        import certvalidator  # noqa: F401
        logger.info("certvalidator: imported successfully")
    except Exception as err:
        logger.warning(
            "certvalidator: import failed (%s) — X.509 chain validation will be DEGRADED. "
            "PCAP analysis will continue but certificate trust path verification is unavailable.",
            err,
        )
        # Do NOT re-raise: chain_validator.py wraps all certvalidator calls in try/except
        # and emits VALIDATION_FAILURE findings gracefully.


def apply_all_patches() -> None:
    """Apply all startup patches. Called once from app.py before create_app()."""
    # Order matters: regex patch → path config → import test
    _patch_oscrypto_version_regex()
    _patch_oscrypto_libcrypto()
    _import_certvalidator_safely()
