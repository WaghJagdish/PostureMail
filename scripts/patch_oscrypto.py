#!/usr/bin/env python3
r"""Patch oscrypto 1.3.0 for OpenSSL 3.x compatibility.

oscrypto 1.3.0 ships with an outdated version regex (\b\d\.\d\.\d[a-z]*\b) that
only matches single-digit patch versions. On OpenSSL 3.0.10+ (including 3.0.11,
3.0.13, 3.0.14 on Linux/Debian Bookworm/Render), this causes:
    LibraryNotFoundError: Error detecting the version of libcrypto

This script applies the official fix from Will Bond (wbond/oscrypto upstream author)
commit d5f3437ed24257895ae1edd9e503cfb352e635a8 to both:
    - oscrypto/_openssl/_libcrypto_cffi.py
    - oscrypto/_openssl/_libcrypto_ctypes.py
"""

from __future__ import annotations

import pathlib
import re
import site
import sys
import sysconfig

TARGET_BLOCK = r"""version_match = re.search(r"\b(\d+\.\d+\.\d+[a-z]*)\b", version_string)
if not version_match:
    version_match = re.search(r"(?<=LibreSSL )(\d+\.\d+(\.\d+)?)\b", version_string)
if not version_match:
    raise LibraryNotFoundError("Error detecting the version of libcrypto")
version = version_match.group(1)
version_parts = re.sub(r"(\d+)([a-z]+)", r"\1.\2", version).split(".")
version_info = tuple(int(part) if part.isdigit() else part for part in version_parts)"""


def get_search_paths() -> list[pathlib.Path]:
    """Collect potential site-packages and lib paths."""
    paths: set[pathlib.Path] = set()

    for p in sys.path:
        if p and pathlib.Path(p).is_dir():
            paths.add(pathlib.Path(p))

    try:
        for p in site.getsitepackages():
            if pathlib.Path(p).is_dir():
                paths.add(pathlib.Path(p))
    except Exception:
        pass

    for key in ("purelib", "platlib"):
        try:
            p = sysconfig.get_path(key)
            if p and pathlib.Path(p).is_dir():
                paths.add(pathlib.Path(p))
        except Exception:
            pass

    # Common deployment paths (Render, Docker, Linux, macOS)
    for extra in [
        "/opt/render/project/src/.venv",
        "/usr/local/lib",
        "/usr/lib",
    ]:
        ep = pathlib.Path(extra)
        if ep.is_dir():
            paths.add(ep)

    return list(paths)


def patch_file(target: pathlib.Path) -> bool:
    """Patch a single oscrypto file in-place if needed."""
    if not target.exists():
        return False

    text = target.read_text(encoding="utf-8")

    # Check if already patched
    if r'version_match = re.search(r"\b(\d+\.\d+\.\d+[a-z]*)\b"' in text:
        print(f"Already patched: {target}")
        return True

    idx_start = text.find("version_match = re.search")
    if idx_start == -1:
        print(f"Pattern not found in: {target}")
        return False

    idx_end = text.find("version_info = tuple(", idx_start)
    if idx_end == -1:
        print(f"version_info assignment not found in: {target}")
        return False

    idx_end = text.find("\n", idx_end)
    if idx_end == -1:
        idx_end = len(text)

    new_text = text[:idx_start] + TARGET_BLOCK + text[idx_end:]
    target.write_text(new_text, encoding="utf-8")

    # Invalidate pyc caches
    for pyc in target.parent.glob(f"__pycache__/{target.stem}*.pyc"):
        try:
            pyc.unlink(missing_ok=True)
        except Exception:
            pass

    print(f"Successfully patched: {target}")
    return True


def main() -> None:
    search_paths = get_search_paths()
    patched_count = 0

    target_files = ["_libcrypto_cffi.py", "_libcrypto_ctypes.py"]

    for base in search_paths:
        for fname in target_files:
            for found in base.rglob(f"oscrypto/_openssl/{fname}"):
                if patch_file(found):
                    patched_count += 1

    if patched_count == 0:
        print("Notice: No unpatched oscrypto files found (already up-to-date or not installed).")
    else:
        print(f"Done: {patched_count} oscrypto file(s) verified/patched.")


if __name__ == "__main__":
    main()
