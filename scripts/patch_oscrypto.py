#!/usr/bin/env python3
"""Patch oscrypto 1.3.0 for OpenSSL 3.x compatibility.

oscrypto 1.3.0 uses a version regex that only matches \d\.\d\.\d
which fails on OpenSSL 3.x where versions are like "3.0.11".
This script patches the installed _libcrypto_ctypes.py in-place.
"""

import pathlib
import re
import sys

# Find the installed oscrypto module
candidates = list(pathlib.Path("/usr/local/lib").rglob("oscrypto/_openssl/_libcrypto_ctypes.py"))
if not candidates:
    # Try site-packages directly
    import sysconfig
    sp = pathlib.Path(sysconfig.get_path("purelib"))
    candidates = list(sp.rglob("oscrypto/_openssl/_libcrypto_ctypes.py"))

if not candidates:
    print("oscrypto/_openssl/_libcrypto_ctypes.py not found — skipping patch", file=sys.stderr)
    sys.exit(0)

target = candidates[0]
print(f"Patching: {target}")

text = target.read_text(encoding="utf-8")

# Old regex that only matches \d\.\d\.\d (3 single digits each)
OLD = r"version_match = re.search('\\b(\\d\\.\\d\\.\\d[a-z]*)\\b', version_string)"
# New regex that matches full patch versions like 3.0.11
NEW = r"version_match = re.search(r'\b(\d+\.\d+\.\d+[a-z]*)\b', version_string)"

if OLD not in text:
    # Check if already patched or different
    if r"version_match = re.search(r'\b(\d+" in text:
        print("Already patched — skipping.")
        sys.exit(0)
    print(f"WARNING: could not find expected regex pattern in {target}")
    print("File may have changed — manual inspection required")
    sys.exit(0)

patched = text.replace(OLD, NEW)
target.write_text(patched, encoding="utf-8")

# Remove any .pyc to force re-compilation
for pyc in target.parent.parent.parent.rglob("*/_libcrypto_ctypes*.pyc"):
    pyc.unlink(missing_ok=True)

print("Patch applied successfully.")
