"""NIST SP 800-57 security bits approximation and strength calculators.

Implements GNFS (General Number Field Sieve) approximation for RSA integer
factorization complexity, discrete logarithm / elliptic curve security metrics,
and cryptographic hash collision resistance. Results are rounded down and snapped
to the standard NIST SP 800-57 Part 1 Table 2 tiers (80, 112, 128, 192, 256).
"""

from __future__ import annotations

import math
from typing import Final

# NIST SP 800-57 Part 1 Rev 5 Table 2 standard security tiers
NIST_SECURITY_TIERS: Final[tuple[int, ...]] = (80, 112, 128, 192, 256)

LN_2: Final[float] = math.log(2.0)


def snap_to_nist_tier(raw_bits: float) -> int:
    """Snap raw continuous security bits DOWN to standard NIST SP 800-57 tier.

    Values below 80 bits are clamped to 0 (or integer below 80 for legacy audit).
    """
    if raw_bits < 80.0:
        return max(0, int(math.floor(raw_bits)))

    for tier in reversed(NIST_SECURITY_TIERS):
        if raw_bits >= tier:
            return tier

    return 80


def rsa_security_bits(n_bits: int) -> int:
    """Calculate effective security bits for an RSA / Finite Field modulus using GNFS.

    Formula:
        GNFS bits = (1.923 * cbrt(n * ln2) * (ln(n * ln2))**(2/3) - 4.69) / ln2

    Returns standard NIST tier:
        n < 1024   -> < 80
        n = 1024   -> 80
        n = 2048   -> 112
        n = 3072   -> 128
        n = 7680   -> 192
        n >= 15360 -> 256
    """
    if n_bits <= 0:
        return 0

    # For standard well-known key lengths, return authoritative NIST tiers directly
    if n_bits <= 512:
        return 56
    if n_bits < 1024:
        return 64
    if n_bits == 1024:
        return 80
    if n_bits == 2048:
        return 112
    if n_bits == 3072:
        return 128
    if n_bits == 4096:
        return 128  # NIST Table 2 maps 4096 to >=128 tier, <192 tier (requires 7680 for 192)
    if n_bits == 7680:
        return 192
    if n_bits >= 15360:
        return 256

    # GNFS formula approximation for arbitrary/non-standard key lengths
    n_ln2 = float(n_bits) * LN_2
    cbrt_term = math.pow(n_ln2, 1.0 / 3.0)
    ln_term = math.pow(math.log(n_ln2), 2.0 / 3.0)
    raw_bits = (1.923 * cbrt_term * ln_term - 4.69) / LN_2

    return snap_to_nist_tier(raw_bits)


def ecc_security_bits(n_bits: int) -> int:
    """Calculate effective security bits for Elliptic Curve Cryptography.

    ECC strength is approximately n_bits / 2 (Pollard's rho attack complexity).
    Snaps to NIST tiers:
        n = 256 -> 128
        n = 384 -> 192
        n = 521 -> 256
    """
    if n_bits <= 0:
        return 0

    if n_bits < 160:
        return max(0, n_bits // 2)
    if n_bits < 224:
        return 80
    if n_bits < 256:
        return 112
    if n_bits < 384:
        return 128
    if n_bits < 512:
        return 192
    return 256


def hash_security_bits(hash_name: str) -> int:
    """Calculate collision resistance security bits for a cryptographic hash function.

    Based on NIST SP 800-57 Part 1 Table 3:
        MD5    -> 0 (broken)
        SHA-1  -> 80 (legacy/broken for collision)
        SHA-224 / SHA-512/224 -> 112
        SHA-256 / SHA-512/256 / SHA3-256 -> 128
        SHA-384 / SHA3-384 -> 192
        SHA-512 / SHA3-512 -> 256
    """
    normalized = hash_name.upper().replace("-", "").replace("_", "")

    if "MD5" in normalized or "MD2" in normalized or "MD4" in normalized:
        return 0
    if "SHA1" in normalized:
        return 80
    if "SHA224" in normalized or "512224" in normalized:
        return 112
    if "SHA256" in normalized or "512256" in normalized or "SHA3256" in normalized:
        return 128
    if "SHA384" in normalized or "SHA3384" in normalized:
        return 192
    if "SHA512" in normalized or "SHA3512" in normalized:
        return 256

    return 80


def security_tier(bits: int) -> str:
    """Classify security bits into NIST SP 800-57 status tier.

    - Approved (>= 112 bits): Secure for general cryptographic protection.
    - Legacy (80..111 bits): Deprecated, legacy use only.
    - Prohibited (< 80 bits): Inadequate security / unacceptable risk.
    """
    if bits >= 112:
        return "approved"
    if bits >= 80:
        return "legacy"
    return "prohibited"
