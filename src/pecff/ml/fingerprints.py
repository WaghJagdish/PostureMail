"""TLS Fingerprinting Engine: JA3, JA3S, JA4, and JA4S implementations.

Standards & Specifications:
1. Salesforce JA3 / JA3S:
   - Client: f"{version},{ciphers},{extensions},{curves},{point_formats}" -> MD5
   - Server: f"{version},{cipher},{extensions}" -> MD5
   - Note on MD5: MD5 is utilized strictly as a 128-bit non-cryptographic hash digest
     for backward compatibility with established threat intelligence platforms and
     fingerprint databases. It is NOT used as a cryptographic security primitive.
2. FoxIO JA4 / JA4S (2023):
   - GREASE-immune and TLS 1.3 robust fingerprinting standard.
   - JA4: <proto><tls_ver><sni_flag><cipher_count><ext_count><alpn>_<sha256_12(sorted ciphers)>_<sha256_12(sorted exts + sigalgs)>
   - JA4S: <proto><tls_ver><ext_count><alpn>_<cipher_hex4>_<sha256_12(sorted exts)>
"""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass
from typing import Final

from pecff.parse.tls_decoder import ClientHelloInfo, ServerHelloInfo, is_grease

# RFC 8701 GREASE values
GREASE_SET: Final[set[int]] = {
    0x0A0A,
    0x1A1A,
    0x2A2A,
    0x3A3A,
    0x4A4A,
    0x5A5A,
    0x6A6A,
    0x7A7A,
    0x8A8A,
    0x9A9A,
    0xAAAA,
    0xBABA,
    0xCACA,
    0xDADA,
    0xEAEA,
    0xFAFA,
}


def is_grease_val(val: int) -> bool:
    """Check if an integer value matches RFC 8701 GREASE specification."""
    if val in GREASE_SET:
        return True
    return is_grease(val)


def strip_grease(values: list[int]) -> list[int]:
    """Filter out GREASE values while strictly preserving wire order."""
    return [v for v in values if not is_grease_val(v)]


def format_alpn(alpn_protocols: list[str]) -> str:
    """Format 2-character ALPN representation for JA4/JA4S (first + last character of first protocol)."""
    if not alpn_protocols:
        return "00"
    first_proto = alpn_protocols[0].strip()
    if not first_proto:
        return "00"
    if len(first_proto) == 1:
        return f"{first_proto[0]}{first_proto[0]}"
    return f"{first_proto[0]}{first_proto[-1]}"


TLS_VERSION_JA4_MAP: Final[dict[int, str]] = {
    0x0304: "13",
    0x0303: "12",
    0x0302: "11",
    0x0301: "10",
    0x0300: "s3",
    0x0200: "s2",
}


def get_tls_version_str(version_val: int) -> str:
    """Convert TLS protocol version integer to 2-character JA4 representation."""
    return TLS_VERSION_JA4_MAP.get(version_val, "00")


def get_highest_client_version(client_hello: ClientHelloInfo) -> int:
    """Determine highest supported TLS version from supported_versions extension or legacy_version."""
    if client_hello.supported_versions:
        non_grease_vers = strip_grease(client_hello.supported_versions)
        if non_grease_vers:
            return max(non_grease_vers)
    return client_hello.legacy_version


def is_ip_address(host_str: str | None) -> bool:
    """Check if a string represents an IPv4 or IPv6 address."""
    if not host_str:
        return False
    try:
        ipaddress.ip_address(host_str.strip("[]"))
        return True
    except ValueError:
        return False


# -----------------------------------------------------------------------------
# JA3 Client Fingerprint
# -----------------------------------------------------------------------------
def calculate_ja3(client_hello: ClientHelloInfo) -> tuple[str, str]:
    """Calculate JA3 client fingerprint string and MD5 hash.

    Format:
        f"{version},{ciphers},{extensions},{curves},{point_formats}"
    where lists are hyphen-delimited decimal integers in exact wire order
    with RFC 8701 GREASE values stripped.
    """
    version_str = str(client_hello.legacy_version)

    # 1. Ciphers (wire order, no GREASE)
    ciphers = strip_grease(client_hello.cipher_suites)
    ciphers_str = "-".join(str(c) for c in ciphers)

    # 2. Extensions (wire order, no GREASE)
    ext_keys = list(client_hello.extensions.keys())
    extensions = strip_grease(ext_keys)
    extensions_str = "-".join(str(e) for e in extensions)

    # 3. Elliptic curves / supported groups (wire order, no GREASE)
    curves = strip_grease(client_hello.supported_groups)
    curves_str = "-".join(str(c) for c in curves)

    # 4. Elliptic curve point formats (wire order)
    point_formats = client_hello.ec_point_formats
    point_formats_str = "-".join(str(p) for p in point_formats)

    ja3_string = f"{version_str},{ciphers_str},{extensions_str},{curves_str},{point_formats_str}"
    # Non-cryptographic MD5 digest used strictly for JA3 corpus lookup compatibility
    ja3_hash = hashlib.md5(ja3_string.encode("ascii")).hexdigest()

    return ja3_string, ja3_hash


# -----------------------------------------------------------------------------
# JA3S Server Fingerprint
# -----------------------------------------------------------------------------
def calculate_ja3s(server_hello: ServerHelloInfo) -> tuple[str, str]:
    """Calculate JA3S server fingerprint string and MD5 hash.

    Format:
        f"{version},{cipher},{extensions}"
    where extensions are hyphen-delimited decimal integers in wire order.
    """
    version_str = str(server_hello.legacy_version)
    cipher_str = str(server_hello.selected_cipher) if server_hello.selected_cipher else ""

    ext_keys = list(server_hello.extensions.keys())
    extensions = strip_grease(ext_keys)
    extensions_str = "-".join(str(e) for e in extensions)

    ja3s_string = f"{version_str},{cipher_str},{extensions_str}"
    # Non-cryptographic MD5 digest used strictly for JA3S corpus lookup compatibility
    ja3s_hash = hashlib.md5(ja3s_string.encode("ascii")).hexdigest()

    return ja3s_string, ja3s_hash


# -----------------------------------------------------------------------------
# JA4 Client Fingerprint (FoxIO)
# -----------------------------------------------------------------------------
def calculate_ja4(client_hello: ClientHelloInfo, protocol_type: str = "t") -> str:
    """Calculate FoxIO JA4 client fingerprint.

    Format:
        JA4 = f"{ja4_a}_{ja4_b}_{ja4_c}"
        ja4_a = <proto><tls_ver><sni_flag><cipher_count><ext_count><alpn>
        ja4_b = 12-char SHA256 of sorted hex ciphers
        ja4_c = 12-char SHA256 of sorted hex exts + signature algorithms
    """
    # 1. JA4_a
    proto = protocol_type.lower()[0] if protocol_type else "t"
    highest_ver = get_highest_client_version(client_hello)
    tls_ver = get_tls_version_str(highest_ver)

    # SNI indicator: 'd' if domain SNI present, 'i' if IP or no SNI
    if client_hello.server_name and not is_ip_address(client_hello.server_name):
        sni_flag = "d"
    else:
        sni_flag = "i"

    non_grease_ciphers = strip_grease(client_hello.cipher_suites)
    cipher_cnt = min(99, len(non_grease_ciphers))
    cipher_cnt_str = f"{cipher_cnt:02d}"

    non_grease_exts = strip_grease(list(client_hello.extensions.keys()))
    ext_cnt = min(99, len(non_grease_exts))
    ext_cnt_str = f"{ext_cnt:02d}"

    alpn_str = format_alpn(client_hello.alpn_protocols)
    ja4_a = f"{proto}{tls_ver}{sni_flag}{cipher_cnt_str}{ext_cnt_str}{alpn_str}"

    # 2. JA4_b (12-char SHA256 of sorted 4-digit hex ciphers)
    if non_grease_ciphers:
        sorted_ciphers_hex = ",".join(f"{c:04x}" for c in sorted(non_grease_ciphers))
        ja4_b = hashlib.sha256(sorted_ciphers_hex.encode("ascii")).hexdigest()[:12]
    else:
        ja4_b = "000000000000"

    # 3. JA4_c (12-char SHA256 of sorted 4-digit hex exts + signature algorithms)
    if non_grease_exts:
        sorted_exts_hex = ",".join(f"{e:04x}" for e in sorted(non_grease_exts))
        # Check for signature algorithms extension (0x000d = 13)
        if client_hello.signature_algorithms:
            sig_algs = strip_grease(client_hello.signature_algorithms)
            sig_algs_hex = ",".join(f"{s:04x}" for s in sig_algs)
            raw_c = f"{sorted_exts_hex}_{sig_algs_hex}"
        else:
            raw_c = sorted_exts_hex
        ja4_c = hashlib.sha256(raw_c.encode("ascii")).hexdigest()[:12]
    else:
        ja4_c = "000000000000"

    return f"{ja4_a}_{ja4_b}_{ja4_c}"


# -----------------------------------------------------------------------------
# JA4S Server Fingerprint (FoxIO)
# -----------------------------------------------------------------------------
def calculate_ja4s(server_hello: ServerHelloInfo, protocol_type: str = "t") -> str:
    """Calculate FoxIO JA4S server fingerprint.

    Format:
        JA4S = f"{ja4s_a}_{ja4s_b}_{ja4s_c}"
        ja4s_a = <proto><tls_ver><ext_count><alpn>
        ja4s_b = 4-digit hex selected cipher
        ja4s_c = 12-char SHA256 of sorted hex exts
    """
    proto = protocol_type.lower()[0] if protocol_type else "t"
    tls_ver = get_tls_version_str(server_hello.selected_version)

    non_grease_exts = strip_grease(list(server_hello.extensions.keys()))
    ext_cnt = min(99, len(non_grease_exts))
    ext_cnt_str = f"{ext_cnt:02d}"

    alpn_str = format_alpn([server_hello.selected_alpn] if server_hello.selected_alpn else [])
    ja4s_a = f"{proto}{tls_ver}{ext_cnt_str}{alpn_str}"

    # JA4S_b: 4-digit hex of selected cipher
    ja4s_b = f"{server_hello.selected_cipher:04x}" if server_hello.selected_cipher else "0000"

    # JA4S_c: 12-char SHA256 of sorted extensions
    if non_grease_exts:
        sorted_exts_hex = ",".join(f"{e:04x}" for e in sorted(non_grease_exts))
        ja4s_c = hashlib.sha256(sorted_exts_hex.encode("ascii")).hexdigest()[:12]
    else:
        ja4s_c = "000000000000"

    return f"{ja4s_a}_{ja4s_b}_{ja4s_c}"


@dataclass(frozen=True, slots=True)
class SessionFingerprints:
    """Consolidated cryptographic and behavioral TLS fingerprints for a session."""

    ja3_string: str
    ja3: str
    ja3s_string: str
    ja3s: str
    ja4: str
    ja4s: str

    def to_document(self) -> str:
        """Construct space-joined fingerprint document for HashingVectorizer."""
        tokens: list[str] = []
        if self.ja3:
            tokens.append(f"ja3_{self.ja3}")
        if self.ja3s:
            tokens.append(f"ja3s_{self.ja3s}")
        if self.ja4:
            tokens.append(f"ja4_{self.ja4}")
        if self.ja4s:
            tokens.append(f"ja4s_{self.ja4s}")
        return " ".join(tokens) if tokens else "ja3_none ja4_none"
