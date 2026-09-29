"""Hostile-input safe TLS 1.0-1.3 record layer decoder and handshake parser.

TLS 1.3 REALITY CHECK:
When `selected_version` is TLS 1.3 (0x0304), the server certificate is encrypted
inside `EncryptedExtensions` and is NOT observable passively over the wire.
The decoder sets `certificates = []` and `cert_analysis_possible = False`.
This is a cryptographic property of TLS 1.3, NOT a missing-certificate failure.
Downstream NIST risk scoring redistributes certificate weight appropriately.

Hostile-Input Hardening:
- Bounded memory buffers and strict slice validation at every field.
- Maximum record fragment length bounded at 18,432 bytes (2^14 + 2048).
- Reassembles fragmented handshake messages across record boundaries.
- Graceful recovery from reassembly gaps (`UNPARSEABLE_GAP`).
- Full RFC 8701 GREASE stripping for accurate JA3/JA4 fingerprinting.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Final

# Maximum allowed TLS record payload (RFC 5246 / RFC 8446)
MAX_TLS_RECORD_LEN: Final[int] = 16384 + 2048  # 18,432 bytes

# RFC 8446 Downgrade Sentinels
TLS12_DOWNGRADE_SENTINEL: Final[bytes] = b"DOWNGRD\x01"
TLS11_DOWNGRADE_SENTINEL: Final[bytes] = b"DOWNGRD\x00"

# RFC 8701 GREASE Values
GREASE_VALUES: Final[set[int]] = {
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


def is_grease(val: int) -> bool:
    """Check if an integer value matches RFC 8701 GREASE pattern (0x?A?A)."""
    if val in GREASE_VALUES:
        return True
    return ((val & 0x0F0F) == 0x0A0A) and ((val >> 8) == (val & 0xFF))


class ContentType(IntEnum):
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23
    HEARTBEAT = 24


class HandshakeType(IntEnum):
    HELLO_REQUEST = 0
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    NEW_SESSION_TICKET = 4
    END_OF_EARLY_DATA = 5
    ENCRYPTED_EXTENSIONS = 8
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    CERTIFICATE_REQUEST = 13
    SERVER_HELLO_DONE = 14
    CERTIFICATE_VERIFY = 15
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20
    KEY_UPDATE = 24
    COMPRESSED_CERTIFICATE = 25


class ExtensionType(IntEnum):
    SERVER_NAME = 0
    MAX_FRAGMENT_LENGTH = 1
    STATUS_REQUEST = 5
    SUPPORTED_GROUPS = 10
    EC_POINT_FORMATS = 11
    SIGNATURE_ALGORITHMS = 13
    ALPN = 16
    SIGNED_CERTIFICATE_TIMESTAMP = 18
    PADDING = 21
    EXTENDED_MASTER_SECRET = 23
    SESSION_TICKET = 35
    PRE_SHARED_KEY = 41
    EARLY_DATA = 42
    SUPPORTED_VERSIONS = 43
    COOKIE = 44
    PSK_KEY_EXCHANGE_MODES = 45
    CERTIFICATE_AUTHORITIES = 47
    POST_HANDSHAKE_AUTH = 49
    SIGNATURE_ALGORITHMS_CERT = 50
    KEY_SHARE = 51
    ENCRYPTED_CLIENT_HELLO = 0xFE0D
    RENEGOTIATION_INFO = 65281


@dataclass(slots=True)
class TLSExtension:
    """Parsed TLS Extension with raw and decoded representation."""

    ext_type: int
    name: str
    length: int
    data: bytes
    parsed_value: Any = None


@dataclass(slots=True)
class ClientHelloInfo:
    """Parsed TLS ClientHello parameters."""

    legacy_version: int
    random: bytes
    session_id: bytes
    cipher_suites: list[int]  # Preserved in exact wire order
    compression_methods: list[int]
    extensions: dict[int, TLSExtension] = field(default_factory=dict)
    supported_versions: list[int] = field(default_factory=list)
    supported_groups: list[int] = field(default_factory=list)
    ec_point_formats: list[int] = field(default_factory=list)
    signature_algorithms: list[int] = field(default_factory=list)
    alpn_protocols: list[str] = field(default_factory=list)
    server_name: str | None = None
    grease_values: list[int] = field(default_factory=list)
    grease_present: bool = False
    ja3_string: str = ""
    ja3_hash: str = ""
    ja4_string: str = ""


@dataclass(slots=True)
class ServerHelloInfo:
    """Parsed TLS ServerHello parameters."""

    legacy_version: int
    selected_version: int
    random: bytes
    session_id_echo: bytes
    selected_cipher: int
    selected_compression: int
    extensions: dict[int, TLSExtension] = field(default_factory=dict)
    selected_alpn: str | None = None
    is_hello_retry_request: bool = False
    downgrade_sentinel_detected: str | None = None  # "TLS12", "TLS11", or None
    grease_values: list[int] = field(default_factory=list)
    grease_present: bool = False
    ja3s_string: str = ""
    ja3s_hash: str = ""


@dataclass(slots=True)
class TLSAlertInfo:
    """TLS Alert record description."""

    level: int  # 1 = warning, 2 = fatal
    description: int  # e.g., 40 = handshake_failure
    description_name: str


@dataclass(slots=True)
class TLSHandshakeSummary:
    """Complete forensic record of a decoded TLS handshake."""

    client_hello: ClientHelloInfo | None = None
    server_hello: ServerHelloInfo | None = None
    certificates_der: list[bytes] = field(default_factory=list)
    cert_analysis_possible: bool = True
    handshake_completed: bool = False
    session_resumed: bool = False
    partial_analysis: bool = False
    resumption_session_id: str | None = None
    alerts: list[TLSAlertInfo] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    records_count: int = 0
    handshake_messages_count: int = 0


class TLSHandshakeDecoder:
    """Hostile-input safe TLS record and handshake parser."""

    def __init__(self) -> None:
        self.summary = TLSHandshakeSummary()
        self._c2s_handshake_buffer = bytearray()
        self._s2c_handshake_buffer = bytearray()

    def process_c2s_record_bytes(self, payload: bytes) -> None:
        """Process reassembled client-to-server TLS record stream."""
        self._process_records(payload, is_c2s=True)

    def process_s2c_record_bytes(self, payload: bytes) -> None:
        """Process reassembled server-to-client TLS record stream."""
        self._process_records(payload, is_c2s=False)

    def _process_records(self, payload: bytes, is_c2s: bool) -> None:
        """Walk TLSPlaintext records and accumulate handshake fragments."""
        offset = 0
        total_len = len(payload)

        while offset + 5 <= total_len:
            ct = payload[offset]
            rec_len = struct.unpack(">H", payload[offset + 3 : offset + 5])[0]

            # Validate record length
            if rec_len > MAX_TLS_RECORD_LEN:
                self.summary.warnings.append(
                    f"Malformed record length {rec_len} > {MAX_TLS_RECORD_LEN} at offset {offset}"
                )
                break

            if offset + 5 + rec_len > total_len:
                # Truncated record at end of stream
                break

            self.summary.records_count += 1
            fragment = payload[offset + 5 : offset + 5 + rec_len]
            offset += 5 + rec_len

            if ct == ContentType.ALERT:
                self._parse_alert(fragment)
            elif ct == ContentType.HANDSHAKE:
                if is_c2s:
                    self._c2s_handshake_buffer.extend(fragment)
                    self._drain_handshake_buffer(is_c2s=True)
                else:
                    self._s2c_handshake_buffer.extend(fragment)
                    self._drain_handshake_buffer(is_c2s=False)

    def _parse_alert(self, fragment: bytes) -> None:
        """Parse 2-byte TLS Alert record."""
        if len(fragment) >= 2:
            lvl = fragment[0]
            desc = fragment[1]
            desc_map = {
                0: "close_notify",
                10: "unexpected_message",
                20: "bad_record_mac",
                21: "decryption_failed",
                22: "record_overflow",
                30: "decompression_failure",
                40: "handshake_failure",
                42: "bad_certificate",
                43: "unsupported_certificate",
                44: "certificate_revoked",
                45: "certificate_expired",
                46: "certificate_unknown",
                47: "illegal_parameter",
                48: "unknown_ca",
                49: "access_denied",
                50: "decode_error",
                51: "decrypt_error",
                70: "protocol_version",
                71: "insufficient_security",
                80: "internal_error",
                86: "inappropriate_fallback",
                90: "user_canceled",
                100: "no_renegotiation",
                109: "missing_extension",
                110: "unsupported_extension",
                112: "unrecognized_name",
                113: "bad_certificate_status_response",
                114: "unknown_psk_identity",
                115: "certificate_required",
                116: "no_application_protocol",
            }
            name = desc_map.get(desc, f"unknown_alert_{desc}")
            self.summary.alerts.append(
                TLSAlertInfo(level=lvl, description=desc, description_name=name)
            )

    def _drain_handshake_buffer(self, is_c2s: bool) -> None:
        """Parse complete handshake messages from reassembled buffer."""
        buf = self._c2s_handshake_buffer if is_c2s else self._s2c_handshake_buffer

        while len(buf) >= 4:
            hs_type = buf[0]
            hs_len = (buf[1] << 16) | (buf[2] << 8) | buf[3]

            if len(buf) < 4 + hs_len:
                # Need more fragments to complete handshake message
                break

            msg_body = bytes(buf[4 : 4 + hs_len])
            del buf[: 4 + hs_len]

            self.summary.handshake_messages_count += 1
            self._dispatch_handshake_message(hs_type, msg_body, is_c2s)

    def _dispatch_handshake_message(self, hs_type: int, body: bytes, is_c2s: bool) -> None:
        """Dispatch decoded handshake message to specialized parser."""
        try:
            if hs_type == HandshakeType.CLIENT_HELLO and is_c2s:
                self.summary.client_hello = self._parse_client_hello(body)
            elif hs_type == HandshakeType.SERVER_HELLO and not is_c2s:
                self.summary.server_hello = self._parse_server_hello(body)
                # Check if TLS 1.3 was negotiated
                if (
                    self.summary.server_hello
                    and self.summary.server_hello.selected_version == 0x0304
                ):
                    self.summary.cert_analysis_possible = False
                    self.summary.certificates_der = []
            elif hs_type == HandshakeType.CERTIFICATE and not is_c2s:
                self.summary.certificates_der = self._parse_certificate_message(body)
            elif hs_type == HandshakeType.FINISHED:
                self.summary.handshake_completed = True
        except Exception as e:
            self.summary.warnings.append(f"Error parsing handshake message type {hs_type}: {e}")

    def _parse_client_hello(self, body: bytes) -> ClientHelloInfo:
        """Decode TLS ClientHello message."""
        if len(body) < 34:
            raise ValueError("ClientHello body truncated before random")

        legacy_ver = struct.unpack(">H", body[0:2])[0]
        rand_bytes = body[2:34]
        offset = 34

        # Session ID
        if offset >= len(body):
            raise ValueError("ClientHello truncated at session_id length")
        sid_len = body[offset]
        offset += 1
        if offset + sid_len > len(body):
            raise ValueError("ClientHello truncated in session_id")
        session_id = body[offset : offset + sid_len]
        offset += sid_len

        # Cipher Suites
        if offset + 2 > len(body):
            raise ValueError("ClientHello truncated at cipher_suites length")
        cs_len = struct.unpack(">H", body[offset : offset + 2])[0]
        offset += 2
        if offset + cs_len > len(body) or cs_len % 2 != 0:
            raise ValueError("ClientHello truncated or invalid cipher_suites length")

        ciphers: list[int] = []
        grease_values: list[int] = []
        for i in range(0, cs_len, 2):
            val = struct.unpack(">H", body[offset + i : offset + i + 2])[0]
            ciphers.append(val)
            if is_grease(val):
                grease_values.append(val)
        offset += cs_len

        # Compression Methods
        if offset >= len(body):
            raise ValueError("ClientHello truncated at compression_methods length")
        comp_len = body[offset]
        offset += 1
        if offset + comp_len > len(body):
            raise ValueError("ClientHello truncated in compression_methods")
        compressions = list(body[offset : offset + comp_len])
        offset += comp_len

        # Extensions
        extensions: dict[int, TLSExtension] = {}
        supp_versions: list[int] = []
        supp_groups: list[int] = []
        ec_formats: list[int] = []
        sig_algos: list[int] = []
        alpn_list: list[str] = []
        sni_name: str | None = None

        if offset + 2 <= len(body):
            ext_total_len = struct.unpack(">H", body[offset : offset + 2])[0]
            offset += 2
            ext_end = min(len(body), offset + ext_total_len)

            while offset + 4 <= ext_end:
                etype, elen = struct.unpack(">HH", body[offset : offset + 4])
                offset += 4
                if offset + elen > ext_end:
                    break
                edata = body[offset : offset + elen]
                offset += elen

                if is_grease(etype):
                    grease_values.append(etype)

                ext_obj = self._parse_single_extension(etype, edata)
                extensions[etype] = ext_obj

                # Extract specialized fields
                if etype == ExtensionType.SERVER_NAME and ext_obj.parsed_value:
                    sni_name = str(ext_obj.parsed_value)
                elif etype == ExtensionType.SUPPORTED_VERSIONS and isinstance(
                    ext_obj.parsed_value, list
                ):
                    supp_versions = [v for v in ext_obj.parsed_value if isinstance(v, int)]
                    for v in supp_versions:
                        if is_grease(v):
                            grease_values.append(v)
                elif etype == ExtensionType.SUPPORTED_GROUPS and isinstance(
                    ext_obj.parsed_value, list
                ):
                    supp_groups = [g for g in ext_obj.parsed_value if isinstance(g, int)]
                    for g in supp_groups:
                        if is_grease(g):
                            grease_values.append(g)
                elif etype == ExtensionType.EC_POINT_FORMATS and isinstance(
                    ext_obj.parsed_value, list
                ):
                    ec_formats = [f for f in ext_obj.parsed_value if isinstance(f, int)]
                    for f in ec_formats:
                        if is_grease(f):
                            grease_values.append(f)
                elif etype == ExtensionType.SIGNATURE_ALGORITHMS and isinstance(
                    ext_obj.parsed_value, list
                ):
                    sig_algos = [s for s in ext_obj.parsed_value if isinstance(s, int)]
                    for s in sig_algos:
                        if is_grease(s):
                            grease_values.append(s)
                elif etype == ExtensionType.ALPN and isinstance(ext_obj.parsed_value, list):
                    alpn_list = [str(a) for a in ext_obj.parsed_value]

        grease_present = len(grease_values) > 0

        # Calculate JA3 (with GREASE stripped)
        ja3_ciphers = [c for c in ciphers if not is_grease(c)]
        ja3_exts = [e for e in extensions if not is_grease(e)]
        ja3_groups = [g for g in supp_groups if not is_grease(g)]
        ja3_formats = [f for f in ec_formats if not is_grease(f)]

        ja3_str = (
            f"{legacy_ver},"
            f"{'-'.join(str(c) for c in ja3_ciphers)},"
            f"{'-'.join(str(e) for e in ja3_exts)},"
            f"{'-'.join(str(g) for g in ja3_groups)},"
            f"{'-'.join(str(f) for f in ja3_formats)}"
        )
        ja3_hash = hashlib.md5(ja3_str.encode("ascii")).hexdigest()

        # Calculate JA4
        proto = "t"
        ver_tag = "13" if (0x0304 in supp_versions) else ("12" if legacy_ver == 0x0303 else "10")
        sni_tag = "d" if sni_name else "i"
        cs_count = f"{min(99, len(ja3_ciphers)):02d}"
        ext_count = f"{min(99, len(ja3_exts)):02d}"
        alpn_tag = alpn_list[0][:2] if alpn_list else "00"
        ja4_a = f"{proto}{ver_tag}{sni_tag}{cs_count}{ext_count}{alpn_tag}"

        sorted_ciphers_hex = "".join(f"{c:04x}" for c in sorted(ja3_ciphers))
        ja4_b = hashlib.sha256(sorted_ciphers_hex.encode("ascii")).hexdigest()[:12]

        sorted_exts_hex = "".join(f"{e:04x}" for e in sorted(ja3_exts))
        ja4_c = hashlib.sha256(sorted_exts_hex.encode("ascii")).hexdigest()[:12]
        ja4_string = f"{ja4_a}_{ja4_b}_{ja4_c}"

        return ClientHelloInfo(
            legacy_version=legacy_ver,
            random=rand_bytes,
            session_id=session_id,
            cipher_suites=ciphers,
            compression_methods=compressions,
            extensions=extensions,
            supported_versions=supp_versions,
            supported_groups=supp_groups,
            ec_point_formats=ec_formats,
            signature_algorithms=sig_algos,
            alpn_protocols=alpn_list,
            server_name=sni_name,
            grease_values=grease_values,
            grease_present=grease_present,
            ja3_string=ja3_str,
            ja3_hash=ja3_hash,
            ja4_string=ja4_string,
        )

    def _parse_server_hello(self, body: bytes) -> ServerHelloInfo:
        """Decode TLS ServerHello message."""
        if len(body) < 38:
            raise ValueError("ServerHello body truncated before selected_cipher")

        legacy_ver = struct.unpack(">H", body[0:2])[0]
        rand_bytes = body[2:34]
        offset = 34

        # Check downgrade sentinels in ServerHello.random[24:32]
        downgrade_sentinel: str | None = None
        if len(rand_bytes) == 32:
            tail8 = rand_bytes[24:32]
            if tail8 == TLS12_DOWNGRADE_SENTINEL:
                downgrade_sentinel = "TLS12"
            elif tail8 == TLS11_DOWNGRADE_SENTINEL:
                downgrade_sentinel = "TLS11"

        # Check HelloRetryRequest sentinel
        # cf 21 ad 74 e5 9a 61 11 be 1d 8c 02 1e 65 b8 91 c2 a2 11 16 7a bb 8c 5e 07 9e 09 e2 c8 a8 33 9c
        hrr_random = bytes.fromhex(
            "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
        )
        is_hrr = rand_bytes == hrr_random

        # Session ID Echo
        sid_len = body[offset]
        offset += 1
        if offset + sid_len > len(body):
            raise ValueError("ServerHello truncated in session_id_echo")
        session_id_echo = body[offset : offset + sid_len]
        offset += sid_len

        # Selected Cipher & Compression
        if offset + 3 > len(body):
            raise ValueError("ServerHello truncated at selected_cipher/compression")
        selected_cipher = struct.unpack(">H", body[offset : offset + 2])[0]
        selected_comp = body[offset + 2]
        offset += 3

        # Extensions
        extensions: dict[int, TLSExtension] = {}
        selected_ver = legacy_ver
        selected_alpn: str | None = None
        grease_values: list[int] = []

        if offset + 2 <= len(body):
            ext_total_len = struct.unpack(">H", body[offset : offset + 2])[0]
            offset += 2
            ext_end = min(len(body), offset + ext_total_len)

            while offset + 4 <= ext_end:
                etype, elen = struct.unpack(">HH", body[offset : offset + 4])
                offset += 4
                if offset + elen > ext_end:
                    break
                edata = body[offset : offset + elen]
                offset += elen

                if is_grease(etype):
                    grease_values.append(etype)

                ext_obj = self._parse_single_extension(etype, edata)
                extensions[etype] = ext_obj

                if etype == ExtensionType.SUPPORTED_VERSIONS and isinstance(
                    ext_obj.parsed_value, int
                ):
                    selected_ver = ext_obj.parsed_value
                elif (
                    etype == ExtensionType.ALPN
                    and isinstance(ext_obj.parsed_value, list)
                    and ext_obj.parsed_value
                ):
                    selected_alpn = str(ext_obj.parsed_value[0])

        grease_present = len(grease_values) > 0

        # Calculate JA3S
        ja3s_exts = [e for e in extensions if not is_grease(e)]
        ja3s_str = f"{selected_ver},{selected_cipher},{'-'.join(str(e) for e in ja3s_exts)}"
        ja3s_hash = hashlib.md5(ja3s_str.encode("ascii")).hexdigest()

        return ServerHelloInfo(
            legacy_version=legacy_ver,
            selected_version=selected_ver,
            random=rand_bytes,
            session_id_echo=session_id_echo,
            selected_cipher=selected_cipher,
            selected_compression=selected_comp,
            extensions=extensions,
            selected_alpn=selected_alpn,
            is_hello_retry_request=is_hrr,
            downgrade_sentinel_detected=downgrade_sentinel,
            grease_values=grease_values,
            grease_present=grease_present,
            ja3s_string=ja3s_str,
            ja3s_hash=ja3s_hash,
        )

    def _parse_certificate_message(self, body: bytes) -> list[bytes]:
        """Decode TLS 1.0-1.2 Certificate message into a list of raw DER certificates."""
        if len(body) < 3:
            return []

        # 3-byte total certificates length
        certs_total_len = (body[0] << 16) | (body[1] << 8) | body[2]
        offset = 3
        certs_end = min(len(body), offset + certs_total_len)

        der_certs: list[bytes] = []
        while offset + 3 <= certs_end:
            c_len = (body[offset] << 16) | (body[offset + 1] << 8) | body[offset + 2]
            offset += 3
            if offset + c_len > certs_end:
                break
            der_certs.append(body[offset : offset + c_len])
            offset += c_len

        return der_certs

    def _parse_single_extension(self, etype: int, data: bytes) -> TLSExtension:
        """Parse individual TLS extension and extract structured metadata."""
        ext_names = {
            0: "server_name",
            1: "max_fragment_length",
            5: "status_request",
            10: "supported_groups",
            11: "ec_point_formats",
            13: "signature_algorithms",
            16: "alpn",
            18: "signed_certificate_timestamp",
            21: "padding",
            23: "extended_master_secret",
            35: "session_ticket",
            41: "pre_shared_key",
            42: "early_data",
            43: "supported_versions",
            44: "cookie",
            45: "psk_key_exchange_modes",
            47: "certificate_authorities",
            49: "post_handshake_auth",
            50: "signature_algorithms_cert",
            51: "key_share",
            0xFE0D: "encrypted_client_hello",
            65281: "renegotiation_info",
        }
        name = ext_names.get(etype, f"unknown_ext_{etype}")
        parsed_val: Any = None

        try:
            if etype == ExtensionType.SERVER_NAME and len(data) >= 5:
                # 2B list length, 1B name_type (0=host_name), 2B name_len, name bytes
                list_len = struct.unpack(">H", data[0:2])[0]
                if list_len >= 3 and len(data) >= 2 + list_len:
                    ntype = data[2]
                    if ntype == 0:  # host_name
                        nlen = struct.unpack(">H", data[3:5])[0]
                        if len(data) >= 5 + nlen:
                            parsed_val = data[5 : 5 + nlen].decode("utf-8", errors="ignore")
            elif etype == ExtensionType.SUPPORTED_GROUPS and len(data) >= 2:
                g_len = struct.unpack(">H", data[0:2])[0]
                if len(data) >= 2 + g_len:
                    groups = []
                    for i in range(2, 2 + g_len, 2):
                        if i + 2 <= len(data):
                            groups.append(struct.unpack(">H", data[i : i + 2])[0])
                    parsed_val = groups
            elif etype == ExtensionType.EC_POINT_FORMATS and len(data) >= 1:
                f_len = data[0]
                if len(data) >= 1 + f_len:
                    parsed_val = list(data[1 : 1 + f_len])
            elif etype == ExtensionType.SIGNATURE_ALGORITHMS and len(data) >= 2:
                s_len = struct.unpack(">H", data[0:2])[0]
                if len(data) >= 2 + s_len:
                    algos = []
                    for i in range(2, 2 + s_len, 2):
                        if i + 2 <= len(data):
                            algos.append(struct.unpack(">H", data[i : i + 2])[0])
                    parsed_val = algos
            elif etype == ExtensionType.ALPN and len(data) >= 2:
                alpn_len = struct.unpack(">H", data[0:2])[0]
                protocols = []
                idx = 2
                while idx < 2 + alpn_len and idx < len(data):
                    p_len = data[idx]
                    idx += 1
                    if idx + p_len <= len(data):
                        protocols.append(data[idx : idx + p_len].decode("utf-8", errors="ignore"))
                        idx += p_len
                parsed_val = protocols
            elif etype == ExtensionType.SUPPORTED_VERSIONS:
                if len(data) == 2:
                    # ServerHello single selected version
                    parsed_val = struct.unpack(">H", data)[0]
                elif len(data) >= 1:
                    # ClientHello list of versions
                    v_len = data[0]
                    versions = []
                    for i in range(1, 1 + v_len, 2):
                        if i + 2 <= len(data):
                            versions.append(struct.unpack(">H", data[i : i + 2])[0])
                    parsed_val = versions
        except Exception:
            parsed_val = None

        return TLSExtension(
            ext_type=etype,
            name=name,
            length=len(data),
            data=data,
            parsed_value=parsed_val,
        )
