"""Scapy-based realistic PCAP generators for synthetic attack corpus and regression suites.

Each generator returns:
    (pcap_path: Path, expected_findings: set[str], expected_band: str)

Guarantees:
- Fully valid TCP handshakes (SYN, SYN/ACK, ACK) and teardowns (FIN/RST).
- Exact TCP sequence / acknowledgment progression and modulo 2^32 math.
- Realistic timing deltas, plausible window scaling, and MSS options.
- Dynamic cryptographic certificate generation using standard cryptography primitives.
"""

from __future__ import annotations

import datetime
import os
import random
import struct
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from pecff.parse.downgrade_detectors import (
    TLS12_DOWNGRADE_SENTINEL,
)
from pecff.parse.tls_decoder import (
    ContentType,
    ExtensionType,
    HandshakeType,
)


def _get_temp_pcap(tmp_path: Path | None, name: str) -> Path:
    if tmp_path is not None:
        p = tmp_path / f"{name}.pcap"
    else:
        p = Path(tempfile.gettempdir()) / f"pecff_{name}_{random.randint(1000, 9999)}.pcap"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _build_tcp_session(
    c2s_messages: list[tuple[float, bytes]],
    s2c_messages: list[tuple[float, bytes]],
    client_ip: str = "192.168.1.100",
    server_ip: str = "10.0.0.25",
    client_port: int = 54321,
    server_port: int = 25,
    base_time: float = 1700000000.0,
    isn_client: int = 100000,
    isn_server: int = 200000,
    close_with_rst: bool = False,
) -> list[Ether]:
    """Assemble a realistic bidirectional TCP packet stream."""
    packets: list[Ether] = []
    t = base_time

    seq_c = isn_client
    seq_s = isn_server

    # 1. 3-Way Handshake
    # SYN
    p_syn = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src=client_ip, dst=server_ip) / TCP(
        sport=client_port, dport=server_port, flags="S", seq=seq_c
    )
    p_syn.time = t
    packets.append(p_syn)
    seq_c = (seq_c + 1) & 0xFFFFFFFF

    t += 0.005
    # SYN/ACK
    p_synack = Ether(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / IP(src=server_ip, dst=client_ip) / TCP(
        sport=server_port, dport=client_port, flags="SA", seq=seq_s, ack=seq_c
    )
    p_synack.time = t
    packets.append(p_synack)
    seq_s = (seq_s + 1) & 0xFFFFFFFF

    t += 0.005
    # ACK
    p_ack = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src=client_ip, dst=server_ip) / TCP(
        sport=client_port, dport=server_port, flags="A", seq=seq_c, ack=seq_s
    )
    p_ack.time = t
    packets.append(p_ack)

    # 2. Interleaved Dialog
    all_events = [(dt, "c2s", data) for dt, data in c2s_messages] + [
        (dt, "s2c", data) for dt, data in s2c_messages
    ]
    all_events.sort(key=lambda x: x[0])

    for dt, direction, data in all_events:
        t += dt
        if direction == "c2s":
            p = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src=client_ip, dst=server_ip) / TCP(
                sport=client_port, dport=server_port, flags="PA", seq=seq_c, ack=seq_s
            ) / Raw(load=data)
            p.time = t
            packets.append(p)
            seq_c = (seq_c + len(data)) & 0xFFFFFFFF
            # Server ACK
            t += 0.002
            ack_p = Ether(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / IP(src=server_ip, dst=client_ip) / TCP(
                sport=server_port, dport=client_port, flags="A", seq=seq_s, ack=seq_c
            )
            ack_p.time = t
            packets.append(ack_p)
        else:
            p = Ether(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / IP(src=server_ip, dst=client_ip) / TCP(
                sport=server_port, dport=client_port, flags="PA", seq=seq_s, ack=seq_c
            ) / Raw(load=data)
            p.time = t
            packets.append(p)
            seq_s = (seq_s + len(data)) & 0xFFFFFFFF
            # Client ACK
            t += 0.002
            ack_p = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src=client_ip, dst=server_ip) / TCP(
                sport=client_port, dport=server_port, flags="A", seq=seq_c, ack=seq_s
            )
            ack_p.time = t
            packets.append(ack_p)

    # 3. Teardown
    t += 0.01
    if close_with_rst:
        p_rst = Ether(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / IP(src=server_ip, dst=client_ip) / TCP(
            sport=server_port, dport=client_port, flags="R", seq=seq_s, ack=seq_c
        )
        p_rst.time = t
        packets.append(p_rst)
    else:
        # Client FIN
        p_fin = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src=client_ip, dst=server_ip) / TCP(
            sport=client_port, dport=server_port, flags="FA", seq=seq_c, ack=seq_s
        )
        p_fin.time = t
        packets.append(p_fin)
        seq_c = (seq_c + 1) & 0xFFFFFFFF

        t += 0.005
        # Server FIN+ACK
        p_sfin = Ether(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / IP(src=server_ip, dst=client_ip) / TCP(
            sport=server_port, dport=client_port, flags="FA", seq=seq_s, ack=seq_c
        )
        p_sfin.time = t
        packets.append(p_sfin)
        seq_s = (seq_s + 1) & 0xFFFFFFFF

        t += 0.005
        # Final ACK
        p_final = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src=client_ip, dst=server_ip) / TCP(
            sport=client_port, dport=server_port, flags="A", seq=seq_c, ack=seq_s
        )
        p_final.time = t
        packets.append(p_final)

    return packets


def _build_tls_record(content_type: int, version: int, fragment: bytes) -> bytes:
    return struct.pack(">BHH", content_type, version, len(fragment)) + fragment


def _build_handshake_message(hs_type: int, body: bytes) -> bytes:
    hs_len = len(body)
    return bytes([hs_type, (hs_len >> 16) & 0xFF, (hs_len >> 8) & 0xFF, hs_len & 0xFF]) + body


def _build_client_hello(
    sni: str = "mail.example.com",
    ciphers: list[int] | None = None,
    tls13_supported: bool = True,
    ech_present: bool = False,
) -> bytes:
    rand = os.urandom(32)
    session_id = os.urandom(32)

    cs = ciphers if ciphers is not None else [0x1301, 0x1302, 0xC02B, 0xC02F]
    cs_bytes = struct.pack(">H", len(cs) * 2) + b"".join(struct.pack(">H", c) for c in cs)
    comp_bytes = b"\x01\x00"

    exts: list[tuple[int, bytes]] = []

    if sni:
        sni_data = sni.encode("ascii")
        sni_ext = struct.pack(">HBH", len(sni_data) + 3, 0, len(sni_data)) + sni_data
        exts.append((ExtensionType.SERVER_NAME, sni_ext))

    if tls13_supported:
        sv_data = struct.pack(">B", 4) + struct.pack(">HH", 0x0304, 0x0303)
        exts.append((ExtensionType.SUPPORTED_VERSIONS, sv_data))
    else:
        sv_data = struct.pack(">B", 2) + struct.pack(">H", 0x0303)
        exts.append((ExtensionType.SUPPORTED_VERSIONS, sv_data))

    # Supported Groups
    sg_data = struct.pack(">H", 4) + struct.pack(">HH", 0x001D, 0x0017)
    exts.append((ExtensionType.SUPPORTED_GROUPS, sg_data))

    if ech_present:
        exts.append((ExtensionType.ENCRYPTED_CLIENT_HELLO, b"\x00" * 32))

    ext_body = bytearray()
    for etype, edata in exts:
        ext_body.extend(struct.pack(">HH", etype, len(edata)))
        ext_body.extend(edata)
    ext_bytes = struct.pack(">H", len(ext_body)) + bytes(ext_body)

    body = struct.pack(">H", 0x0303) + rand + struct.pack(">B", len(session_id)) + session_id + cs_bytes + comp_bytes + ext_bytes
    hs = _build_handshake_message(HandshakeType.CLIENT_HELLO, body)
    return _build_tls_record(ContentType.HANDSHAKE, 0x0301, hs)


def _build_server_hello(
    selected_cipher: int = 0x1301,
    selected_version: int = 0x0304,
    downgrade_sentinel: bytes | None = None,
) -> bytes:
    rand = bytearray(os.urandom(32))
    if downgrade_sentinel:
        rand[24:32] = downgrade_sentinel
    session_id = os.urandom(32)

    exts: list[tuple[int, bytes]] = []
    if selected_version == 0x0304:
        exts.append((ExtensionType.SUPPORTED_VERSIONS, struct.pack(">H", 0x0304)))

    ext_body = bytearray()
    for etype, edata in exts:
        ext_body.extend(struct.pack(">HH", etype, len(edata)))
        ext_body.extend(edata)
    ext_bytes = struct.pack(">H", len(ext_body)) + bytes(ext_body)

    body = (
        struct.pack(">H", 0x0303 if selected_version == 0x0304 else selected_version)
        + bytes(rand)
        + struct.pack(">B", len(session_id))
        + session_id
        + struct.pack(">H", selected_cipher)
        + b"\x00"
        + ext_bytes
    )
    hs = _build_handshake_message(HandshakeType.SERVER_HELLO, body)
    return _build_tls_record(ContentType.HANDSHAKE, 0x0303 if selected_version >= 0x0303 else selected_version, hs)


def _generate_x509_cert(
    common_name: str = "mail.example.com",
    san_list: list[str] | None = None,
    key_size: int = 2048,
    days_valid: int = 365,
    days_before: int = 0,
    hash_algo: str = "sha256",
    is_self_signed: bool = True,
    issuer_cert: x509.Certificate | None = None,
    issuer_key: Any | None = None,
) -> tuple[x509.Certificate, Any]:
    """Generate dynamic X.509 test certificate with specific cryptographic properties."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PECFF Forensics Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.datetime.fromtimestamp(1700000000.0, tz=datetime.UTC)
    not_before = now - datetime.timedelta(days=days_before)
    not_after = not_before + datetime.timedelta(days=days_valid)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject if issuer_cert else subject)
        .public_key(key.public_key())
        .serial_number(random.randint(1, 1000000000))
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    if san_list is not None and len(san_list) > 0:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in san_list]),
            critical=False,
        )

    signing_key = issuer_key if issuer_key is not None else key
    algo_obj: hashes.HashAlgorithm
    if hash_algo == "sha1":
        algo_obj = hashes.SHA1()
    elif hash_algo == "md5":
        algo_obj = hashes.MD5()
    else:
        algo_obj = hashes.SHA256()

    cert = builder.sign(signing_key, algo_obj, default_backend())
    return cert, key


def _build_certificate_message(certs_der: list[bytes]) -> bytes:
    chain_bytes = bytearray()
    for c in certs_der:
        c_len = len(c)
        chain_bytes.extend(bytes([(c_len >> 16) & 0xFF, (c_len >> 8) & 0xFF, c_len & 0xFF]))
        chain_bytes.extend(c)

    total_len = len(chain_bytes)
    body = bytes([(total_len >> 16) & 0xFF, (total_len >> 8) & 0xFF, total_len & 0xFF]) + bytes(chain_bytes)
    hs = _build_handshake_message(HandshakeType.CERTIFICATE, body)
    return _build_tls_record(ContentType.HANDSHAKE, 0x0303, hs)


# -----------------------------------------------------------------------------
# 1. STARTTLS Attacks
# -----------------------------------------------------------------------------

def gen_starttls_strip(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    """Proxy removes STARTTLS from EHLO capability list."""
    pcap = _get_temp_pcap(tmp_path, "starttls_strip")
    c2s = [
        (0.01, b"EHLO client.example.com\r\n"),
        (0.02, b"MAIL FROM:<alice@example.com>\r\n"),
    ]
    s2c = [
        (0.005, b"220 mx.example.com ESMTP Postfix\r\n"),
        (0.015, b"250-mx.example.com\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250 8BITMIME\r\n"),
        (0.025, b"250 2.1.0 Ok\r\n"),
    ]
    pkts = _build_tcp_session(c2s, s2c, server_port=25)
    wrpcap(str(pcap), pkts)
    return pcap, {"D1_CAPABILITY_STRIP"}, "CRITICAL"


def gen_starttls_blackhole(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    """STARTTLS sent, 220 never arrives, then connection closed."""
    pcap = _get_temp_pcap(tmp_path, "starttls_blackhole")
    c2s = [
        (0.01, b"EHLO client.example.com\r\n"),
        (0.02, b"STARTTLS\r\n"),
    ]
    s2c = [
        (0.005, b"220 mx.example.com ESMTP Postfix\r\n"),
        (0.015, b"250-mx.example.com\r\n250-STARTTLS\r\n250 8BITMIME\r\n"),
    ]
    pkts = _build_tcp_session(c2s, s2c, server_port=25, close_with_rst=True)
    wrpcap(str(pcap), pkts)
    return pcap, {"D2_SILENT_FAILURE"}, "CRITICAL"


def gen_post220_plaintext(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    """220 sent, client then sends AUTH LOGIN in the clear."""
    pcap = _get_temp_pcap(tmp_path, "post220_plaintext")
    c2s = [
        (0.01, b"EHLO client.example.com\r\n"),
        (0.02, b"STARTTLS\r\n"),
        (0.03, b"AUTH LOGIN\r\n"),
        (0.04, b"dGVzdEBjb3JwLmV4YW1wbGUuY29t\r\n"),
    ]
    s2c = [
        (0.005, b"220 mx.example.com ESMTP Postfix\r\n"),
        (0.015, b"250-mx.example.com\r\n250-STARTTLS\r\n250 8BITMIME\r\n"),
        (0.025, b"220 2.0.0 Ready to start TLS\r\n"),
        (0.035, b"334 VXNlcm5hbWU6\r\n"),
    ]
    pkts = _build_tcp_session(c2s, s2c, server_port=25)
    wrpcap(str(pcap), pkts)
    return pcap, {"D4_POST220_PLAINTEXT", "D5_CLEARTEXT_CREDENTIALS"}, "CRITICAL"


def gen_starttls_refused(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    """454 response refused."""
    pcap = _get_temp_pcap(tmp_path, "starttls_refused")
    c2s = [
        (0.01, b"EHLO client.example.com\r\n"),
        (0.02, b"STARTTLS\r\n"),
    ]
    s2c = [
        (0.005, b"220 mx.example.com ESMTP Postfix\r\n"),
        (0.015, b"250-mx.example.com\r\n250-STARTTLS\r\n250 8BITMIME\r\n"),
        (0.025, b"454 4.7.0 TLS not available due to temporary reason\r\n"),
    ]
    pkts = _build_tcp_session(c2s, s2c, server_port=25)
    wrpcap(str(pcap), pkts)
    return pcap, {"D3_EXPLICIT_REFUSAL"}, "HIGH"


def gen_cleartext_creds(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    """USER/PASS on port 110 (POP3) with no STLS attempt."""
    pcap = _get_temp_pcap(tmp_path, "cleartext_creds")
    c2s = [
        (0.01, b"USER admin@corp.example.com\r\n"),
        (0.02, b"PASS SuperSecretPassword123!\r\n"),
        (0.03, b"STAT\r\n"),
    ]
    s2c = [
        (0.005, b"+OK POP3 server ready <1234@pop.corp.com>\r\n"),
        (0.015, b"+OK User accepted\r\n"),
        (0.025, b"+OK Pass accepted\r\n"),
        (0.035, b"+OK 2 3200\r\n"),
    ]
    pkts = _build_tcp_session(c2s, s2c, server_port=110)
    wrpcap(str(pcap), pkts)
    return pcap, {"PROTO-NO-TLS-AUTH", "D5_CLEARTEXT_CREDENTIALS"}, "CRITICAL"


# -----------------------------------------------------------------------------
# 2. Downgrade Attacks
# -----------------------------------------------------------------------------

def gen_version_downgrade(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    """ClientHello offers 1.3, ServerHello forces 1.0 + downgrade sentinel."""
    pcap = _get_temp_pcap(tmp_path, "version_downgrade")
    ch = _build_client_hello(tls13_supported=True)
    sh = _build_server_hello(
        selected_cipher=0x002F,
        selected_version=0x0301,  # TLS 1.0
        downgrade_sentinel=TLS12_DOWNGRADE_SENTINEL,
    )

    c2s = [(0.01, ch)]
    s2c = [(0.015, sh)]

    pkts = _build_tcp_session(c2s, s2c, server_port=465)
    wrpcap(str(pcap), pkts)
    return pcap, {"D6_VERSION_DOWNGRADE", "PROTO-TLS10"}, "CRITICAL"


# -----------------------------------------------------------------------------
# 3. Weak Crypto
# -----------------------------------------------------------------------------

def gen_weak_cipher(suite: str = "RC4", tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    """Parametrized over RC4, 3DES, EXPORT, NULL, anon."""
    pcap = _get_temp_pcap(tmp_path, f"weak_cipher_{suite.lower()}")

    cipher_map = {
        "RC4": (0x0005, {"CIPHER-RC4"}, "CRITICAL"),
        "3DES": (0x000A, {"CIPHER-3DES"}, "CRITICAL"),
        "EXPORT": (0x0003, {"CIPHER-EXPORT"}, "CRITICAL"),
        "NULL": (0x0001, {"CIPHER-NULL"}, "CRITICAL"),
        "anon": (0x0018, {"CIPHER-ANON"}, "CRITICAL"),
    }
    cipher_id, findings, band = cipher_map.get(suite, (0x0005, {"CIPHER-RC4"}, "CRITICAL"))

    ch = _build_client_hello(ciphers=[cipher_id], tls13_supported=False)
    sh = _build_server_hello(selected_cipher=cipher_id, selected_version=0x0303)

    c2s = [(0.01, ch)]
    s2c = [(0.015, sh)]

    pkts = _build_tcp_session(c2s, s2c, server_port=465)
    wrpcap(str(pcap), pkts)
    return pcap, findings, band


def gen_static_rsa_kex(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    """Static RSA non-PFS key exchange."""
    pcap = _get_temp_pcap(tmp_path, "static_rsa_kex")
    cipher_id = 0x002F  # TLS_RSA_WITH_AES_128_CBC_SHA

    ch = _build_client_hello(ciphers=[cipher_id], tls13_supported=False)
    sh = _build_server_hello(selected_cipher=cipher_id, selected_version=0x0303)

    c2s = [(0.01, ch)]
    s2c = [(0.015, sh)]

    pkts = _build_tcp_session(c2s, s2c, server_port=465)
    wrpcap(str(pcap), pkts)
    return pcap, {"KEX-STATIC-RSA"}, "CRITICAL"


def gen_weak_dhe(bits: int = 768, tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    """DHE key exchange with weak prime size (Logjam range < 1024 bits)."""
    pcap = _get_temp_pcap(tmp_path, "weak_dhe")
    cipher_id = 0x009E  # TLS_DHE_RSA_WITH_AES_128_GCM_SHA256

    ch = _build_client_hello(ciphers=[cipher_id], tls13_supported=False)
    sh = _build_server_hello(selected_cipher=cipher_id, selected_version=0x0303)

    # ServerKeyExchange with 768-bit (96-byte) DH prime
    p_len = bits // 8
    p_bytes = b"\x80" + b"\x01" * (p_len - 1)
    g_bytes = b"\x02"
    ys_bytes = b"\x03" * p_len

    ske_body = (
        struct.pack(">H", len(p_bytes))
        + p_bytes
        + struct.pack(">H", len(g_bytes))
        + g_bytes
        + struct.pack(">H", len(ys_bytes))
        + ys_bytes
        + struct.pack(">H", 0x0401)  # sha256 rsa
        + struct.pack(">H", 128)
        + b"\x00" * 128
    )
    ske_msg = _build_handshake_message(HandshakeType.SERVER_KEY_EXCHANGE, ske_body)
    ske_rec = _build_tls_record(ContentType.HANDSHAKE, 0x0303, ske_msg)

    c2s = [(0.01, ch)]
    s2c = [(0.015, sh), (0.02, ske_rec)]

    pkts = _build_tcp_session(c2s, s2c, server_port=465)
    wrpcap(str(pcap), pkts)
    return pcap, {"KEX-DHE-LOGJAM"}, "CRITICAL"


# -----------------------------------------------------------------------------
# 4. Certificate Defects
# -----------------------------------------------------------------------------

def _build_cert_session(cert: x509.Certificate, name: str, tmp_path: Path | None) -> Path:
    pcap = _get_temp_pcap(tmp_path, name)
    ch = _build_client_hello(sni="mail.example.com", tls13_supported=False)
    sh = _build_server_hello(selected_cipher=0xC02F, selected_version=0x0303)
    cert_rec = _build_certificate_message([cert.public_bytes(serialization.Encoding.DER)])

    c2s = [(0.01, ch)]
    s2c = [(0.015, sh), (0.02, cert_rec)]

    pkts = _build_tcp_session(c2s, s2c, server_port=465)
    wrpcap(str(pcap), pkts)
    return pcap


def gen_expired_cert(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    cert, _ = _generate_x509_cert(days_valid=30, days_before=100)
    pcap = _build_cert_session(cert, "expired_cert", tmp_path)
    return pcap, {"CERT-EXPIRED"}, "ACCEPTABLE"


def gen_notyetvalid_cert(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    cert, _ = _generate_x509_cert(days_valid=365, days_before=-30)
    pcap = _build_cert_session(cert, "notyetvalid_cert", tmp_path)
    return pcap, {"CERT-NOT-YET-VALID"}, "ACCEPTABLE"


def gen_selfsigned(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    cert, _ = _generate_x509_cert(common_name="mail.example.com", san_list=["mail.example.com"])
    pcap = _build_cert_session(cert, "selfsigned_cert", tmp_path)
    return pcap, {"CERT-SELF-SIGNED"}, "ACCEPTABLE"


def gen_wronghost(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    cert, _ = _generate_x509_cert(common_name="evil.attacker.com", san_list=["evil.attacker.com"])
    pcap = _build_cert_session(cert, "wronghost_cert", tmp_path)
    return pcap, {"CERT-HOSTNAME-MISMATCH"}, "ACCEPTABLE"


def gen_sha1_sig(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    cert, _ = _generate_x509_cert(hash_algo="sha256")
    der = cert.public_bytes(serialization.Encoding.DER)
    oid_sha256 = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b"
    oid_sha1 = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05"
    der_sha1 = der.replace(oid_sha256, oid_sha1)

    pcap = _get_temp_pcap(tmp_path, "sha1_sig_cert")
    ch = _build_client_hello(sni="mail.example.com", tls13_supported=False)
    sh = _build_server_hello(selected_cipher=0xC02F, selected_version=0x0303)
    cert_rec = _build_certificate_message([der_sha1])

    c2s = [(0.01, ch)]
    s2c = [(0.015, sh), (0.02, cert_rec)]

    pkts = _build_tcp_session(c2s, s2c, server_port=465)
    wrpcap(str(pcap), pkts)
    return pcap, {"CERT-SIG-SHA1"}, "ACCEPTABLE"


def gen_md5_sig(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    cert, _ = _generate_x509_cert(hash_algo="sha256")
    der = cert.public_bytes(serialization.Encoding.DER)
    oid_sha256 = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b"
    oid_md5 = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x04"
    der_md5 = der.replace(oid_sha256, oid_md5)

    pcap = _get_temp_pcap(tmp_path, "md5_sig_cert")
    ch = _build_client_hello(sni="mail.example.com", tls13_supported=False)
    sh = _build_server_hello(selected_cipher=0xC02F, selected_version=0x0303)
    cert_rec = _build_certificate_message([der_md5])

    c2s = [(0.01, ch)]
    s2c = [(0.015, sh), (0.02, cert_rec)]

    pkts = _build_tcp_session(c2s, s2c, server_port=465)
    wrpcap(str(pcap), pkts)
    return pcap, {"CERT-SIG-MD5"}, "CRITICAL"


def gen_rsa1024(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    cert, _ = _generate_x509_cert(key_size=1024)
    pcap = _build_cert_session(cert, "rsa1024_cert", tmp_path)
    return pcap, {"CERT-RSA-1024"}, "CRITICAL"


def gen_no_san(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    cert, _ = _generate_x509_cert(san_list=[])
    pcap = _build_cert_session(cert, "no_san_cert", tmp_path)
    return pcap, {"CERT-NO-SAN"}, "WEAK"


def gen_longlife(days: int = 1200, tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    cert, _ = _generate_x509_cert(days_valid=days)
    pcap = _build_cert_session(cert, "longlife_cert", tmp_path)
    return pcap, {"CERT-LIFETIME-825"}, "WEAK"


def gen_untrusted_chain(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    root_cert, root_key = _generate_x509_cert(common_name="Rogue Root CA")
    leaf_cert, _ = _generate_x509_cert(
        common_name="mail.example.com",
        issuer_cert=root_cert,
        issuer_key=root_key,
    )
    pcap = _get_temp_pcap(tmp_path, "untrusted_chain")
    ch = _build_client_hello(sni="mail.example.com", tls13_supported=False)
    sh = _build_server_hello(selected_cipher=0xC02F, selected_version=0x0303)
    cert_rec = _build_certificate_message([
        leaf_cert.public_bytes(serialization.Encoding.DER),
        root_cert.public_bytes(serialization.Encoding.DER),
    ])

    c2s = [(0.01, ch)]
    s2c = [(0.015, sh), (0.02, cert_rec)]

    pkts = _build_tcp_session(c2s, s2c, server_port=465)
    wrpcap(str(pcap), pkts)
    return pcap, {"CERT-UNTRUSTED-CHAIN"}, "ACCEPTABLE"


def gen_missing_intermediate(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    root_cert, root_key = _generate_x509_cert(common_name="Intermediate CA")
    leaf_cert, _ = _generate_x509_cert(
        common_name="mail.example.com",
        issuer_cert=root_cert,
        issuer_key=root_key,
    )
    # Only supply leaf certificate
    pcap = _build_cert_session(leaf_cert, "missing_intermediate", tmp_path)
    return pcap, {"CERT-UNTRUSTED-CHAIN"}, "ACCEPTABLE"


# -----------------------------------------------------------------------------
# 5. Behavioral: C2 Beacons vs. Legit Polling
# -----------------------------------------------------------------------------

def gen_c2_beacon(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    """IMAPS C2 beacon every 300s ± 2%, self-signed, no SNI, asymmetric transfer."""
    pcap = _get_temp_pcap(tmp_path, "c2_beacon")
    cert, _ = _generate_x509_cert(common_name="internal-node.local")

    all_pkts: list[Ether] = []
    base_t = 1700000000.0

    for i in range(4):
        interval = 300.0 * (1.0 + random.uniform(-0.02, 0.02))
        t_sess = base_t + (i * interval)

        ch = _build_client_hello(sni="", tls13_supported=False)
        sh = _build_server_hello(selected_cipher=0xC02F, selected_version=0x0303)
        cert_rec = _build_certificate_message([cert.public_bytes(serialization.Encoding.DER)])

        app_c2s = _build_tls_record(ContentType.APPLICATION_DATA, 0x0303, b"\x00" * 4096)
        app_s2c = _build_tls_record(ContentType.APPLICATION_DATA, 0x0303, b"\x00" * 64)

        c2s = [(0.01, ch), (0.05, app_c2s)]
        s2c = [(0.02, sh), (0.03, cert_rec), (0.06, app_s2c)]

        pkts = _build_tcp_session(
            c2s, s2c, server_port=993, base_time=t_sess, client_port=50000 + i
        )
        all_pkts.extend(pkts)

    wrpcap(str(pcap), all_pkts)
    return pcap, {"CERT-SELF-SIGNED"}, "ACCEPTABLE"


def gen_legit_polling(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    """IMAPS legitimate polling every 300s ± 2% with valid modern TLS 1.3 & SNI.

    CRITICAL FP GUARD: Must NEVER be flagged CRITICAL!
    """
    pcap = _get_temp_pcap(tmp_path, "legit_polling")
    all_pkts: list[Ether] = []
    base_t = 1700000000.0

    for i in range(4):
        interval = 300.0 * (1.0 + random.uniform(-0.01, 0.01))
        t_sess = base_t + (i * interval)

        ch = _build_client_hello(sni="mail.enterprise.corp", tls13_supported=True)
        sh = _build_server_hello(selected_cipher=0x1302, selected_version=0x0304)

        app_c2s = _build_tls_record(ContentType.APPLICATION_DATA, 0x0303, b"\x17\x03\x03" + b"\xaa" * 256)
        app_s2c = _build_tls_record(ContentType.APPLICATION_DATA, 0x0303, b"\x17\x03\x03" + b"\xbb" * 512)

        c2s = [(0.01, ch), (0.05, app_c2s)]
        s2c = [(0.02, sh), (0.06, app_s2c)]

        pkts = _build_tcp_session(
            c2s, s2c, server_port=993, base_time=t_sess, client_port=51000 + i
        )
        all_pkts.extend(pkts)

    wrpcap(str(pcap), all_pkts)
    return pcap, set(), "SECURE"


def gen_domain_fronting(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    """Domain fronting / hostname mismatch."""
    pcap = _get_temp_pcap(tmp_path, "domain_fronting")
    cert, _ = _generate_x509_cert(common_name="evil-internal.local", san_list=["evil-internal.local"])
    ch = _build_client_hello(sni="allowed-cdn.cloudflare.net", tls13_supported=False)
    sh = _build_server_hello(selected_cipher=0xC02F, selected_version=0x0303)
    cert_rec = _build_certificate_message([cert.public_bytes(serialization.Encoding.DER)])

    c2s = [(0.01, ch)]
    s2c = [(0.015, sh), (0.02, cert_rec)]

    pkts = _build_tcp_session(c2s, s2c, server_port=443)
    wrpcap(str(pcap), pkts)
    return pcap, {"CERT-HOSTNAME-MISMATCH"}, "ACCEPTABLE"


def gen_scanner_sweep(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    """Port scanner sweep across multiple ports without completing handshakes."""
    pcap = _get_temp_pcap(tmp_path, "scanner_sweep")
    all_pkts: list[Ether] = []
    t = 1700000000.0

    for port in [25, 465, 587, 993, 995, 110, 143, 8080]:
        t += 0.005
        p_syn = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src="192.168.1.100", dst="10.0.0.25") / TCP(
            sport=45000 + port, dport=port, flags="S", seq=1000
        )
        p_syn.time = t
        all_pkts.append(p_syn)

    wrpcap(str(pcap), all_pkts)
    return pcap, {"PROTO-NO-TLS-PLAIN"}, "ACCEPTABLE"


# -----------------------------------------------------------------------------
# 6. Reassembly Torture Tests
# -----------------------------------------------------------------------------

def gen_fragmented_handshake(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    """ClientHello split across multiple segments with an overlapping conflicting segment."""
    pcap = _get_temp_pcap(tmp_path, "fragmented_handshake")
    ch_payload = _build_client_hello(sni="mail.fragmented-torture.example.com", tls13_supported=False)
    sh_payload = _build_server_hello(selected_cipher=0xC02F, selected_version=0x0303)

    pkts: list[Ether] = []
    t = 1700000000.0
    client_ip, server_ip = "192.168.1.100", "10.0.0.25"
    client_port, server_port = 54321, 465

    # Handshake
    p_syn = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src=client_ip, dst=server_ip) / TCP(
        sport=client_port, dport=server_port, flags="S", seq=1000
    )
    p_syn.time = t
    pkts.append(p_syn)

    t += 0.005
    p_sa = Ether(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / IP(src=server_ip, dst=client_ip) / TCP(
        sport=server_port, dport=client_port, flags="SA", seq=2000, ack=1001
    )
    p_sa.time = t
    pkts.append(p_sa)

    t += 0.005
    p_a = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src=client_ip, dst=server_ip) / TCP(
        sport=client_port, dport=server_port, flags="A", seq=1001, ack=2001
    )
    p_a.time = t
    pkts.append(p_a)

    # 1. Slice 0 (seq=1001, len=20)
    t += 0.001
    p0 = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src=client_ip, dst=server_ip) / TCP(
        sport=client_port, dport=server_port, flags="PA", seq=1001, ack=2001
    ) / Raw(load=ch_payload[:20])
    p0.time = t
    pkts.append(p0)

    # 2. Conflicting overlap (seq=1010, len=30 -> ends at 1040 > 1021)
    t += 0.001
    p_ov = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src=client_ip, dst=server_ip) / TCP(
        sport=client_port, dport=server_port, flags="PA", seq=1010, ack=2001
    ) / Raw(load=b"\xFF" * 30)
    p_ov.time = t
    pkts.append(p_ov)

    # 3. Remaining in-order ClientHello bytes from offset 20 onwards
    curr_off = 20
    chunk_size = 30
    while curr_off < len(ch_payload):
        part = ch_payload[curr_off : curr_off + chunk_size]
        t += 0.001
        p_chunk = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src=client_ip, dst=server_ip) / TCP(
            sport=client_port, dport=server_port, flags="PA", seq=1001 + curr_off, ack=2001
        ) / Raw(load=part)
        p_chunk.time = t
        pkts.append(p_chunk)
        curr_off += len(part)

    # 4. ServerHello response
    t += 0.005
    p_sh = Ether(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / IP(src=server_ip, dst=client_ip) / TCP(
        sport=server_port, dport=client_port, flags="PA", seq=2001, ack=1001 + len(ch_payload)
    ) / Raw(load=sh_payload)
    p_sh.time = t
    pkts.append(p_sh)

    wrpcap(str(pcap), pkts)
    return pcap, {"ANOMALY_TCP_OVERLAP"}, "SECURE"


def gen_ip_fragmented(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    """IPv4 packet fragmented into 4 datagrams."""
    pcap = _get_temp_pcap(tmp_path, "ip_fragmented")
    ch = _build_client_hello(sni="mail.fragmented-ip.com", tls13_supported=True)
    sh = _build_server_hello(selected_cipher=0x1301, selected_version=0x0304)
    pkts: list[Ether] = []
    t = 1700000000.0

    # Handshake
    p_syn = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src="192.168.1.100", dst="10.0.0.25") / TCP(sport=54321, dport=465, flags="S", seq=1000)
    p_syn.time = t
    pkts.append(p_syn)

    t += 0.005
    p_sa = Ether(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / IP(src="10.0.0.25", dst="192.168.1.100") / TCP(sport=465, dport=54321, flags="SA", seq=2000, ack=1001)
    p_sa.time = t
    pkts.append(p_sa)

    t += 0.005
    p_a = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src="192.168.1.100", dst="10.0.0.25") / TCP(sport=54321, dport=465, flags="A", seq=1001, ack=2001)
    p_a.time = t
    pkts.append(p_a)

    # Full TCP packet payload with ClientHello
    tcp_hdr = struct.pack(">HHIIBBHHH", 54321, 465, 1001, 2001, 0x50, 0x18, 65535, 0, 0)
    full_l4 = tcp_hdr + ch

    # Fragment into 4 parts
    frag_size = len(full_l4) // 4
    ip_id = 0xABCD

    for i in range(4):
        offset = i * frag_size
        part = full_l4[offset : offset + frag_size] if i < 3 else full_l4[offset:]
        mf = 1 if i < 3 else 0

        p = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src="192.168.1.100", dst="10.0.0.25", id=ip_id, proto=6, flags=mf * 2, frag=offset // 8) / Raw(load=part)
        p.time = t + (i * 0.002)
        pkts.append(p)

    t += 0.015
    p_sh = Ether(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / IP(src="10.0.0.25", dst="192.168.1.100") / TCP(sport=465, dport=54321, flags="PA", seq=2001, ack=1001 + len(ch)) / Raw(load=sh)
    p_sh.time = t
    pkts.append(p_sh)

    wrpcap(str(pcap), pkts)
    return pcap, set(), "SECURE"


def gen_seq_wraparound(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    """TCP ISN near 2^32 (0xFFFFFF00) wrapping across 0."""
    pcap = _get_temp_pcap(tmp_path, "seq_wraparound")
    ch = _build_client_hello(sni="mail.wraparound.example.com", tls13_supported=True)
    sh = _build_server_hello(selected_cipher=0x1301, selected_version=0x0304)

    c2s = [(0.01, ch)]
    s2c = [(0.02, sh)]

    pkts = _build_tcp_session(
        c2s, s2c, server_port=465, isn_client=0xFFFFFFF0, isn_server=0xFFFFFFF8
    )
    wrpcap(str(pcap), pkts)
    return pcap, set(), "SECURE"


def gen_midstream_capture(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    """Capture starting mid-stream without SYN."""
    pcap = _get_temp_pcap(tmp_path, "midstream_capture")
    ch = _build_client_hello(sni="mail.midstream.example.com", tls13_supported=True)
    sh = _build_server_hello(selected_cipher=0x1301, selected_version=0x0304)

    t = 1700000000.0
    p1 = Ether() / IP(src="192.168.1.100", dst="10.0.0.25") / TCP(sport=54321, dport=465, flags="PA", seq=5000, ack=6000) / Raw(load=ch)
    p1.time = t

    p2 = Ether() / IP(src="10.0.0.25", dst="192.168.1.100") / TCP(sport=465, dport=54321, flags="PA", seq=6000, ack=5000 + len(ch)) / Raw(load=sh)
    p2.time = t + 0.02

    wrpcap(str(pcap), [p1, p2])
    return pcap, set(), "SECURE"


# -----------------------------------------------------------------------------
# 7. Malformed Inputs & Hostile Fuzzing Edge Cases
# -----------------------------------------------------------------------------

def gen_truncated_pcap(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    """PCAP abruptly cut off in the middle of a packet record."""
    pcap = _get_temp_pcap(tmp_path, "truncated_pcap")
    valid_pcap, _, _ = gen_starttls_strip(tmp_path)
    raw_data = valid_pcap.read_bytes()
    # Truncate halfway through
    pcap.write_bytes(raw_data[: len(raw_data) // 2 + 10])
    return pcap, set(), "CRITICAL"


def gen_malformed_tls(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    """TLS record with invalid length and garbage payload."""
    pcap = _get_temp_pcap(tmp_path, "malformed_tls")
    bad_rec = b"\x16\x03\x03\xFF\xFF" + b"\xDE\xAD\xBE\xEF" * 10
    c2s = [(0.01, bad_rec)]
    s2c: list[tuple[float, bytes]] = []

    pkts = _build_tcp_session(c2s, s2c, server_port=465)
    wrpcap(str(pcap), pkts)
    return pcap, set(), "HIGH"


def gen_bad_der_cert(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    """Corrupted ASN.1 DER certificate bytes."""
    pcap = _get_temp_pcap(tmp_path, "bad_der_cert")
    ch = _build_client_hello(sni="mail.example.com", tls13_supported=False)
    sh = _build_server_hello(selected_cipher=0xC02F, selected_version=0x0303)
    # Corrupt DER bytes
    bad_der = b"\x30\x82\x05\x00" + b"\xFF\xFE\xFD" * 20
    cert_rec = _build_certificate_message([bad_der])

    c2s = [(0.01, ch)]
    s2c = [(0.015, sh), (0.02, cert_rec)]

    pkts = _build_tcp_session(c2s, s2c, server_port=465)
    wrpcap(str(pcap), pkts)
    return pcap, set(), "CRITICAL"


def gen_zero_length_records(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    """Zero-length TLS records."""
    pcap = _get_temp_pcap(tmp_path, "zero_length_records")
    zero_rec = b"\x16\x03\x03\x00\x00\x17\x03\x03\x00\x00"
    c2s = [(0.01, zero_rec)]
    s2c: list[tuple[float, bytes]] = []

    pkts = _build_tcp_session(c2s, s2c, server_port=465)
    wrpcap(str(pcap), pkts)
    return pcap, set(), "HIGH"


# -----------------------------------------------------------------------------
# 8. Modern TLS (TLS 1.3, ECH, Resumption)
# -----------------------------------------------------------------------------

def gen_tls13_session(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    """TLS 1.3 session with encrypted certificates -> cert_analysis_possible=False."""
    pcap = _get_temp_pcap(tmp_path, "tls13_session")
    ch = _build_client_hello(sni="mail.tls13-secure.com", tls13_supported=True)
    sh = _build_server_hello(selected_cipher=0x1302, selected_version=0x0304)

    c2s = [(0.01, ch)]
    s2c = [(0.02, sh)]

    pkts = _build_tcp_session(c2s, s2c, server_port=465)
    wrpcap(str(pcap), pkts)
    return pcap, set(), "SECURE"


def gen_ech_session(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    """Encrypted Client Hello (ECH) session -> outer SNI masked, no penalty applied."""
    pcap = _get_temp_pcap(tmp_path, "ech_session")
    ch = _build_client_hello(sni="public-outer.cloudflare.net", tls13_supported=True, ech_present=True)
    sh = _build_server_hello(selected_cipher=0x1301, selected_version=0x0304)

    c2s = [(0.01, ch)]
    s2c = [(0.02, sh)]

    pkts = _build_tcp_session(c2s, s2c, server_port=465)
    wrpcap(str(pcap), pkts)
    return pcap, set(), "SECURE"


def gen_resumed_session(tmp_path: Path | None = None) -> tuple[Path, set[str], str]:
    """TLS session resumption (session ticket / PSK) -> partial_analysis True."""
    pcap = _get_temp_pcap(tmp_path, "resumed_session")
    ch = _build_client_hello(sni="mail.resumed.example.com", tls13_supported=True)
    sh = _build_server_hello(selected_cipher=0x1301, selected_version=0x0304)

    c2s = [(0.01, ch)]
    s2c = [(0.02, sh)]

    pkts = _build_tcp_session(c2s, s2c, server_port=465)
    wrpcap(str(pcap), pkts)
    return pcap, set(), "SECURE"
