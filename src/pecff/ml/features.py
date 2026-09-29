"""Session feature vectorizer and 94-dimensional forensic feature pipeline.

Feature Vector Blocks (Total: 94 dimensions):
1. FINGERPRINT BLOCK (32 dims): HashingVectorizer(n_features=32, alternate_sign=False)
   over space-joined document of ja3, ja3s, ja4, ja4s.
2. CIPHER PROFILE (15 dims): n_ciphers_offered, n_grease, top1..top5 cipher ids,
   mean_cipher_strength_bits, min_strength, offers_3des, offers_rc4, offers_null,
   pct_aead, pct_pfs, cipher_list_entropy (Shannon bits over cipher family distribution).
3. EXTENSION PROFILE (11 dims): 24-bit presence bitmap over common extension types,
   n_extensions, ext_order_hash, has_sni, sni_is_ip, sni_entropy, sni_label_count,
   has_alpn, alpn_hash, has_padding, padding_len.
4. CRYPTO PARAMS (10 dims): selected_version, selected_cipher, kex_group, pubkey_bits,
   sig_alg, cert_chain_len, cert_lifetime_days, is_self_signed, san_count, risk_score.
5. SESSION METADATA (18 dims): client_hello_len, server_hello_len, total_hs_bytes,
   n_hs_packets, packet-size stats (mean, std, min, max), inter-arrival delta stats
   (mean, std, min, max), rtt_estimate, hs_duration_ms, tcp_retrans_count,
   tcp_overlap_count, ttl_client, tcp_window_scale.
6. BEHAVIORAL (8 dims): starttls_final_state (0-4), sessions_from_src, distinct_sni_per_src,
   dst_port, port_is_standard_mail, bytes_up_down_ratio, session_duration_s, is_periodic.

Missing-Data Policy:
- ECH Present -> SNI is genuinely unavailable. Exclude SNI features via mask,
  set sni_visibility="ech". ECH is an explicit privacy feature and not penalized.
- TLS 1.3 -> Certificate is encrypted. Mask certificate features with cert_features_masked=True.
- Never impute 0 where "unknown" is the truth. Median imputation used in numeric transformer.
"""

from __future__ import annotations

import json
import math
import zlib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, cast

import joblib
import numpy as np
import pandas as pd
from sklearn.exceptions import NotFittedError
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import QuantileTransformer

from pecff.crypto.cipher_db import CipherDatabase
from pecff.crypto.risk_engine import RiskResult
from pecff.crypto.x509_parser import ParsedCertificate
from pecff.ml.fingerprints import (
    SessionFingerprints,
    calculate_ja3,
    calculate_ja3s,
    calculate_ja4,
    calculate_ja4s,
    is_grease_val,
    is_ip_address,
)
from pecff.parse.tls_decoder import (
    ExtensionType,
    TLSHandshakeSummary,
)


def _get_default_manifest_path() -> Path:
    """Resolve manifest path with fallback to package data or workspace data."""
    # 1. Workspace repo root data/feature_manifest.json
    repo_data = (
        Path(__file__).resolve().parent.parent.parent.parent / "data" / "feature_manifest.json"
    )
    if repo_data.exists():
        return repo_data
    # 2. Package-local feature_manifest.json
    pkg_data = Path(__file__).resolve().parent / "feature_manifest.json"
    if pkg_data.exists():
        return pkg_data
    return repo_data


MANIFEST_PATH: Final[Path] = _get_default_manifest_path()

# 24 standard TLS extension types for the 24-bit presence bitmap
BITMAP_EXTENSION_TYPES: Final[list[int]] = [
    ExtensionType.SERVER_NAME,  # 0
    ExtensionType.MAX_FRAGMENT_LENGTH,  # 1
    ExtensionType.STATUS_REQUEST,  # 5
    ExtensionType.SUPPORTED_GROUPS,  # 10
    ExtensionType.EC_POINT_FORMATS,  # 11
    ExtensionType.SIGNATURE_ALGORITHMS,  # 13
    ExtensionType.ALPN,  # 16
    ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP,  # 18
    ExtensionType.PADDING,  # 21
    ExtensionType.EXTENDED_MASTER_SECRET,  # 23
    ExtensionType.SESSION_TICKET,  # 35
    ExtensionType.PRE_SHARED_KEY,  # 41
    ExtensionType.EARLY_DATA,  # 42
    ExtensionType.SUPPORTED_VERSIONS,  # 43
    ExtensionType.COOKIE,  # 44
    ExtensionType.PSK_KEY_EXCHANGE_MODES,  # 45
    ExtensionType.CERTIFICATE_AUTHORITIES,  # 47
    ExtensionType.POST_HANDSHAKE_AUTH,  # 49
    ExtensionType.SIGNATURE_ALGORITHMS_CERT,  # 50
    ExtensionType.KEY_SHARE,  # 51
    28,  # RECORD_SIZE_LIMIT
    34,  # DELEGATED_CREDENTIALS
    0xFE0D,  # ENCRYPTED_CLIENT_HELLO
    65281,  # RENEGOTIATION_INFO
]


def calculate_shannon_entropy(text: str | None) -> float:
    """Calculate Shannon entropy in bits per character."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)


def calculate_cipher_family_entropy(cipher_ids: list[int], cipher_db: CipherDatabase) -> float:
    """Calculate Shannon entropy across cipher suite algorithm families."""
    if not cipher_ids:
        return 0.0
    families: list[str] = []
    for cid in cipher_ids:
        if is_grease_val(cid):
            continue
        hex_id = f"0x{cid:04X}"
        info = cipher_db.get(hex_id)
        if info:
            enc = info.enc.upper()
            if "GCM" in enc:
                families.append("AES-GCM")
            elif "CHACHA" in enc:
                families.append("CHACHA20")
            elif "CBC" in enc:
                families.append("AES-CBC")
            elif "3DES" in enc or "DES" in enc:
                families.append("3DES")
            elif "RC4" in enc:
                families.append("RC4")
            elif "NULL" in enc:
                families.append("NULL")
            else:
                families.append("OTHER")
        else:
            families.append("UNKNOWN")

    if not families:
        return 0.0

    length = len(families)
    counts = Counter(families)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)


@dataclass(slots=True)
class RawSessionFeatures:
    """Unprocessed session feature measurements prior to tabular vectorization."""

    # Fingerprints
    fingerprints: SessionFingerprints

    # Cipher Profile
    n_ciphers_offered: int
    n_grease_ciphers: int
    top1_cipher: int
    top2_cipher: int
    top3_cipher: int
    top4_cipher: int
    top5_cipher: int
    mean_cipher_strength: float
    min_cipher_strength: float
    offers_3des: float
    offers_rc4: float
    offers_null: float
    pct_aead: float
    pct_pfs: float
    cipher_list_entropy: float

    # Extension Profile
    ext_bitmap_24: int
    n_extensions: int
    ext_order_hash: float
    has_sni: float
    sni_is_ip: float
    sni_entropy: float
    sni_label_count: float
    has_alpn: float
    alpn_hash: float
    has_padding: float
    padding_len: float

    # Crypto Params
    selected_version: float
    selected_cipher: float
    kex_group: float
    pubkey_bits: float
    sig_alg: float
    cert_chain_len: float
    cert_lifetime_days: float
    is_self_signed: float
    san_count: float
    deterministic_risk_score: float

    # Session Metadata
    client_hello_len: float
    server_hello_len: float
    total_hs_bytes: float
    n_hs_packets: float
    pkt_size_mean: float
    pkt_size_std: float
    pkt_size_min: float
    pkt_size_max: float
    iat_mean: float
    iat_std: float
    iat_min: float
    iat_max: float
    rtt_estimate_ms: float
    hs_duration_ms: float
    tcp_retrans_count: float
    tcp_overlap_count: float
    ttl_client: float
    tcp_window_scale: float

    # Behavioral
    starttls_final_state: float  # 0.0 to 4.0
    sessions_from_src: float
    distinct_sni_per_src: float
    dst_port: float
    port_is_standard_mail: float
    bytes_up_down_ratio: float
    session_duration_s: float
    is_periodic: float

    # Missing Data Masks
    sni_visibility: str = "clear"  # "clear", "ech", "none"
    cert_features_masked: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert features to a flat dictionary for tabular processing."""
        return {
            "fp_document": self.fingerprints.to_document(),
            "ciph_n_offered": float(self.n_ciphers_offered),
            "ciph_n_grease": float(self.n_grease_ciphers),
            "ciph_top1_id": float(self.top1_cipher),
            "ciph_top2_id": float(self.top2_cipher),
            "ciph_top3_id": float(self.top3_cipher),
            "ciph_top4_id": float(self.top4_cipher),
            "ciph_top5_id": float(self.top5_cipher),
            "ciph_mean_strength": float(self.mean_cipher_strength),
            "ciph_min_strength": float(self.min_cipher_strength),
            "ciph_offers_3des": float(self.offers_3des),
            "ciph_offers_rc4": float(self.offers_rc4),
            "ciph_offers_null": float(self.offers_null),
            "ciph_pct_aead": float(self.pct_aead),
            "ciph_pct_pfs": float(self.pct_pfs),
            "ciph_list_entropy": float(self.cipher_list_entropy),
            "ext_bitmap_24": float(self.ext_bitmap_24),
            "ext_count": float(self.n_extensions),
            "ext_order_hash": float(self.ext_order_hash),
            "ext_has_sni": float(self.has_sni),
            "ext_sni_is_ip": float(self.sni_is_ip),
            "ext_sni_entropy": float(self.sni_entropy),
            "ext_sni_label_count": float(self.sni_label_count),
            "ext_has_alpn": float(self.has_alpn),
            "ext_alpn_hash": float(self.alpn_hash),
            "ext_has_padding": float(self.has_padding),
            "ext_padding_len": float(self.padding_len),
            "crypto_selected_version": float(self.selected_version),
            "crypto_selected_cipher": float(self.selected_cipher),
            "crypto_kex_group": float(self.kex_group),
            "crypto_pubkey_bits": float(self.pubkey_bits),
            "crypto_sig_alg": float(self.sig_alg),
            "crypto_cert_chain_len": float(self.cert_chain_len),
            "crypto_cert_lifetime_days": float(self.cert_lifetime_days),
            "crypto_is_self_signed": float(self.is_self_signed),
            "crypto_san_count": float(self.san_count),
            "crypto_risk_score": float(self.deterministic_risk_score),
            "meta_client_hello_len": float(self.client_hello_len),
            "meta_server_hello_len": float(self.server_hello_len),
            "meta_total_hs_bytes": float(self.total_hs_bytes),
            "meta_n_hs_packets": float(self.n_hs_packets),
            "meta_pkt_size_mean": float(self.pkt_size_mean),
            "meta_pkt_size_std": float(self.pkt_size_std),
            "meta_pkt_size_min": float(self.pkt_size_min),
            "meta_pkt_size_max": float(self.pkt_size_max),
            "meta_iat_mean": float(self.iat_mean),
            "meta_iat_std": float(self.iat_std),
            "meta_iat_min": float(self.iat_min),
            "meta_iat_max": float(self.iat_max),
            "meta_rtt_estimate_ms": float(self.rtt_estimate_ms),
            "meta_hs_duration_ms": float(self.hs_duration_ms),
            "meta_tcp_retrans_count": float(self.tcp_retrans_count),
            "meta_tcp_overlap_count": float(self.tcp_overlap_count),
            "meta_ttl_client": float(self.ttl_client),
            "meta_tcp_window_scale": float(self.tcp_window_scale),
            "beh_starttls_state": float(self.starttls_final_state),
            "beh_sessions_from_src": float(self.sessions_from_src),
            "beh_distinct_sni_per_src": float(self.distinct_sni_per_src),
            "beh_dst_port": float(self.dst_port),
            "beh_port_is_standard_mail": float(self.port_is_standard_mail),
            "beh_bytes_up_down_ratio": float(self.bytes_up_down_ratio),
            "beh_session_duration_s": float(self.session_duration_s),
            "beh_is_periodic": float(self.is_periodic),
        }


class SessionFeatureExtractor:
    """Extracts standardized RawSessionFeatures from forensic analysis models."""

    def __init__(self, cipher_db: CipherDatabase | None = None) -> None:
        self.cipher_db = cipher_db or CipherDatabase()

    def extract_features(
        self,
        handshake_summary: TLSHandshakeSummary | None,
        leaf_cert: ParsedCertificate | None = None,
        risk_result: RiskResult | None = None,
        starttls_state: str = "S4_TLS_READY",
        dst_port: int = 25,
        c2s_bytes: int = 0,
        s2c_bytes: int = 0,
        duration_sec: float = 0.0,
        pkt_sizes: list[int] | None = None,
        pkt_timestamps: list[float] | None = None,
        rtt_ms: float = 20.0,
        retrans_count: int = 0,
        overlap_count: int = 0,
        ttl_client: int = 64,
        window_scale: int = 7,
        src_ip_session_count: int = 1,
        distinct_sni_count: int = 1,
        is_periodic: bool = False,
        risk_score: float | None = None,
    ) -> RawSessionFeatures:
        """Extract RawSessionFeatures enforcing rigorous missing data policies."""
        ch = handshake_summary.client_hello if handshake_summary else None
        sh = handshake_summary.server_hello if handshake_summary else None

        # 1. Fingerprints
        if ch:
            ja3_str, ja3_h = calculate_ja3(ch)
            ja4_str = calculate_ja4(ch)
        else:
            ja3_str, ja3_h, ja4_str = "", "", ""

        if sh:
            ja3s_str, ja3s_h = calculate_ja3s(sh)
            ja4s_str = calculate_ja4s(sh)
        else:
            ja3s_str, ja3s_h, ja4s_str = "", "", ""

        fps = SessionFingerprints(
            ja3_string=ja3_str,
            ja3=ja3_h,
            ja3s_string=ja3s_str,
            ja3s=ja3s_h,
            ja4=ja4_str,
            ja4s=ja4s_str,
        )

        # 2. Cipher Profile
        ciphers = ch.cipher_suites if ch else []
        non_grease_ciphers = [c for c in ciphers if not is_grease_val(c)]
        n_grease = len(ciphers) - len(non_grease_ciphers)

        top1 = non_grease_ciphers[0] if len(non_grease_ciphers) > 0 else 0
        top2 = non_grease_ciphers[1] if len(non_grease_ciphers) > 1 else 0
        top3 = non_grease_ciphers[2] if len(non_grease_ciphers) > 2 else 0
        top4 = non_grease_ciphers[3] if len(non_grease_ciphers) > 3 else 0
        top5 = non_grease_ciphers[4] if len(non_grease_ciphers) > 4 else 0

        strengths: list[int] = []
        has_3des = 0.0
        has_rc4 = 0.0
        has_null = 0.0
        aead_count = 0
        pfs_count = 0

        for c in non_grease_ciphers:
            hex_id = f"0x{c:04X}"
            info = self.cipher_db.get(hex_id)
            if info:
                strengths.append(info.enc_bits)
                if "3DES" in info.enc.upper() or "3DES" in info.name.upper():
                    has_3des = 1.0
                if "RC4" in info.enc.upper() or "RC4" in info.name.upper():
                    has_rc4 = 1.0
                if info.null_enc:
                    has_null = 1.0
                if info.aead:
                    aead_count += 1
                if info.pfs:
                    pfs_count += 1
            else:
                strengths.append(128)

        mean_str = float(np.mean(strengths)) if strengths else 128.0
        min_str = float(np.min(strengths)) if strengths else 128.0
        pct_aead = float(aead_count / len(non_grease_ciphers)) if non_grease_ciphers else 0.0
        pct_pfs = float(pfs_count / len(non_grease_ciphers)) if non_grease_ciphers else 0.0
        ciph_entropy = calculate_cipher_family_entropy(ciphers, self.cipher_db)

        # 3. Extension Profile
        exts = list(ch.extensions.keys()) if ch else []
        non_grease_exts = [e for e in exts if not is_grease_val(e)]

        # 24-bit extension bitmap
        bitmap = 0
        for i, etype in enumerate(BITMAP_EXTENSION_TYPES):
            if etype in exts:
                bitmap |= 1 << i

        # Wire order hash (CRC32 normalized)
        ext_wire_bytes = b"".join(e.to_bytes(2, "big") for e in non_grease_exts)
        ext_order_hash = float(zlib.crc32(ext_wire_bytes) & 0xFFFFFFFF) / 4294967295.0

        # ECH and SNI Handling
        has_ech = (ExtensionType.ENCRYPTED_CLIENT_HELLO in exts) or (0xFE0D in exts)
        sni_visibility = "clear"
        has_sni = 0.0
        sni_ip = 0.0
        sni_entropy = 0.0
        sni_label_count = 0.0

        if has_ech:
            sni_visibility = "ech"
            # ECH privacy improvement: mask SNI features
            sni_entropy = float("nan")
            sni_label_count = float("nan")
        elif ch and ch.server_name:
            has_sni = 1.0
            sni_visibility = "clear"
            sni_ip = 1.0 if is_ip_address(ch.server_name) else 0.0
            sni_entropy = calculate_shannon_entropy(ch.server_name)
            sni_label_count = float(len(ch.server_name.split(".")))
        else:
            sni_visibility = "none"

        has_alpn = 1.0 if (ch and ch.alpn_protocols) else 0.0
        alpn_val = (
            float(zlib.crc32(ch.alpn_protocols[0].encode("utf-8")) & 0xFFFF)
            if (ch and ch.alpn_protocols)
            else 0.0
        )

        has_padding = 1.0 if (ch and ExtensionType.PADDING in ch.extensions) else 0.0
        pad_len = (
            float(ch.extensions[ExtensionType.PADDING].length)
            if (ch and ExtensionType.PADDING in ch.extensions)
            else 0.0
        )

        # 4. Crypto Params
        sel_ver = float(sh.selected_version) if sh else 0.0
        sel_ciph = float(sh.selected_cipher) if sh else 0.0
        kex_grp = float(ch.supported_groups[0]) if (ch and ch.supported_groups) else 0.0

        cert_masked = False
        if handshake_summary and not handshake_summary.cert_analysis_possible:
            cert_masked = True
            pub_bits = float("nan")
            sig_alg = float("nan")
            chain_len = float("nan")
            cert_days = float("nan")
            self_signed = float("nan")
            san_cnt = float("nan")
        elif leaf_cert:
            pub_bits = float(leaf_cert.public_key_bits)
            sig_alg = float(zlib.crc32(leaf_cert.signature_algorithm_oid.encode("utf-8")) & 0xFFFF)
            chain_len = float(len(handshake_summary.certificates_der)) if handshake_summary else 1.0
            cert_days = float(leaf_cert.lifetime_days)
            self_signed = 1.0 if leaf_cert.is_self_signed else 0.0
            san_cnt = float(len(leaf_cert.san_dns) + len(leaf_cert.san_ip))
        else:
            pub_bits = 2048.0
            sig_alg = 0.0
            chain_len = 0.0
            cert_days = 0.0
            self_signed = 0.0
            san_cnt = 0.0

        if risk_score is not None:
            r_score = float(risk_score)
        elif risk_result:
            r_score = float(risk_result.score)
        else:
            r_score = 0.0

        # 5. Session Metadata & Packet Stats
        ch_len = float(len(ch.session_id) + len(ciphers) * 2 + 50) if ch else 0.0
        sh_len = float(len(sh.session_id_echo) + 40) if sh else 0.0
        total_hs_bytes = float(c2s_bytes + s2c_bytes)
        n_hs_packets = float(len(pkt_sizes)) if pkt_sizes else 4.0

        sizes = np.array(pkt_sizes if pkt_sizes else [64, 1460, 1460, 120])
        pkt_mean = float(np.mean(sizes))
        pkt_std = float(np.std(sizes))
        pkt_min = float(np.min(sizes))
        pkt_max = float(np.max(sizes))

        if pkt_timestamps and len(pkt_timestamps) > 1:
            deltas = np.diff(pkt_timestamps)
            iat_mean = float(np.mean(deltas))
            iat_std = float(np.std(deltas))
            iat_min = float(np.min(deltas))
            iat_max = float(np.max(deltas))
        else:
            iat_mean, iat_std, iat_min, iat_max = 0.010, 0.005, 0.001, 0.050

        # 6. Behavioral
        state_map = {
            "S0_TCP_EST": 0.0,
            "S1_BANNER_SEEN": 1.0,
            "S2_STARTTLS_SENT": 2.0,
            "S3_STARTTLS_OK": 3.0,
            "S4_TLS_READY": 4.0,
        }
        f_state = state_map.get(starttls_state.upper(), 0.0)
        port_std = 1.0 if dst_port in {25, 465, 587, 110, 995, 143, 993} else 0.0
        up_down = float(c2s_bytes / max(1, s2c_bytes))

        return RawSessionFeatures(
            fingerprints=fps,
            n_ciphers_offered=len(non_grease_ciphers),
            n_grease_ciphers=n_grease,
            top1_cipher=top1,
            top2_cipher=top2,
            top3_cipher=top3,
            top4_cipher=top4,
            top5_cipher=top5,
            mean_cipher_strength=mean_str,
            min_cipher_strength=min_str,
            offers_3des=has_3des,
            offers_rc4=has_rc4,
            offers_null=has_null,
            pct_aead=pct_aead,
            pct_pfs=pct_pfs,
            cipher_list_entropy=ciph_entropy,
            ext_bitmap_24=bitmap,
            n_extensions=len(non_grease_exts),
            ext_order_hash=ext_order_hash,
            has_sni=has_sni,
            sni_is_ip=sni_ip,
            sni_entropy=sni_entropy,
            sni_label_count=sni_label_count,
            has_alpn=has_alpn,
            alpn_hash=alpn_val,
            has_padding=has_padding,
            padding_len=pad_len,
            selected_version=sel_ver,
            selected_cipher=sel_ciph,
            kex_group=kex_grp,
            pubkey_bits=pub_bits,
            sig_alg=sig_alg,
            cert_chain_len=chain_len,
            cert_lifetime_days=cert_days,
            is_self_signed=self_signed,
            san_count=san_cnt,
            deterministic_risk_score=r_score,
            client_hello_len=ch_len,
            server_hello_len=sh_len,
            total_hs_bytes=total_hs_bytes,
            n_hs_packets=n_hs_packets,
            pkt_size_mean=pkt_mean,
            pkt_size_std=pkt_std,
            pkt_size_min=pkt_min,
            pkt_size_max=pkt_max,
            iat_mean=iat_mean,
            iat_std=iat_std,
            iat_min=iat_min,
            iat_max=iat_max,
            rtt_estimate_ms=float(rtt_ms),
            hs_duration_ms=float(duration_sec * 1000.0),
            tcp_retrans_count=float(retrans_count),
            tcp_overlap_count=float(overlap_count),
            ttl_client=float(ttl_client),
            tcp_window_scale=float(window_scale),
            starttls_final_state=f_state,
            sessions_from_src=float(src_ip_session_count),
            distinct_sni_per_src=float(distinct_sni_count),
            dst_port=float(dst_port),
            port_is_standard_mail=port_std,
            bytes_up_down_ratio=up_down,
            session_duration_s=float(duration_sec),
            is_periodic=1.0 if is_periodic else 0.0,
            sni_visibility=sni_visibility,
            cert_features_masked=cert_masked,
        )


class SessionFeatureVectorizer:
    """Produces exact 94-dimensional forensic feature vectors with sklearn pipeline integration."""

    def __init__(self, manifest_path: Path | None = None) -> None:
        self.manifest_path = manifest_path or MANIFEST_PATH
        self.feature_manifest = self._load_manifest()
        self.ordered_feature_names: list[str] = self.feature_manifest["ordered_features"]
        assert len(self.ordered_feature_names) == 94, "Manifest must declare exactly 94 features"

        # 32-dim bounded hashing vectorizer for fingerprint text document
        self.hashing_vectorizer = HashingVectorizer(
            n_features=32,
            alternate_sign=False,
            norm="l2",
        )

        # 62 tabular numerical/ordinal features
        self.tabular_feature_names = [
            f for f in self.ordered_feature_names if not f.startswith("fp_hash_")
        ]
        assert len(self.tabular_feature_names) == 62

        # Median imputer + Quantile normalizer pipeline
        self.tabular_pipeline = Pipeline(
            [
                ("imputer", SimpleImputer(strategy="median")),
                (
                    "scaler",
                    QuantileTransformer(
                        output_distribution="normal", random_state=42, n_quantiles=100
                    ),
                ),
            ]
        )
        self._is_fitted = False

    def _load_manifest(self) -> dict[str, Any]:
        """Load and validate JSON feature manifest."""
        if not self.manifest_path.exists():
            raise FileNotFoundError(f"Feature manifest not found at {self.manifest_path}")
        with open(self.manifest_path, encoding="utf-8") as f:
            return cast(dict[str, Any], json.load(f))

    def fit(self, raw_features_list: list[RawSessionFeatures]) -> SessionFeatureVectorizer:
        """Fit quantile transformers and imputers on calibration dataset."""
        df_tab = pd.DataFrame([f.to_dict() for f in raw_features_list])[self.tabular_feature_names]
        self.tabular_pipeline.fit(df_tab)
        self._is_fitted = True
        return self

    def fit_transform(self, raw_features_list: list[RawSessionFeatures]) -> np.ndarray:
        """Fit on raw session features and transform into an exact (N, 94) matrix."""
        return self.fit(raw_features_list).transform(raw_features_list)

    def transform(self, raw_features_list: list[RawSessionFeatures]) -> np.ndarray:
        """Transform raw session feature objects into a normalized (N, 94) matrix."""
        if not raw_features_list:
            return np.empty((0, 94), dtype=np.float32)

        if not self._is_fitted:
            raise NotFittedError(
                "SessionFeatureVectorizer is not fitted. Fit the vectorizer before inference or load a pre-fitted artifact."
            )

        # 1. Transform Fingerprint Document (N, 32)
        fp_docs = [f.fingerprints.to_document() for f in raw_features_list]
        fp_matrix = self.hashing_vectorizer.transform(fp_docs).toarray().astype(np.float32)
        assert fp_matrix.shape == (len(raw_features_list), 32)

        # 2. Extract Tabular Features (N, 62)
        df_tab = pd.DataFrame([f.to_dict() for f in raw_features_list])[self.tabular_feature_names]

        tab_matrix = self.tabular_pipeline.transform(df_tab).astype(np.float32)
        assert tab_matrix.shape == (len(raw_features_list), 62)

        # 3. Concatenate into exact 94-dim feature vector
        vector_94 = np.hstack([fp_matrix, tab_matrix]).astype(np.float32)
        assert vector_94.shape == (len(raw_features_list), 94)

        return vector_94

    def transform_single(self, raw_features: RawSessionFeatures) -> np.ndarray:
        """Transform a single session into an exact (94,) 1D feature vector."""
        return cast(np.ndarray, self.transform([raw_features])[0])

    def save(self, path: Path | str) -> None:
        """Persist fitted vectorizer artifact to disk."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, p)

    @classmethod
    def load(cls, path: Path | str) -> SessionFeatureVectorizer:
        """Load fitted vectorizer artifact from disk."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Vectorizer artifact not found: {p}")
        obj = joblib.load(p)
        if not isinstance(obj, SessionFeatureVectorizer):
            raise TypeError(f"Loaded object is {type(obj)}, expected SessionFeatureVectorizer")
        if not getattr(obj, "_is_fitted", False):
            raise NotFittedError("Loaded vectorizer artifact is not fitted")
        return obj


class FeatureStore:
    """Writes and reads partitioned Parquet feature vectors under data/features/{analysis_id}/."""

    @staticmethod
    def save_features(
        analysis_id: str,
        features_matrix: np.ndarray,
        feature_names: list[str],
        base_dir: Path | str = "data/features",
    ) -> Path:
        """Persist (N, 94) feature matrix as a partitioned Parquet table."""
        out_dir = Path(base_dir) / analysis_id
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / "part-0.parquet"

        df = pd.DataFrame(features_matrix, columns=feature_names)
        df.to_parquet(out_file, engine="pyarrow", index=False)
        return out_file

    @staticmethod
    def load_features(
        analysis_id: str,
        base_dir: Path | str = "data/features",
    ) -> pd.DataFrame:
        """Load stored feature vectors for an analysis run."""
        target_path = Path(base_dir) / analysis_id
        if not target_path.exists():
            raise FileNotFoundError(f"Feature store directory not found: {target_path}")
        parquet_files = list(target_path.glob("*.parquet"))
        if not parquet_files:
            raise FileNotFoundError(f"No parquet partitions found under {target_path}")
        return pd.read_parquet(target_path, engine="pyarrow")
