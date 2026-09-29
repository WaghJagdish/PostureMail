"""Test suite for the 94-dimensional session feature vectorizer and feature store.

Tests:
1. Feature vector output shape is exactly (N, 94).
2. Manifest consistency: Vectorizer features match data/feature_manifest.json.
3. Missing Data Policies:
   - ECH sessions have SNI features masked (NaN), not zeroed/penalized.
   - TLS 1.3 sessions have certificate features masked (NaN).
4. FeatureStore partitioned Parquet roundtrip persistence and recovery.
"""

from __future__ import annotations

import datetime
from pathlib import Path

import numpy as np
import pytest

from pecff.crypto.x509_parser import ParsedCertificate
from pecff.ml.features import (
    FeatureStore,
    SessionFeatureExtractor,
    SessionFeatureVectorizer,
)
from pecff.parse.tls_decoder import (
    ClientHelloInfo,
    ServerHelloInfo,
    TLSExtension,
    TLSHandshakeSummary,
)


@pytest.fixture
def sample_handshake_summary() -> TLSHandshakeSummary:
    """Sample decoded TLS 1.2 handshake summary."""
    ch_exts: dict[int, TLSExtension] = {
        0: TLSExtension(0, "server_name", 16, b"", "mail.example.com"),
        10: TLSExtension(10, "supported_groups", 6, b"", [29, 23]),
        11: TLSExtension(11, "ec_point_formats", 2, b"", [0]),
        13: TLSExtension(13, "signature_algorithms", 4, b"", [0x0403, 0x0804]),
        16: TLSExtension(16, "alpn", 6, b"", ["smtp"]),
        23: TLSExtension(23, "extended_master_secret", 0, b"", None),
    }
    ch = ClientHelloInfo(
        legacy_version=771,
        random=b"\x01" * 32,
        session_id=b"\x02" * 32,
        cipher_suites=[0xC02F, 0xC030, 0xCCA8],
        compression_methods=[0],
        extensions=ch_exts,
        supported_groups=[29, 23],
        ec_point_formats=[0],
        signature_algorithms=[0x0403, 0x0804],
        alpn_protocols=["smtp"],
        server_name="mail.example.com",
    )
    sh_exts: dict[int, TLSExtension] = {
        23: TLSExtension(23, "extended_master_secret", 0, b"", None),
    }
    sh = ServerHelloInfo(
        legacy_version=771,
        selected_version=0x0303,
        random=b"\x03" * 32,
        session_id_echo=b"\x02" * 32,
        selected_cipher=0xC02F,
        selected_compression=0,
        extensions=sh_exts,
        selected_alpn="smtp",
    )
    return TLSHandshakeSummary(
        client_hello=ch,
        server_hello=sh,
        certificates_der=[b"cert_bytes_1", b"cert_bytes_2"],
        cert_analysis_possible=True,
        handshake_completed=True,
    )


@pytest.fixture
def sample_leaf_cert() -> ParsedCertificate:
    """Sample parsed X.509 leaf certificate."""
    now = datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC)
    return ParsedCertificate(
        fingerprint_sha256="1" * 64,
        spki_sha256="2" * 64,
        serial_number="12345",
        version=3,
        subject_dn="CN=mail.example.com",
        issuer_dn="CN=Test CA",
        not_before=now,
        not_after=now + datetime.timedelta(days=90),
        lifetime_days=90,
        signature_algorithm_oid="1.2.840.113549.1.1.11",
        signature_hash="SHA256",
        public_key_algorithm="RSA",
        public_key_bits=2048,
        ec_curve=None,
        security_bits=112,
        is_self_signed=False,
        san_dns=["mail.example.com"],
        sct_count=2,
    )


class TestSessionFeatures:
    """Feature extraction, vectorization, missing-data policy, and persistence tests."""

    def test_feature_vector_shape_is_exactly_94(
        self,
        sample_handshake_summary: TLSHandshakeSummary,
        sample_leaf_cert: ParsedCertificate,
    ) -> None:
        """A single session extracts and vectorizes to an exact (94,) 1D vector."""
        extractor = SessionFeatureExtractor()
        raw_feat = extractor.extract_features(
            handshake_summary=sample_handshake_summary,
            leaf_cert=sample_leaf_cert,
            dst_port=587,
            c2s_bytes=1024,
            s2c_bytes=4096,
            duration_sec=0.15,
            pkt_sizes=[64, 1500, 1500, 128],
            pkt_timestamps=[1.0, 1.02, 1.05, 1.15],
        )

        vectorizer = SessionFeatureVectorizer()
        # Verify NotFittedError before fitting
        with pytest.raises(Exception):
            vectorizer.transform_single(raw_feat)

        vectorizer.fit([raw_feat])
        vec_1d = vectorizer.transform_single(raw_feat)
        assert vec_1d.shape == (94,)
        assert not np.isnan(vec_1d).any(), "Standard vector must not contain NaNs after imputation"

        # Batch transform
        vec_2d = vectorizer.transform([raw_feat, raw_feat])
        assert vec_2d.shape == (2, 94)

    def test_feature_manifest_alignment(self) -> None:
        """Vectorizer ordered features must match data/feature_manifest.json precisely."""
        vectorizer = SessionFeatureVectorizer()
        assert len(vectorizer.ordered_feature_names) == 94
        assert vectorizer.ordered_feature_names[:32] == [f"fp_hash_{i:02d}" for i in range(32)]
        assert "ciph_n_offered" in vectorizer.ordered_feature_names
        assert "ext_bitmap_24" in vectorizer.ordered_feature_names
        assert "crypto_risk_score" in vectorizer.ordered_feature_names
        assert "meta_pkt_size_mean" in vectorizer.ordered_feature_names
        assert "beh_starttls_state" in vectorizer.ordered_feature_names

    def test_missing_data_policy_ech_masking(
        self, sample_handshake_summary: TLSHandshakeSummary
    ) -> None:
        """When Encrypted Client Hello (ECH) is present, SNI features are masked with NaN, not zeroed."""
        # Add ECH extension (0xFE0D) to ClientHello
        assert sample_handshake_summary.client_hello is not None
        sample_handshake_summary.client_hello.extensions[0xFE0D] = TLSExtension(
            0xFE0D, "encrypted_client_hello", 32, b"ech_config", None
        )

        extractor = SessionFeatureExtractor()
        raw_feat = extractor.extract_features(
            handshake_summary=sample_handshake_summary,
            dst_port=465,
        )

        assert raw_feat.sni_visibility == "ech"
        assert np.isnan(raw_feat.sni_entropy), "ECH session must mask SNI entropy with NaN"
        assert np.isnan(raw_feat.sni_label_count), "ECH session must mask SNI label count with NaN"

    def test_missing_data_policy_tls13_certificate_masking(self) -> None:
        """When TLS 1.3 encrypts certificates, certificate fields are masked with NaN."""
        hs = TLSHandshakeSummary(
            client_hello=ClientHelloInfo(
                legacy_version=771,
                random=b"\x01" * 32,
                session_id=b"\x02" * 32,
                cipher_suites=[0x1301],
                compression_methods=[0],
                extensions={},
            ),
            server_hello=ServerHelloInfo(
                legacy_version=771,
                selected_version=0x0304,
                random=b"\x03" * 32,
                session_id_echo=b"\x02" * 32,
                selected_cipher=0x1301,
                selected_compression=0,
                extensions={},
            ),
            cert_analysis_possible=False,
            handshake_completed=True,
        )

        extractor = SessionFeatureExtractor()
        raw_feat = extractor.extract_features(handshake_summary=hs)

        assert raw_feat.cert_features_masked is True
        assert np.isnan(raw_feat.pubkey_bits)
        assert np.isnan(raw_feat.cert_chain_len)
        assert np.isnan(raw_feat.cert_lifetime_days)
        assert np.isnan(raw_feat.is_self_signed)

    def test_feature_store_parquet_roundtrip(
        self,
        tmp_path: Path,
        sample_handshake_summary: TLSHandshakeSummary,
        sample_leaf_cert: ParsedCertificate,
    ) -> None:
        """FeatureStore persists (N, 94) matrix to partitioned Parquet and loads back cleanly."""
        extractor = SessionFeatureExtractor()
        raw_feat = extractor.extract_features(
            handshake_summary=sample_handshake_summary,
            leaf_cert=sample_leaf_cert,
        )
        vectorizer = SessionFeatureVectorizer()
        matrix = vectorizer.fit_transform([raw_feat, raw_feat, raw_feat])

        analysis_id = "test_analysis_123"
        saved_file = FeatureStore.save_features(
            analysis_id=analysis_id,
            features_matrix=matrix,
            feature_names=vectorizer.ordered_feature_names,
            base_dir=tmp_path,
        )

        assert saved_file.exists()
        assert saved_file.name == "part-0.parquet"

        df_loaded = FeatureStore.load_features(analysis_id, base_dir=tmp_path)
        assert df_loaded.shape == (3, 94)
        assert list(df_loaded.columns) == vectorizer.ordered_feature_names
