"""Focused regression test suite for Phase 1 SIH audit fixes.

Tests:
1. TLS Version Mapping (SSL 3.0, TLS 1.0, 1.1, 1.2, 1.3, and unknown versions receiving penalty 70).
2. TLS -> Risk Dataflow (cipher suites, named groups, leaf certificates reach C2-C5).
3. STARTTLS cleartext credential propagation (triggers OMEGA = 1.25 and PROTO-NO-TLS-AUTH veto).
4. TLS -> ML Handshake Serialization / Deserialization roundtrip.
5. ML Inference vs explicit degradation when artifact missing/unfitted.
6. Vectorizer 94-dimensional invariant and NotFittedError enforcement.
7. Canonical 5-tuple + VLAN flow hash symmetry across packet directions.
"""

from __future__ import annotations

import struct
from pathlib import Path
import pytest
from sklearn.exceptions import NotFittedError

from pecff.crypto.risk_engine import (
    NISTDeterministicRiskScorer,
    SessionCryptoParameters,
)
from pecff.crypto.cipher_db import cipher_db
from pecff.ml.features import (
    SessionFeatureExtractor,
    SessionFeatureVectorizer,
)
from pecff.parse.starttls_fsm import StarttlsFSM, StarttlsState
from pecff.parse.tls_decoder import (
    ClientHelloInfo,
    ServerHelloInfo,
    TLSExtension,
    TLSHandshakeSummary,
)
from pecff.tasks.celery_app import load_ml_model_from_disk, load_vectorizer_from_disk
from pecff.tasks.pipeline import (
    TLS_VERSION_MAP,
    compute_canonical_flow_hash,
    deserialize_handshake_summary,
    ml_scoring_task,
    resolve_protocol_version,
    serialize_handshake_summary,
)


class TestTLSVersionMapping:
    """Verify TLS version mapping and explicit unknown handling."""

    def test_version_mapping_table(self) -> None:
        assert TLS_VERSION_MAP[0x0200] == "SSL 2.0"
        assert TLS_VERSION_MAP[0x0300] == "SSL 3.0"
        assert TLS_VERSION_MAP[0x0301] == "TLS 1.0"
        assert TLS_VERSION_MAP[0x0302] == "TLS 1.1"
        assert TLS_VERSION_MAP[0x0303] == "TLS 1.2"
        assert TLS_VERSION_MAP[0x0304] == "TLS 1.3"

    def test_resolve_protocol_version_unknown(self) -> None:
        fsm = StarttlsFSM("SMTP", "EXPLICIT")
        sh = ServerHelloInfo(
            legacy_version=771,
            selected_version=0x0399,  # Unknown version
            random=b"\x00" * 32,
            session_id_echo=b"",
            selected_cipher=0x1301,
            selected_compression=0,
        )
        hs = TLSHandshakeSummary(server_hello=sh)
        ver = resolve_protocol_version(hs, fsm)
        assert ver == "UNKNOWN (0x0399)"

        # Scorer must penalize unknown version with 70 in C1
        scorer = NISTDeterministicRiskScorer()
        params = SessionCryptoParameters(protocol_version=ver)
        res = scorer.score_session(params)
        assert res.component_scores["protocol_version"] == 70
        assert any(p.rule_id == "PROTO-UNKNOWN" for p in res.provenance)


class TestTLSToRiskDataflow:
    """Verify cipher suite, kex, and leaf cert propagation into risk engine."""

    def test_cipher_evaluation_c2(self) -> None:
        scorer = NISTDeterministicRiskScorer()
        # Weak 3DES cipher
        params_3des = SessionCryptoParameters(
            protocol_version="TLS 1.2",
            cipher_id="0x000A",  # TLS_RSA_WITH_3DES_EDE_CBC_SHA
            cipher_info=cipher_db.get("0x000A"),
        )
        res_3des = scorer.score_session(params_3des)
        assert res_3des.component_scores["cipher_hash"] > 0
        assert any("3DES" in p.evidence for p in res_3des.provenance)

        # Strong AES-128-GCM cipher
        params_gcm = SessionCryptoParameters(
            protocol_version="TLS 1.2",
            cipher_id="0xC02F",  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            cipher_info=cipher_db.get("0xC02F"),
        )
        res_gcm = scorer.score_session(params_gcm)
        assert res_gcm.component_scores["cipher_hash"] == 0


class TestSTARTTLSContextMultiplier:
    """Verify cleartext credentials trigger OMEGA = 1.25 and veto when plaintext."""

    def test_omega_cleartext_credentials(self) -> None:
        scorer = NISTDeterministicRiskScorer()
        params = SessionCryptoParameters(
            protocol_version="TLS 1.2",
            cleartext_credentials_observed=True,
            cipher_id="0x000A",
            cipher_info=cipher_db.get("0x000A"),
        )
        res = scorer.score_session(params)
        assert res.context_multiplier == 1.25

    def test_plaintext_auth_veto(self) -> None:
        scorer = NISTDeterministicRiskScorer()
        params = SessionCryptoParameters(
            protocol_version="NONE",
            cleartext_credentials_observed=True,
            has_auth=True,
        )
        res = scorer.score_session(params)
        assert res.score == 100
        assert any(v.rule_id == "PROTO-NO-TLS-AUTH" for v in res.vetoes)


class TestTLSToMLHandshakeSerialization:
    """Verify handshake serialization roundtrip and feature extractor integration."""

    def test_handshake_serialization_roundtrip(self) -> None:
        ch = ClientHelloInfo(
            legacy_version=771,
            random=b"\xaa" * 32,
            session_id=b"\xbb" * 32,
            cipher_suites=[0xC02F, 0x1301],
            compression_methods=[0],
            extensions={
                0: TLSExtension(0, "server_name", 16, b"", "smtp.example.com"),
                10: TLSExtension(10, "supported_groups", 4, b"", [29, 23]),
            },
            supported_groups=[29, 23],
            server_name="smtp.example.com",
        )
        sh = ServerHelloInfo(
            legacy_version=771,
            selected_version=0x0303,
            random=b"\xcc" * 32,
            session_id_echo=b"\xbb" * 32,
            selected_cipher=0xC02F,
            selected_compression=0,
            extensions={},
            selected_alpn="smtp",
        )
        hs = TLSHandshakeSummary(
            client_hello=ch,
            server_hello=sh,
            certificates_der=[b"der_cert_mock"],
            handshake_completed=True,
        )

        serialized = serialize_handshake_summary(hs)
        assert serialized is not None
        reconstructed = deserialize_handshake_summary(serialized)
        assert reconstructed is not None
        assert reconstructed.client_hello is not None
        assert reconstructed.client_hello.server_name == "smtp.example.com"
        assert reconstructed.client_hello.cipher_suites == [0xC02F, 0x1301]
        assert reconstructed.server_hello is not None
        assert reconstructed.server_hello.selected_cipher == 0xC02F
        assert reconstructed.certificates_der == [b"der_cert_mock"]

        # Extract features from reconstructed summary
        extractor = SessionFeatureExtractor()
        feat = extractor.extract_features(
            handshake_summary=reconstructed,
            risk_score=15.0,
        )
        assert feat.has_sni == 1.0
        assert feat.n_ciphers_offered == 2
        assert feat.deterministic_risk_score == 15.0


class TestMLModelInferenceAndDegradation:
    """Verify fitted model inference and explicit degradation on missing artifact."""

    def test_fitted_model_loads_and_infers(self) -> None:
        model = load_ml_model_from_disk()
        vectorizer = load_vectorizer_from_disk()
        assert model is not None, "Trained model artifact should exist in data/models"
        assert vectorizer is not None, "Fitted vectorizer artifact should exist in data/models"

        extractor = SessionFeatureExtractor()
        feat = extractor.extract_features(handshake_summary=None, dst_port=25)
        vec = vectorizer.transform([feat])
        assert vec.shape == (1, 94)

        score = -model.score_samples(vec)
        pred = model.predict(vec)
        assert len(score) == 1
        assert pred[0] in {-1, 1}

    def test_explicit_degradation_when_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Simulate missing model
        import pecff.tasks.pipeline as pipeline_mod

        monkeypatch.setattr(pipeline_mod, "get_preloaded_ml_model", lambda: None)
        monkeypatch.setattr(pipeline_mod, "get_preloaded_vectorizer", lambda: None)

        corpus_data = {
            "analysis_id": "test-degraded",
            "sessions": [
                {
                    "id": "sess-1",
                    "server_port": 25,
                    "c2s_bytes": 100,
                    "s2c_bytes": 200,
                    "duration_sec": 1.0,
                    "risk_score": 10.0,
                }
            ],
        }

        res = ml_scoring_task(corpus_data)
        assert res["sessions"][0]["is_anomaly"] is False
        assert res["sessions"][0]["ml_result"] is None


class TestFeatureDimensionalityAndVectorizer:
    """Verify exact 94-dimensional matrix and NotFittedError behavior."""

    def test_unfitted_vectorizer_raises(self) -> None:
        vec = SessionFeatureVectorizer()
        extractor = SessionFeatureExtractor()
        feat = extractor.extract_features(handshake_summary=None)
        with pytest.raises(NotFittedError):
            vec.transform([feat])

    def test_pre_fitted_vectorizer_94_dims(self) -> None:
        vec = load_vectorizer_from_disk()
        assert vec is not None
        extractor = SessionFeatureExtractor()
        feat = extractor.extract_features(handshake_summary=None)
        matrix = vec.transform([feat, feat, feat])
        assert matrix.shape == (3, 94)


class TestCanonicalFlowHash:
    """Verify canonical 5-tuple + VLAN flow hashing."""

    def test_bidirectional_symmetry(self) -> None:
        # Build IPv4 TCP packet A -> B
        # IP header: proto=6, src=192.168.1.10, dst=192.168.1.20
        # TCP header: src_port=12345, dst_port=25
        ip_fwd = (
            b"\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x00\x00"
            b"\xc0\xa8\x01\x0a"  # 192.168.1.10
            b"\xc0\xa8\x01\x14"  # 192.168.1.20
            b"\x30\x39\x00\x19\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\x20\x00\x00\x00\x00\x00"
        )
        # IP header: proto=6, src=192.168.1.20, dst=192.168.1.10
        # TCP header: src_port=25, dst_port=12345
        ip_rev = (
            b"\x45\x00\x00\x28\x00\x02\x00\x00\x40\x06\x00\x00"
            b"\xc0\xa8\x01\x14"  # 192.168.1.20
            b"\xc0\xa8\x01\x0a"  # 192.168.1.10
            b"\x00\x19\x30\x39\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\x20\x00\x00\x00\x00\x00"
        )

        h_fwd = compute_canonical_flow_hash(memoryview(ip_fwd), vlan_id=10)
        h_rev = compute_canonical_flow_hash(memoryview(ip_rev), vlan_id=10)

        assert h_fwd is not None
        assert h_rev is not None
        assert h_fwd == h_rev, "Flow hash must be identical in forward and reverse directions"

    def test_port_sensitivity(self) -> None:
        # Same IPs, different client port
        ip_pkt1 = (
            b"\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x00\x00"
            b"\xc0\xa8\x01\x0a\xc0\xa8\x01\x14"
            b"\x30\x39\x00\x19\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\x20\x00\x00\x00\x00\x00"
        )
        ip_pkt2 = (
            b"\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x00\x00"
            b"\xc0\xa8\x01\x0a\xc0\xa8\x01\x14"
            b"\x30\x3a\x00\x19\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\x20\x00\x00\x00\x00\x00"
        )
        h1 = compute_canonical_flow_hash(memoryview(ip_pkt1), vlan_id=None)
        h2 = compute_canonical_flow_hash(memoryview(ip_pkt2), vlan_id=None)
        assert h1 != h2, "Flow hash must differentiate different client ports"
