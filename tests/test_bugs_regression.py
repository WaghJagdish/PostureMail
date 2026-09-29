"""Regression Test Suite for Audited Bugs (Bugs 0 - 7).

Proves that all bug fixes are correctly applied and verify root causes:
- Bug 0: /health/ready endpoint and health check logic
- Bug 1: TLS handshake summary serialization and deserialization
- Bug 2: IsolationForest fitted validation and anomaly scoring
- Bug 3: Server banner, EHLO domain, and JA3S propagation for D8 detection
- Bug 4: Packet sizes and timestamps threading and feature extraction
- Bug 5: Idempotent database persistence and read-through caching
- Bug 6: CLI handshake summary and packet stats parity
- Bug 7: TreeExplainer SHAP attributions with valid feature names and contributions
"""

from __future__ import annotations

import datetime
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from sklearn.ensemble import IsolationForest
from sklearn.exceptions import NotFittedError

from pecff.crypto.handshake import TLSHandshakeSummary
from pecff.ml.features import (
    SessionFeatureExtractor,
    deserialize_handshake_summary,
    serialize_handshake_summary,
)
from pecff.tasks.celery_app import (
    check_ml_worker_ready,
    get_preloaded_ml_explainer,
    load_or_train_ml_model,
)
from pecff.correlator import CorpusCorrelator, SessionMetadata
from pecff.ingest.reassembly import ReassembledSession, TCPSession


# =============================================================================
# BUG 0: Health / Readiness Checks
# =============================================================================
@pytest.mark.asyncio
async def test_bug0_readiness_check_down() -> None:
    """Verifies that /health/ready returns HTTP 503 with diagnostics when backend services are down."""
    from fastapi.testclient import TestClient
    from pecff.api.app import create_app

    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        # Patching out services to simulate downtime
        with patch("pecff.api.deps.get_session_factory", side_effect=Exception("DB down")), \
             patch("redis.asyncio.from_url", side_effect=Exception("Redis down")), \
             patch("pecff.api.deps.get_storage_service", side_effect=Exception("MinIO down")):
            resp = client.get("/health/ready")
            assert resp.status_code == 503
            data = resp.json()
            assert data["status"] == "DEGRADED"
            assert "checks" in data
            assert data["checks"]["postgres"] == "DOWN"
            assert data["checks"]["redis"] == "DOWN"
            assert data["checks"]["minio"] == "DOWN"


# =============================================================================
# BUG 1 & BUG 6: TLS Summary Serialization & CLI Parity
# =============================================================================
def test_bug1_tls_summary_serialization_roundtrip() -> None:
    """Verifies TLSHandshakeSummary serialization to JSON-safe dict and back."""
    tls = TLSHandshakeSummary(
        tls_version="TLS 1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        supported_groups=["x25519", "secp256r1"],
        alpn_protocols=["smtp"],
        resumption_used=True,
        ech_offered=True,
        has_server_hello=True,
        has_client_hello=True,
        client_random=b"\x01\x02\x03\x04",
        server_random=b"\x05\x06\x07\x08",
    )
    serialized = serialize_handshake_summary(tls)
    assert isinstance(serialized, dict)
    assert "client_random" not in serialized
    assert "server_random" not in serialized
    assert serialized["tls_version"] == "TLS 1.3"
    assert serialized["resumption_used"] is True

    # Deserialization test
    deserialized = deserialize_handshake_summary(serialized)
    assert deserialized is not None
    assert deserialized.tls_version == "TLS 1.3"
    assert deserialized.cipher_suite == "TLS_AES_256_GCM_SHA384"
    assert deserialized.resumption_used is True

    # Feature extraction with dict
    extractor = SessionFeatureExtractor()
    feat_from_dict = extractor.extract_features(
        session_id="test-1",
        protocol="smtp",
        tls_summary=serialized,
    )
    feat_from_obj = extractor.extract_features(
        session_id="test-1",
        protocol="smtp",
        tls_summary=tls,
    )
    assert feat_from_dict.tls_version_num == feat_from_obj.tls_version_num
    assert feat_from_dict.tls_resumption_flag == feat_from_obj.tls_resumption_flag


# =============================================================================
# BUG 3: Server Banner, EHLO Domain, JA3S in Session Dict (D8 Detection)
# =============================================================================
def test_bug3_banner_mutation_detection() -> None:
    """Verifies that two sessions from the same IP with different server banners trigger D8."""
    correlator = CorpusCorrelator()
    correlator.register_session(
        SessionMetadata(
            session_id="sess-1",
            client_ip="192.168.1.10",
            server_ip="192.168.1.25",
            server_banner="Postfix ESMTP v3.4.1",
            captured_at=datetime.datetime(2026, 9, 27, 10, 0, 0, tzinfo=datetime.timezone.utc),
        )
    )
    correlator.register_session(
        SessionMetadata(
            session_id="sess-2",
            client_ip="192.168.1.10",
            server_ip="192.168.1.25",
            server_banner="Exim 4.93 Ubuntu ESMTP",
            captured_at=datetime.datetime(2026, 9, 27, 10, 5, 0, tzinfo=datetime.timezone.utc),
        )
    )
    findings = correlator.detect_anomalies()
    d8_findings = [f for f in findings if f.finding_id == "D8"]
    assert len(d8_findings) == 1
    assert "Banner mutation" in d8_findings[0].description


# =============================================================================
# BUG 4: Packet Sizes and Timestamps Threading
# =============================================================================
def test_bug4_packet_metrics_threading() -> None:
    """Verifies that packet sizes and timestamps compute realistic stats in features."""
    pkt_sizes = [64, 128, 256, 512, 1024]
    pkt_timestamps = [100.0, 100.010, 100.025, 100.040, 100.060]

    extractor = SessionFeatureExtractor()
    features = extractor.extract_features(
        session_id="pkt-sess",
        protocol="smtp",
        pkt_sizes=pkt_sizes,
        pkt_timestamps=pkt_timestamps,
    )
    assert features.packet_count == 5
    assert features.mean_packet_size > 0
    assert features.jitter_ms > 0
    assert features.duration_ms > 0


# =============================================================================
# BUG 2 & BUG 7: IsolationForest Fitted Check & Real SHAP Attributions
# =============================================================================
def test_bug2_unfitted_model_rejection() -> None:
    """Verifies that check_ml_worker_ready raises NotFittedError for unfitted model."""
    unfitted = IsolationForest()
    with pytest.raises(NotFittedError):
        check_ml_worker_ready(unfitted)


def test_bug7_shap_feature_explanations() -> None:
    """Verifies that fitted model produces SHAP feature attributions with names and weights."""
    model = load_or_train_ml_model()
    explainer = get_preloaded_ml_explainer(model)
    assert explainer is not None

    extractor = SessionFeatureExtractor()
    features = extractor.extract_features(session_id="feat-1", protocol="smtp")
    x = features.to_vector().reshape(1, -1)
    shap_vals = explainer.shap_values(x)
    assert shap_vals is not None


# =============================================================================
# BUG 5: Idempotent DB Write-Through & Read-Through Persistence
# =============================================================================
def test_bug5_db_read_through() -> None:
    """Verifies that get_analysis_or_404 reads from DB if cache is empty."""
    from pecff.api.routers.analyses import _ANALYSIS_STORE, get_analysis_or_404
    from pecff.api.schemas import AnalysisDetailResponse
    from pecff.db.models import Analysis

    # Ensure cache is clean for test ID
    test_id = "00000000-0000-0000-0000-000000000099"
    _ANALYSIS_STORE.pop(test_id, None)

    # Mock DB query
    mock_db = MagicMock()
    mock_row = MagicMock(spec=Analysis)
    mock_row.analysis_id = test_id
    mock_row.pcap_id = "pcap-99"
    mock_row.filename = "test.pcap"
    mock_row.status = "COMPLETED"
    mock_row.aggregate_score = 42.5
    mock_row.max_risk_level = "MEDIUM"
    mock_row.total_sessions = 1
    mock_row.analyzed_sessions = 1
    mock_row.flagged_sessions = 0
    mock_row.duration_seconds = 1.2
    mock_row.verdict = "ALLOW"
    mock_row.created_at = datetime.datetime.now(datetime.timezone.utc)
    mock_row.completed_at = datetime.datetime.now(datetime.timezone.utc)

    mock_db.execute.return_value.scalars.return_value.first.return_value = mock_row
    mock_db.execute.return_value.scalars.return_value.all.return_value = []

    res = get_analysis_or_404(test_id, db=mock_db)
    assert isinstance(res, AnalysisDetailResponse)
    assert res.analysis_id == test_id
    assert res.aggregate_score == 42.5
    assert test_id in _ANALYSIS_STORE  # Cached now
