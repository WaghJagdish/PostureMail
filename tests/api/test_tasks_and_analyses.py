"""Integration tests for Task tracking, Cursor-paginated Session Queries, Streaming Documents, and RBAC."""

from __future__ import annotations

import datetime
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pecff.api.app import app
from pecff.api.routers.analyses import register_analysis
from pecff.api.routers.tasks import update_task_state
from pecff.api.schemas import (
    AnalysisDetailResponse,
    FindingSchema,
    MLAnomalyResultSchema,
    RiskResultSchema,
    SessionDetailSchema,
)
from pecff.api.security import create_dev_token

SCHEMA_FILE = Path(__file__).parent.parent.parent / "schema" / "pecff-analysis-1.0.0.json"


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def admin_token() -> str:
    return create_dev_token(user_id="test-admin", roles=["admin"])


@pytest.fixture
def analyst_token() -> str:
    return create_dev_token(user_id="test-analyst", roles=["analyst"])


@pytest.fixture
def readonly_token() -> str:
    return create_dev_token(user_id="test-readonly", roles=["readonly"])


@pytest.fixture
def populated_analysis() -> str:
    """Register an analysis with 1,000 diverse sessions for pagination and search tests."""
    analysis_id = "test-analysis-perf-1000"
    sessions: list[SessionDetailSchema] = []

    for i in range(1000):
        risk = float(i % 101)
        if risk <= 19:
            band = "SECURE"
        elif risk <= 39:
            band = "ACCEPTABLE"
        elif risk <= 59:
            band = "WEAK"
        elif risk <= 79:
            band = "HIGH"
        else:
            band = "CRITICAL"

        proto = "SMTP" if i % 2 == 0 else "IMAP"
        sessions.append(
            SessionDetailSchema(
                id=f"sess-{analysis_id}-{i:04d}",
                analysis_id=analysis_id,
                client_ip=f"192.168.1.{10 + (i % 20)}",
                client_port=40000 + i,
                server_ip=f"10.0.0.{1 + (i % 5)}",
                server_port=587 if proto == "SMTP" else 993,
                protocol=proto,
                mode="EXPLICIT" if proto == "SMTP" else "IMPLICIT",
                starttls_state="S4_TLS_READY",
                risk_score=risk,
                risk_band=band,
                ja3="771,4865,0,29,0",
                ja4="t13d0906h2_1301_0000",
                sni="mail.company.example.com" if i % 3 == 0 else "smtp.org.example.net",
                first_seen=1700000000.0 + (i * 10),
                duration_sec=1.5,
                is_anomaly=(i % 50 == 0),
                c2s_bytes=1024 + i,
                s2c_bytes=4096 + i,
                risk_breakdown=RiskResultSchema(
                    score=int(risk),
                    band=band,
                    context_multiplier=1.0,
                    component_scores={
                        "protocol_version": 0,
                        "cipher_hash": 0,
                        "key_exchange": 0,
                        "certificate": 0,
                        "session_hygiene": 0,
                    },
                    component_weights={
                        "protocol_version": 0.25,
                        "cipher_hash": 0.25,
                        "key_exchange": 0.20,
                        "certificate": 0.20,
                        "session_hygiene": 0.10,
                    },
                    vetoes=[],
                    effective_security_bits=128,
                    weight_redistributed=False,
                    provenance=[],
                ),
                ml_result=MLAnomalyResultSchema(
                    is_anomaly=(i % 50 == 0),
                    anomaly_score=-0.65 if (i % 50 == 0) else 0.25,
                    anomaly_percentile=98.5 if (i % 50 == 0) else 15.0,
                    top_feature_explanations=[],
                ),
            )
        )

    analysis_doc = AnalysisDetailResponse(
        schema_version="1.0.0",
        analysis_id=analysis_id,
        created_at=datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC),
        pcap_filename="large_email_traffic.pcap",
        pcap_sha256="a" * 64,
        status="COMPLETED",
        total_packets=50000,
        total_sessions=len(sessions),
        overall_risk_score=100.0,
        overall_risk_band="CRITICAL",
        summary_data={"protocols": {"SMTP": 500, "IMAP": 500}},
        sessions=sessions,
        findings=[
            FindingSchema(
                id="finding-1",
                session_id=sessions[0].id,
                rule_id="PROTO-SSL3",
                title="Deprecated SSLv3",
                description="POODLE vulnerability detected",
                severity="CRITICAL",
                standards_ref="RFC 7568",
                evidence={},
            )
        ],
    )
    register_analysis(analysis_doc)
    return analysis_id


class TestTasksAndAnalysesAPI:
    """Validate task lifecycle, cursor pagination, document streaming, and RBAC."""

    def test_task_status_and_revocation(self, client: TestClient, analyst_token: str) -> None:
        """Query task state and revoke active task cleanly."""
        task_id = "test-task-12345"
        update_task_state(
            task_id=task_id,
            state="PARSING",
            progress=0.45,
            stage_detail="Processing packet 45,000",
            packets_processed=45000,
        )

        headers = {"Authorization": f"Bearer {analyst_token}"}
        res = client.get(f"/api/v1/tasks/{task_id}", headers=headers)
        assert res.status_code == 200
        assert res.json()["state"] == "PARSING"
        assert res.json()["progress"] == 0.45

        # Revoke task
        del_res = client.delete(f"/api/v1/tasks/{task_id}", headers=headers)
        assert del_res.status_code == 200
        assert del_res.json()["state"] == "REVOKED"

    def test_cursor_pagination_and_indexed_filters(
        self, client: TestClient, readonly_token: str, populated_analysis: str
    ) -> None:
        """Cursor pagination retrieves pages sequentially under 200ms latency ceiling."""
        headers = {"Authorization": f"Bearer {readonly_token}"}
        analysis_id = populated_analysis

        # 1. Fetch First Page (limit=50, filter min_risk=60)
        t0 = time.perf_counter()
        res1 = client.get(
            f"/api/v1/analyses/{analysis_id}/sessions?limit=50&min_risk=60&sort_by=risk&sort_order=desc",
            headers=headers,
        )
        t1 = time.perf_counter()
        assert (t1 - t0) < 0.200  # Strict sub-200ms latency requirement

        assert res1.status_code == 200
        data1 = res1.json()
        assert len(data1["items"]) == 50
        assert data1["has_more"] is True
        assert data1["next_cursor"] is not None

        # Verify items sorted descending
        scores = [item["risk_score"] for item in data1["items"]]
        assert scores == sorted(scores, reverse=True)
        assert min(scores) >= 60.0

        # 2. Fetch Second Page using cursor
        cursor = data1["next_cursor"]
        res2 = client.get(
            f"/api/v1/analyses/{analysis_id}/sessions?limit=50&min_risk=60&sort_by=risk&sort_order=desc&cursor={cursor}",
            headers=headers,
        )
        assert res2.status_code == 200
        data2 = res2.json()
        assert len(data2["items"]) == 50
        # Check no overlap between page 1 and page 2
        p1_ids = {s["id"] for s in data1["items"]}
        p2_ids = {s["id"] for s in data2["items"]}
        assert len(p1_ids.intersection(p2_ids)) == 0

    def test_stream_analysis_document_conforms_to_schema(
        self, client: TestClient, readonly_token: str, populated_analysis: str
    ) -> None:
        """GET /api/v1/analyses/{id} streams valid JSON conforming to committed schema."""
        headers = {"Authorization": f"Bearer {readonly_token}"}
        analysis_id = populated_analysis

        res = client.get(f"/api/v1/analyses/{analysis_id}", headers=headers)
        assert res.status_code == 200
        doc = res.json()
        assert doc["schema_version"] == "1.0.0"
        assert doc["analysis_id"] == analysis_id
        assert "sessions" in doc
        assert "findings" in doc

        # Verify against Pydantic schema model
        validated = AnalysisDetailResponse.model_validate(doc)
        assert validated.analysis_id == analysis_id

    def test_rbac_roles_enforcement(
        self, client: TestClient, readonly_token: str, analyst_token: str, admin_token: str
    ) -> None:
        """Readonly role is denied verdict submission (403), analyst is allowed."""
        verdict_payload = {
            "verdict": "SUSPICIOUS",
            "confidence": 0.95,
            "notes": "Legacy cipher suite observed.",
        }

        # Readonly token -> 403 Forbidden
        ro_headers = {"Authorization": f"Bearer {readonly_token}"}
        ro_res = client.post(
            "/api/v1/sessions/sess-123/verdict", headers=ro_headers, json=verdict_payload
        )
        assert ro_res.status_code == 403

        # Analyst token -> 201 Created
        an_headers = {"Authorization": f"Bearer {analyst_token}"}
        an_res = client.post(
            "/api/v1/sessions/sess-123/verdict", headers=an_headers, json=verdict_payload
        )
        assert an_res.status_code == 201
        assert an_res.json()["status"] == "RECORDED"

        # Admin token -> Access audit logs (200)
        ad_headers = {"Authorization": f"Bearer {admin_token}"}
        ad_res = client.get("/api/v1/audit/logs", headers=ad_headers)
        assert ad_res.status_code == 200
        assert isinstance(ad_res.json(), list)
