"""Integration tests for PCAP upload, streaming SHA-256 hashing, and deduplication."""

from __future__ import annotations

import io

import pytest
from fastapi.testclient import TestClient

from pecff.api.app import app
from pecff.api.security import create_dev_token

# Classic PCAP magic bytes header (24 bytes global header)
VALID_PCAP_HEADER = b"\xa1\xb2\xc3\xd4\x00\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00"


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def analyst_token() -> str:
    return create_dev_token(user_id="test-analyst", roles=["analyst"])


class TestPcapUploadAPI:
    """Validate upload endpoints, magic-byte checks, streaming hash, and deduplication."""

    def test_upload_valid_pcap_returns_202(self, client: TestClient, analyst_token: str) -> None:
        """Valid PCAP upload streams bytes, hashes SHA-256, and returns 202 Accepted with status URL."""
        pcap_payload = VALID_PCAP_HEADER + b"\x00" * 100
        headers = {"Authorization": f"Bearer {analyst_token}"}
        files = {
            "file": ("test_mail.pcap", io.BytesIO(pcap_payload), "application/vnd.tcpdump.pcap")
        }

        res = client.post("/api/v1/pcaps", headers=headers, files=files)
        assert res.status_code == 202
        data = res.json()
        assert "analysis_id" in data
        assert "task_id" in data
        assert "sha256" in data
        assert data["is_duplicate"] is False
        assert data["status_url"] == f"/api/v1/tasks/{data['task_id']}"

    def test_upload_deduplication_returns_200(self, client: TestClient, analyst_token: str) -> None:
        """Re-uploading the exact same SHA-256 capture returns HTTP 200 with duplicate_of set."""
        pcap_payload = VALID_PCAP_HEADER + b"UNIQUE_DEDUP_TEST_PAYLOAD_123"
        headers = {"Authorization": f"Bearer {analyst_token}"}
        files1 = {"file": ("dedup1.pcap", io.BytesIO(pcap_payload), "application/octet-stream")}

        # First upload -> 202
        res1 = client.post("/api/v1/pcaps", headers=headers, files=files1)
        assert res1.status_code == 202
        id1 = res1.json()["analysis_id"]

        # Second upload with identical content -> 200
        files2 = {"file": ("dedup2.pcap", io.BytesIO(pcap_payload), "application/octet-stream")}
        res2 = client.post("/api/v1/pcaps", headers=headers, files=files2)
        assert res2.status_code == 200
        data2 = res2.json()
        assert data2["is_duplicate"] is True
        assert data2["duplicate_of"] == id1

    def test_upload_corrupt_magic_bytes_rejected_400(
        self, client: TestClient, analyst_token: str
    ) -> None:
        """Uploading arbitrary non-PCAP bytes returns 400 Bad Request."""
        corrupt_payload = b"NOT_A_PCAP_FILE_JUST_PLAIN_TEXT"
        headers = {"Authorization": f"Bearer {analyst_token}"}
        files = {"file": ("invalid.txt", io.BytesIO(corrupt_payload), "text/plain")}

        res = client.post("/api/v1/pcaps", headers=headers, files=files)
        assert res.status_code == 400
        assert "magic bytes" in res.json()["detail"].lower()

    def test_presigned_upload_url_generation(self, client: TestClient, analyst_token: str) -> None:
        """POST /api/v1/pcaps/presign generates a valid presigned S3 PUT URL for direct uploads."""
        headers = {"Authorization": f"Bearer {analyst_token}"}
        payload = {"filename": "large_traffic_5gib.pcap", "size_bytes": 5 * 1024 * 1024 * 1024}

        res = client.post("/api/v1/pcaps/presign", headers=headers, json=payload)
        assert res.status_code == 200
        data = res.json()
        assert "upload_url" in data
        assert "file_key" in data
        assert data["expires_in_seconds"] == 3600
        assert "analysis_id" in data
