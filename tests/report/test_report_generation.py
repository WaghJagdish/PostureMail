"""Comprehensive tests for forensic report generation, Chain of Custody, and exporters."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pecff.api.schemas import (
    AnalysisDetailResponse,
    CertificateSchema,
    FindingSchema,
    MLAnomalyResultSchema,
    RiskResultSchema,
    SessionDetailSchema,
    VetoFindingSchema,
)
from pecff.report.chain_of_custody import ChainOfCustody, ChainOfCustodyValidationError
from pecff.report.compliance import evaluate_compliance_controls
from pecff.report.engine import ForensicReportEngine
from pecff.report.privacy import PCAPRetentionSweeper, scrub_pii_from_analysis


@pytest.fixture
def sample_analysis_response() -> AnalysisDetailResponse:
    """Fixture providing a complete mock forensic analysis response."""
    return AnalysisDetailResponse(
        schema_version="1.0.0",
        analysis_id="analysis-test-report-123",
        created_at=datetime(2026, 9, 25, 12, 0, 0, tzinfo=UTC),
        pcap_filename="test_enterprise_mail.pcap",
        pcap_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        status="COMPLETED",
        total_packets=125400,
        total_sessions=2,
        overall_risk_score=85.0,
        overall_risk_band="CRITICAL",
        summary_data={
            "session_count": 2,
            "findings_count": 2,
        },
        sessions=[
            SessionDetailSchema(
                id="sess-001",
                analysis_id="analysis-test-report-123",
                client_ip="192.168.1.100",
                client_port=52344,
                server_ip="10.0.0.25",
                server_port=25,
                protocol="SMTP",
                mode="EXPLICIT",
                starttls_state="S_STRIP_DETECTED",
                risk_score=85.0,
                risk_band="CRITICAL",
                ja3="771,4865-4866,0-10-11,29-23,0",
                ja4="t13d1516h2_8daaf6152771_000000000000",
                sni="mail.enterprise.corp",
                first_seen=1700000000.0,
                duration_sec=2.45,
                is_anomaly=True,
                c2s_bytes=4096,
                s2c_bytes=8192,
                server_banner="220 mx.enterprise.corp ESMTP for alice.smith@corp.example.com",
                risk_breakdown=RiskResultSchema(
                    score=85,
                    band="CRITICAL",
                    context_multiplier=1.0,
                    component_scores={
                        "protocol_version": 20,
                        "cipher_hash": 15,
                        "key_exchange": 10,
                        "certificate": 0,
                        "session_hygiene": 85,
                    },
                    component_weights={
                        "protocol_version": 0.25,
                        "cipher_hash": 0.25,
                        "key_exchange": 0.20,
                        "certificate": 0.20,
                        "session_hygiene": 0.10,
                    },
                    vetoes=[
                        VetoFindingSchema(
                            rule_id="VETO-STRIP-ATTEMPT",
                            floor_score=85,
                            evidence="STARTTLS stripped from EHLO response",
                            nist_reference="RFC 7457 / RFC 8314",
                        )
                    ],
                    effective_security_bits=128,
                    weight_redistributed=False,
                    provenance=[],
                ),
                ml_result=MLAnomalyResultSchema(
                    is_anomaly=True,
                    anomaly_score=0.82,
                    anomaly_percentile=98.5,
                    top_feature_explanations=[],
                ),
                certificates=[
                    CertificateSchema(
                        fingerprint_sha256="a" * 64,
                        spki_sha256="b" * 64,
                        subject_dn="CN=mail.enterprise.corp",
                        issuer_dn="CN=DigiCert Global Root CA",
                        serial_number="0x1234",
                        not_before=datetime(2025, 1, 1, tzinfo=UTC),
                        not_after=datetime(2027, 1, 1, tzinfo=UTC),
                        lifetime_days=730,
                        public_key_algorithm="RSA",
                        public_key_bits=2048,
                        signature_algorithm="sha256WithRSAEncryption",
                        is_self_signed=False,
                        san_dns=["mail.enterprise.corp"],
                        sct_count=2,
                    )
                ],
            ),
            SessionDetailSchema(
                id="sess-002",
                analysis_id="analysis-test-report-123",
                client_ip="192.168.1.101",
                client_port=52345,
                server_ip="10.0.0.25",
                server_port=465,
                protocol="SMTP",
                mode="IMPLICIT",
                starttls_state="S4_ENCRYPTED",
                risk_score=15.0,
                risk_band="SECURE",
                ja3=None,
                ja4=None,
                sni="secure.enterprise.corp",
                first_seen=1700000010.0,
                duration_sec=1.12,
                is_anomaly=False,
                c2s_bytes=2048,
                s2c_bytes=4096,
                risk_breakdown=None,
                ml_result=None,
            ),
        ],
        findings=[
            FindingSchema(
                id="find-001",
                session_id="sess-001",
                rule_id="VETO-STRIP-ATTEMPT",
                title="STARTTLS Stripping Attack Observed",
                description="Server EHLO response had 250-STARTTLS capability actively suppressed.",
                severity="CRITICAL",
                standards_ref="RFC 7457 §3.2 / RFC 8314",
                evidence={"diff": "- 250-STARTTLS"},
            )
        ],
    )


class TestForensicReportEngine:
    """Validate multi-format reporting, deterministic rendering, compliance, and privacy."""

    def test_byte_reproducible_pdf_rendering(
        self, sample_analysis_response: AnalysisDetailResponse
    ) -> None:
        """Two runs on identical input must produce identical PDF bytes."""
        engine = ForensicReportEngine()
        pdf_run1 = engine.generate_pdf(sample_analysis_response)
        pdf_run2 = engine.generate_pdf(sample_analysis_response)

        assert pdf_run1.startswith(b"%PDF-")
        assert len(pdf_run1) > 1000
        # Assert exact byte-for-byte reproducibility
        assert pdf_run1 == pdf_run2

    def test_json_schema_validation(
        self, sample_analysis_response: AnalysisDetailResponse, tmp_path: Path
    ) -> None:
        """JSON output must validate against published schema/pecff-analysis-1.0.0.json."""
        engine = ForensicReportEngine()
        out_file = tmp_path / "analysis.json"
        json_str = engine.generate_json(sample_analysis_response, output_path=out_file, validate=True)

        assert out_file.exists()
        parsed = json.loads(json_str)
        assert parsed["analysis_id"] == "analysis-test-report-123"
        assert parsed["overall_risk_score"] == 85.0
        assert "chain_of_custody" in parsed
        assert "chain_of_custody_digest" in parsed

    def test_csv_export(
        self, sample_analysis_response: AnalysisDetailResponse, tmp_path: Path
    ) -> None:
        """CSV export must produce spreadsheet rows matching session count."""
        engine = ForensicReportEngine()
        out_file = tmp_path / "sessions.csv"
        csv_text = engine.generate_csv(sample_analysis_response, output_path=out_file)

        assert out_file.exists()
        lines = csv_text.strip().split("\n")
        assert len(lines) == 3  # Header + 2 sessions
        assert "session_id,first_seen_iso" in lines[0]
        assert "sess-001" in lines[1]
        assert "sess-002" in lines[2]

    def test_stix2_bundle_validation(
        self, sample_analysis_response: AnalysisDetailResponse, tmp_path: Path
    ) -> None:
        """STIX 2.1 bundle must contain valid Indicator and ObservedData objects."""
        engine = ForensicReportEngine()
        out_file = tmp_path / "stix2.json"
        stix_json = engine.generate_stix2(sample_analysis_response, output_path=out_file)

        assert out_file.exists()
        parsed = json.loads(stix_json)
        assert parsed["type"] == "bundle"
        assert len(parsed["objects"]) > 0

        # Validate with stix2 library if present
        try:
            import stix2
            bundle = stix2.parse(stix_json, allow_custom=True)
            assert bundle.type == "bundle"
        except ImportError:
            pass

    def test_misp_event_export(
        self, sample_analysis_response: AnalysisDetailResponse, tmp_path: Path
    ) -> None:
        """MISP exporter must generate Event JSON with attributes and taxonomy tags."""
        engine = ForensicReportEngine()
        out_file = tmp_path / "misp.json"
        misp_json = engine.generate_misp(sample_analysis_response, output_path=out_file)

        assert out_file.exists()
        parsed = json.loads(misp_json)
        assert "Event" in parsed
        assert parsed["Event"]["threat_level_id"] == "1"
        assert len(parsed["Event"]["Attribute"]) >= 1
        assert any(t["name"] == "tlp:amber+strict" for t in parsed["Event"]["Tag"])

    def test_executive_html_template(
        self, sample_analysis_response: AnalysisDetailResponse, tmp_path: Path
    ) -> None:
        """Executive HTML must render plain-language summary without hex dumps."""
        engine = ForensicReportEngine()
        out_file = tmp_path / "executive.html"
        html = engine.generate_executive_html(sample_analysis_response, output_path=out_file)

        assert out_file.exists()
        assert "<!DOCTYPE html>" in html
        assert "Executive Cryptographic Posture Audit" in html
        assert "Plain-Language Executive Summary" in html
        assert "Top 5 Priority Remediation Actions" in html
        assert "Forensic Chain of Custody" in html

    def test_technical_html_template(
        self, sample_analysis_response: AnalysisDetailResponse, tmp_path: Path
    ) -> None:
        """Technical HTML must render FSM tables, evidence hex boxes, and limitations appendix."""
        engine = ForensicReportEngine()
        out_file = tmp_path / "technical.html"
        html = engine.generate_technical_html(sample_analysis_response, output_path=out_file)

        assert out_file.exists()
        assert "Technical Cryptographic Forensics Audit" in html
        assert "Protocol Evidence Hex Dump" in html
        assert "Appendix: Methodology, Ruleset" in html
        assert "TLS 1.3 Certificate Opacity" in html

    def test_compliance_matrix_mapping(
        self, sample_analysis_response: AnalysisDetailResponse, tmp_path: Path
    ) -> None:
        """Compliance HTML must map NIST SP 800-52r2, NIST SP 800-57, and PCI-DSS controls."""
        engine = ForensicReportEngine()
        out_file = tmp_path / "compliance.html"
        html = engine.generate_compliance_html(sample_analysis_response, output_path=out_file)

        assert out_file.exists()
        assert "Compliance" in html and "Cryptographic Standard Audit" in html
        assert "NIST SP 800-52 Rev. 2" in html
        assert "PCI-DSS v4.0" in html

        rows = evaluate_compliance_controls(sample_analysis_response.model_dump(mode="json"))
        assert len(rows) == 6
        assert any(r.control_id == "NIST-800-52r2-3.1" for r in rows)

    def test_chain_of_custody_completeness_assertion(self) -> None:
        """Missing any required chain-of-custody field must raise ChainOfCustodyValidationError."""
        # Missing pcap_sha256
        bad_custody = ChainOfCustody(
            pcap_sha256="",
            pcap_filename="capture.pcap",
            file_size=1024,
            capture_start=1700000000.0,
            capture_end=1700000060.0,
            engine_version="1.0.0",
            ruleset_version="2026.1",
            ca_bundle_sha256="c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ff",
            ml_model_id="pecff-isolationforest-v1",
            ml_model_sha256="8f9a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a",
            analysis_id="test-analysis",
            generated_at="2026-09-25T12:00:00Z",
            operator="analyst",
        )

        with pytest.raises(ChainOfCustodyValidationError):
            bad_custody.validate()

    def test_pii_redaction_and_retention(
        self, sample_analysis_response: AnalysisDetailResponse
    ) -> None:
        """Credentials and email addresses must be pseudonymized by default with salt."""
        raw_dict = sample_analysis_response.model_dump(mode="json")
        raw_dict["sessions"][0]["server_banner"] = (
            "220 mail.corp.com ESMTP AUTH PLAIN dGVzdDpQYXNzdzByZCE= for user.secret@corp.example.com"
        )

        # 1. Default Scrubbing (retain_pii=False)
        scrubbed = scrub_pii_from_analysis(raw_dict, retain_pii=False)
        assert scrubbed.pii_redacted is True
        banner_scrubbed = scrubbed.sanitized_data["sessions"][0]["server_banner"]
        assert "user.secret@corp.example.com" not in banner_scrubbed
        assert "u_" in banner_scrubbed  # Salted localpart hash
        assert "[REDACTED_CREDENTIAL" in banner_scrubbed

        # 2. Retained with Justification
        retained = scrub_pii_from_analysis(
            raw_dict,
            retain_pii=True,
            justification="Court subpoena evidentiary preservation Case #84920",
        )
        assert retained.pii_redacted is False
        banner_retained = retained.sanitized_data["sessions"][0]["server_banner"]
        assert "user.secret@corp.example.com" in banner_retained
        assert retained.sanitized_data["pii_retained"] is True

    def test_pcap_retention_sweeper(self, tmp_path: Path) -> None:
        """Sweeper should remove capture files older than retention TTL."""
        old_pcap = tmp_path / "old_capture.pcap"
        old_pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)

        # Set modification time 100 hours in the past
        past_time = datetime.now(UTC).timestamp() - (100 * 3600)
        import os

        os.utime(old_pcap, (past_time, past_time))

        sweeper = PCAPRetentionSweeper(storage_dir=tmp_path, retention_ttl_hours=72)
        removed = sweeper.sweep_expired_captures()

        assert len(removed) == 1
        assert not old_pcap.exists()

    def test_generate_all_artifacts(
        self, sample_analysis_response: AnalysisDetailResponse, tmp_path: Path
    ) -> None:
        """generate_all_artifacts should produce all 8 artifacts in output directory."""
        engine = ForensicReportEngine()
        artifacts = engine.generate_all_artifacts(sample_analysis_response, tmp_path / "out")

        assert len(artifacts) == 8
        for name, file_path in artifacts.items():
            assert file_path.exists(), f"Artifact {name} ({file_path}) was not created"
            assert file_path.stat().st_size > 0
