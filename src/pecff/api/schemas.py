"""Pydantic v2 schemas for the PECFF REST API and forensic output specification §5.1.

Requirements:
- Versioned analysis document: schema_version is required in every analysis output.
- JSON Schema artifact generator for schema/pecff-analysis-1.0.0.json.
- Full type fidelity for session lists, cursor pagination, task tracking, and audit events.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

CURRENT_SCHEMA_VERSION = "1.0.0"


class BaseSchema(BaseModel):
    """Base schema enabling standard serialization options."""

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        use_enum_values=True,
    )


# -----------------------------------------------------------------------------
# Upload & Ingestion Schemas
# -----------------------------------------------------------------------------
class PcapUploadResponse(BaseSchema):
    """HTTP 202 / 200 Upload ingestion response."""

    analysis_id: str = Field(description="Unique UUID for this analysis execution.")
    task_id: str = Field(description="Celery asynchronous pipeline task identifier.")
    sha256: str = Field(description="Hexadecimal SHA-256 digest of uploaded PCAP artifact.")
    status_url: str = Field(description="Polling endpoint for progress and state updates.")
    duplicate_of: str | None = Field(
        default=None,
        description="If hash already exists in repository, ID of existing analysis.",
    )
    is_duplicate: bool = Field(
        default=False,
        description="Whether this upload was deduplicated against an existing archive.",
    )


class PresignedUploadRequest(BaseSchema):
    """Request for direct-to-object-storage upload for large capture files."""

    filename: str = Field(description="Target PCAP/PCAPNG capture filename.")
    size_bytes: int = Field(gt=0, description="Exact file size in bytes.")
    sha256: str | None = Field(default=None, description="Optional anticipated SHA-256 checksum.")


class PresignedUploadResponse(BaseSchema):
    """Presigned PUT URL for direct MinIO/S3 ingestion."""

    upload_url: str = Field(description="Time-limited presigned S3 PUT URL.")
    file_key: str = Field(description="Assigned storage key in object bucket.")
    expires_in_seconds: int = Field(default=3600, description="Validity period of presigned URL.")
    analysis_id: str = Field(description="Pre-allocated analysis identifier.")


# -----------------------------------------------------------------------------
# Task Tracking & WebSocket Streaming Schemas
# -----------------------------------------------------------------------------
TaskState = Literal["PENDING", "PARSING", "SCORING", "SCORING_ML", "SUCCESS", "FAILURE", "REVOKED"]


class TaskStatusResponse(BaseSchema):
    """Real-time task tracking status payload."""

    task_id: str = Field(description="Celery task identifier.")
    state: TaskState = Field(description="Current pipeline execution state.")
    progress: float = Field(
        ge=0.0, le=1.0, default=0.0, description="Normalized progress fraction 0.0 to 1.0."
    )
    stage_detail: str = Field(
        default="", description="Human-readable description of active pipeline stage."
    )
    packets_processed: int = Field(default=0, description="Number of packets parsed so far.")
    total_packets: int | None = Field(default=None, description="Total packet count if known.")
    eta_seconds: float | None = Field(
        default=None, description="Estimated time remaining in seconds."
    )
    error: str | None = Field(default=None, description="Error message if state is FAILURE.")
    analysis_id: str | None = Field(
        default=None, description="Resulting analysis ID upon completion."
    )


class TaskStreamEvent(BaseSchema):
    """WebSocket event frame for live progress streaming."""

    event: Literal["progress", "state_change", "complete", "error"]
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    payload: TaskStatusResponse


# -----------------------------------------------------------------------------
# Forensic Evidence & Output Document Schemas (§5.1)
# -----------------------------------------------------------------------------
class ProvenanceItemSchema(BaseSchema):
    """Individual cryptographic finding evidence item with standards citation."""

    component: str = Field(description="Evaluated risk component.")
    rule_id: str = Field(description="Unique rule identifier (e.g. PROTO-SSL3).")
    penalty: int = Field(description="Numerical risk penalty applied.")
    evidence: str = Field(description="Forensic observation triggering this penalty.")
    nist_reference: str = Field(description="Official NIST SP 800-57 or RFC section reference.")


class VetoFindingSchema(BaseSchema):
    """Categorical risk floor veto item."""

    rule_id: str = Field(description="Veto rule identifier.")
    floor_score: int = Field(description="Minimum categorical floor score.")
    evidence: str = Field(description="Observed catastrophic flaw.")
    nist_reference: str = Field(description="Authoritative standard reference.")


class RiskResultSchema(BaseSchema):
    """Deterministic NIST SP 800-57 risk score breakdown."""

    score: int = Field(ge=0, le=100, description="Deterministic risk score 0 to 100.")
    band: str = Field(description="Risk band: SECURE, ACCEPTABLE, WEAK, HIGH, or CRITICAL.")
    context_multiplier: float = Field(description="Context multiplier OMEGA applied.")
    component_scores: dict[str, int] = Field(description="Raw component score breakdown.")
    component_weights: dict[str, float] = Field(description="Applied weights summing to 1.0.")
    vetoes: list[VetoFindingSchema] = Field(
        default_factory=list, description="Triggered veto floors."
    )
    effective_security_bits: int = Field(description="Effective security strength S_eff bits.")
    weight_redistributed: bool = Field(description="Whether TLS 1.3 cert weight was redistributed.")
    provenance: list[ProvenanceItemSchema] = Field(
        default_factory=list, description="Auditable provenance items."
    )


class FindingSchema(BaseSchema):
    """Specific vulnerability, downgrade, or anomaly finding."""

    id: str = Field(description="Finding unique ID.")
    session_id: str = Field(description="Associated TCP flow session ID.")
    rule_id: str = Field(description="Rule identifier.")
    title: str = Field(description="Concise human-readable finding title.")
    description: str = Field(description="Detailed forensic explanation.")
    severity: str = Field(description="Finding severity: INFO, LOW, MEDIUM, HIGH, CRITICAL.")
    standards_ref: str = Field(description="RFC / NIST SP standard reference.")
    evidence: dict[str, Any] = Field(default_factory=dict, description="Raw protocol evidence.")


class CertificateSchema(BaseSchema):
    """Parsed X.509 certificate forensic record."""

    fingerprint_sha256: str = Field(description="SHA-256 fingerprint of DER certificate.")
    spki_sha256: str = Field(description="SHA-256 of Subject Public Key Info.")
    subject_dn: str = Field(description="Subject Distinguished Name.")
    issuer_dn: str = Field(description="Issuer Distinguished Name.")
    serial_number: str = Field(description="Hexadecimal/decimal serial number.")
    not_before: datetime = Field(description="Validity start timestamp.")
    not_after: datetime = Field(description="Validity expiration timestamp.")
    lifetime_days: int = Field(description="Total validity lifetime in days.")
    public_key_algorithm: str = Field(description="RSA, ECDSA, Ed25519, etc.")
    public_key_bits: int = Field(description="Key modulus or curve bit size.")
    signature_algorithm: str = Field(description="Signature algorithm OID or name.")
    is_self_signed: bool = Field(description="Whether certificate is self-signed.")
    san_dns: list[str] = Field(
        default_factory=list, description="Subject Alternative Name DNS list."
    )
    sct_count: int = Field(default=0, description="Certificate Transparency SCT count.")


class MLAnomalyResultSchema(BaseSchema):
    """Unsupervised machine learning anomaly detection score."""

    is_anomaly: bool = Field(description="Whether session is flagged as an outlier.")
    anomaly_score: float = Field(description="Raw anomaly decision score.")
    anomaly_percentile: float = Field(description="Empirical anomaly percentile 0-100.")
    top_feature_explanations: list[dict[str, Any]] = Field(
        default_factory=list, description="Top contributing feature deviations."
    )
    is_experimental: bool = Field(
        default=True, description="Experimental flag indicating ML is isolated from primary verdict."
    )


class TemporalBehaviorSchema(BaseSchema):
    """Explainable temporal beaconing and automated timing behavior candidate."""

    classification: str = Field(
        default="INSUFFICIENT_DATA",
        description="Temporal classification: NORMAL, SUSPICIOUS_TIMING, BEACON_CANDIDATE, INSUFFICIENT_DATA.",
    )
    behavior_score: int = Field(default=0, ge=0, le=100, description="Temporal regularity score 0-100.")
    mean_interval: float | None = Field(default=None, description="Mean recurrence period in seconds.")
    std_interval: float | None = Field(default=None, description="Standard deviation of intervals in seconds.")
    cv: float | None = Field(default=None, description="Coefficient of variation (std/mean).")
    jitter_pct: float | None = Field(default=None, description="Jitter percentage.")
    duration: float = Field(default=0.0, description="Observed communication duration in seconds.")
    event_count: int = Field(default=0, description="Total observed communication events in group.")
    explanation: list[str] = Field(default_factory=list, description="Step-by-step evidence reasons.")
    analyst_note: str = Field(
        default="",
        description="Analyst context note emphasizing that timing alone does not establish malicious activity.",
    )


class SessionSummarySchema(BaseSchema):
    """Summary record for session listing and cursor pagination."""

    id: str = Field(description="Unique session identifier.")
    analysis_id: str = Field(description="Parent analysis execution ID.")
    client_ip: str = Field(description="Client IP address.")
    client_port: int = Field(description="Client TCP port.")
    server_ip: str = Field(description="Server IP address.")
    server_port: int = Field(description="Server TCP port.")
    protocol: str = Field(description="SMTP, IMAP, or POP3.")
    mode: str = Field(description="EXPLICIT or IMPLICIT.")
    starttls_state: str = Field(description="Final STARTTLS state (S0-S4).")
    risk_score: float = Field(description="NIST SP 800-57 risk score (0-100).")
    risk_band: str = Field(description="SECURE, ACCEPTABLE, WEAK, HIGH, CRITICAL.")
    ja3: str | None = Field(default=None, description="Client JA3 fingerprint hash.")
    ja4: str | None = Field(default=None, description="Client JA4 fingerprint.")
    sni: str | None = Field(default=None, description="SNI server hostname.")
    first_seen: float = Field(description="First packet capture timestamp (epoch).")
    duration_sec: float = Field(description="TCP session duration in seconds.")
    is_anomaly: bool = Field(default=False, description="ML anomaly flag.")
    temporal_classification: str | None = Field(
        default=None, description="Temporal behavior classification: BEACON_CANDIDATE, SUSPICIOUS_TIMING, NORMAL, INSUFFICIENT_DATA."
    )


class SessionDetailSchema(SessionSummarySchema):
    """Comprehensive forensic session detail."""

    c2s_bytes: int = Field(default=0, description="Client to server payload bytes.")
    s2c_bytes: int = Field(default=0, description="Server to client payload bytes.")
    ja3s: str | None = Field(default=None, description="Server JA3S fingerprint hash.")
    server_banner: str | None = Field(default=None, description="Observed mail server banner.")
    ehlo_domain: str | None = Field(default=None, description="Observed EHLO/HELO domain name.")
    risk_breakdown: RiskResultSchema | None = Field(
        default=None, description="Detailed risk audit."
    )
    ml_result: MLAnomalyResultSchema | None = Field(
        default=None, description="ML anomaly breakdown (experimental)."
    )
    temporal_behavior: TemporalBehaviorSchema | None = Field(
        default=None, description="Explainable temporal behavior evidence."
    )
    certificates: list[CertificateSchema] = Field(
        default_factory=list, description="Certificate chain."
    )
    findings: list[FindingSchema] = Field(
        default_factory=list, description="Detected security findings."
    )


class CursorPaginatedSessions(BaseSchema):
    """Cursor-based server-side pagination response."""

    items: list[SessionSummarySchema] = Field(description="Page session records.")
    next_cursor: str | None = Field(
        default=None, description="Opaque cursor string for fetching the next page."
    )
    has_more: bool = Field(description="Whether additional records exist beyond this page.")
    total_count: int = Field(description="Total matched sessions across all pages.")


class AnalysisDetailResponse(BaseSchema):
    """Complete forensic analysis output document conforming to §5.1 specification."""

    schema_version: str = Field(
        default=CURRENT_SCHEMA_VERSION, description="PECFF analysis schema specification version."
    )
    analysis_id: str = Field(description="Unique analysis UUID.")
    created_at: datetime = Field(description="Analysis generation timestamp.")
    pcap_filename: str = Field(description="Original capture file name.")
    pcap_sha256: str = Field(description="SHA-256 digest of analyzed capture file.")
    status: str = Field(description="Analysis status: PENDING, PROCESSING, COMPLETED, FAILED.")
    total_packets: int = Field(description="Total processed packet count.")
    total_sessions: int = Field(description="Total reconstructed mail sessions.")
    overall_risk_score: float = Field(description="Corpus-level aggregated risk score.")
    overall_risk_band: str = Field(description="Aggregated risk band.")
    summary_data: dict[str, Any] = Field(
        default_factory=dict, description="Corpus summary metrics."
    )
    sessions: list[SessionDetailSchema] = Field(
        default_factory=list, description="Reconstructed sessions."
    )
    findings: list[FindingSchema] = Field(default_factory=list, description="Corpus-wide findings.")


# -----------------------------------------------------------------------------
# Verdict & Audit Logging Schemas
# -----------------------------------------------------------------------------
class VerdictSubmissionRequest(BaseSchema):
    """Analyst verdict and forensic ground-truth submission."""

    verdict: Literal["BENIGN", "SUSPICIOUS", "MALICIOUS", "POLICY_VIOLATION"]
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    notes: str = Field(default="", max_length=4096)
    tags: list[str] = Field(default_factory=list)


class VerdictSubmissionResponse(BaseSchema):
    """Verdict confirmation payload."""

    verdict_id: str
    session_id: str
    analyst_id: str
    submitted_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    verdict: str
    status: str = "RECORDED"


class AuditLogEntrySchema(BaseSchema):
    """Security audit event log entry."""

    id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    principal: str
    role: str
    action: str  # "upload", "generate_report", "submit_verdict", "retrieve_pii"
    resource_id: str
    ip_address: str | None = None
    status_code: int = 200
    details: dict[str, Any] = Field(default_factory=dict)


def export_json_schema(output_path: Path | None = None) -> Path:
    """Export the Pydantic v2 JSON Schema for §5.1 output specification to a file."""
    target_path = output_path or (
        Path(__file__).resolve().parent.parent.parent.parent
        / "schema"
        / f"pecff-analysis-{CURRENT_SCHEMA_VERSION}.json"
    )
    target_path.parent.mkdir(parents=True, exist_ok=True)
    schema_dict = AnalysisDetailResponse.model_json_schema()
    with open(target_path, "w", encoding="utf-8") as f:
        json.dump(schema_dict, f, indent=2)
    return target_path
