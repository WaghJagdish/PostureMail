"""SQLAlchemy 2.0 database models for forensic storage and analysis indexing.

Tables:
- analyses: High-level PCAP analysis metadata and overall risk assessment
- pcaps: Ingested capture file attributes and checksums
- sessions: Forensic TCP/TLS email flow records with JA3/JA4 fingerprints
- certificates: Deduplicated X.509 certificate repository
- session_certificates: Association table linking sessions to certificate chains
- findings: Individual rule infractions, downgrade anomalies, and security warnings
- ml_results: Unsupervised ML anomaly scores and feature vector explanations
- tasks: Asynchronous pipeline task states
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Table,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

# Cross-database JSON type (JSONB on PostgreSQL, JSON fallback elsewhere)
JsonBlob = JSON().with_variant(JSONB, "postgresql")


class Base(DeclarativeBase):
    """Base declarative class for all PECFF ORM models."""

    pass


# Join table for deduplicated Certificate to Session mapping
session_certificates = Table(
    "session_certificates",
    Base.metadata,
    Column(
        "session_id", String(64), ForeignKey("sessions.id", ondelete="CASCADE"), primary_key=True
    ),
    Column(
        "certificate_id",
        String(64),
        ForeignKey("certificates.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column("chain_position", Integer, nullable=False, default=0),  # 0 = leaf
)


class Analysis(Base):
    """Overall PCAP analysis record."""

    __tablename__ = "analyses"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    pcap_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    pcap_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        String(32), default="PENDING"
    )  # PENDING, PROCESSING, COMPLETED, FAILED
    total_packets: Mapped[int] = mapped_column(Integer, default=0)
    total_sessions: Mapped[int] = mapped_column(Integer, default=0)
    overall_risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    summary_data: Mapped[dict[str, Any]] = mapped_column(JsonBlob, default=dict)

    sessions: Mapped[list[Session]] = relationship(
        "Session", back_populates="analysis", cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship(
        "Finding", back_populates="analysis", cascade="all, delete-orphan"
    )
    ml_results: Mapped[list[MLResult]] = relationship(
        "MLResult", back_populates="analysis", cascade="all, delete-orphan"
    )


class Pcap(Base):
    """Ingested capture file archive record."""

    __tablename__ = "pcaps"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    file_format: Mapped[str] = mapped_column(String(16), nullable=False)  # pcap, pcapng
    snaplen: Mapped[int] = mapped_column(Integer, nullable=False)
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    capture_start: Mapped[float | None] = mapped_column(Float, nullable=True)
    capture_end: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class Session(Base):
    """Forensic email TCP/TLS session flow."""

    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False
    )
    client_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    client_port: Mapped[int] = mapped_column(Integer, nullable=False)
    server_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    server_port: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

    protocol: Mapped[str] = mapped_column(String(16), nullable=False)  # SMTP, IMAP, POP3
    mode: Mapped[str] = mapped_column(String(16), nullable=False)  # EXPLICIT, IMPLICIT
    protocol_detected_by: Mapped[str] = mapped_column(String(16), default="content")
    port_is_standard_mail: Mapped[bool] = mapped_column(Boolean, default=True)

    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    starttls_state: Mapped[str] = mapped_column(String(32), default="S0_TCP_EST")
    server_banner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ehlo_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)

    ja3: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    ja3s: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ja4: Mapped[str | None] = mapped_column(String(64), nullable=True)

    c2s_bytes: Mapped[int] = mapped_column(Integer, default=0)
    s2c_bytes: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[float] = mapped_column(Float, nullable=False)
    last_seen: Mapped[float] = mapped_column(Float, nullable=False)
    duration_sec: Mapped[float] = mapped_column(Float, default=0.0)

    handshake_data: Mapped[dict[str, Any]] = mapped_column(JsonBlob, default=dict)
    fsm_transitions: Mapped[list[dict[str, Any]]] = mapped_column(JsonBlob, default=list)
    quality_metrics: Mapped[dict[str, Any]] = mapped_column(JsonBlob, default=dict)

    analysis: Mapped[Analysis] = relationship("Analysis", back_populates="sessions")
    certificates: Mapped[list[Certificate]] = relationship(
        "Certificate", secondary=session_certificates, back_populates="sessions"
    )
    findings: Mapped[list[Finding]] = relationship(
        "Finding", back_populates="session", cascade="all, delete-orphan"
    )
    ml_result: Mapped[MLResult | None] = relationship(
        "MLResult", back_populates="session", uselist=False, cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("idx_sessions_analysis_risk", "analysis_id", "risk_score"),
        Index("idx_sessions_ja3", "ja3"),
    )


class Certificate(Base):
    """Deduplicated X.509 Certificate repository."""

    __tablename__ = "certificates"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    fingerprint_sha256: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    spki_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    serial_number: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=3)
    subject_dn: Mapped[str] = mapped_column(String(512), nullable=False)
    issuer_dn: Mapped[str] = mapped_column(String(512), nullable=False)
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    lifetime_days: Mapped[int] = mapped_column(Integer, default=0)

    public_key_algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    public_key_bits: Mapped[int] = mapped_column(Integer, nullable=False)
    ec_curve: Mapped[str | None] = mapped_column(String(64), nullable=True)
    signature_algorithm_oid: Mapped[str] = mapped_column(String(64), nullable=False)
    security_bits: Mapped[int] = mapped_column(Integer, default=0)
    is_self_signed: Mapped[bool] = mapped_column(Boolean, default=False)

    san_dns: Mapped[list[str]] = mapped_column(JsonBlob, default=list)
    san_ip: Mapped[list[str]] = mapped_column(JsonBlob, default=list)
    extensions_data: Mapped[dict[str, Any]] = mapped_column(JsonBlob, default=dict)
    raw_der: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    sessions: Mapped[list[Session]] = relationship(
        "Session", secondary=session_certificates, back_populates="certificates"
    )

    __table_args__ = (Index("idx_certificates_fp", "fingerprint_sha256"),)


class Finding(Base):
    """Forensic finding / rule violation record."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False
    )
    session_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=True
    )
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False
    )  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(1024), nullable=False)
    evidence_offset: Mapped[int] = mapped_column(Integer, default=0)
    evidence_bytes: Mapped[bytes] = mapped_column(LargeBinary, default=b"")
    standards_ref: Mapped[str] = mapped_column(String(255), default="")
    evidence_summary: Mapped[dict[str, Any]] = mapped_column(JsonBlob, default=dict)

    analysis: Mapped[Analysis] = relationship("Analysis", back_populates="findings")
    session: Mapped[Session | None] = relationship("Session", back_populates="findings")


class MLResult(Base):
    """Unsupervised Machine Learning anomaly scoring results."""

    __tablename__ = "ml_results"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False
    )
    session_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("sessions.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    anomaly_score: Mapped[float] = mapped_column(Float, nullable=False)
    is_outlier: Mapped[bool] = mapped_column(Boolean, default=False)
    feature_vector: Mapped[dict[str, Any]] = mapped_column(JsonBlob, default=dict)
    explanation: Mapped[dict[str, Any]] = mapped_column(JsonBlob, default=dict)

    analysis: Mapped[Analysis] = relationship("Analysis", back_populates="ml_results")
    session: Mapped[Session] = relationship("Session", back_populates="ml_result")


class Task(Base):
    """Background task execution state."""

    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    task_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="PENDING")
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    error_message: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )
