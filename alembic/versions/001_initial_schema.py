"""Initial schema with JSONB columns and forensic indices.

Revision ID: 001_initial_schema
Revises:
Create Date: 2026-09-25 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "001_initial_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. analyses
    op.create_table(
        "analyses",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("pcap_filename", sa.String(length=255), nullable=False),
        sa.Column("pcap_sha256", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="PENDING"),
        sa.Column("total_packets", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_sessions", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("overall_risk_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column(
            "summary_data", sa.JSON().with_variant(postgresql.JSONB(), "postgresql"), nullable=False
        ),
    )
    op.create_index("ix_analyses_pcap_sha256", "analyses", ["pcap_sha256"])

    # 2. pcaps
    op.create_table(
        "pcaps",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("sha256", sa.String(length=64), unique=True, nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("file_format", sa.String(length=16), nullable=False),
        sa.Column("snaplen", sa.Integer(), nullable=False),
        sa.Column("packet_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("capture_start", sa.Float(), nullable=True),
        sa.Column("capture_end", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_pcaps_sha256", "pcaps", ["sha256"])

    # 3. certificates
    op.create_table(
        "certificates",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("fingerprint_sha256", sa.String(length=64), unique=True, nullable=False),
        sa.Column("spki_sha256", sa.String(length=64), nullable=False),
        sa.Column("serial_number", sa.String(length=128), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("subject_dn", sa.String(length=512), nullable=False),
        sa.Column("issuer_dn", sa.String(length=512), nullable=False),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("not_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lifetime_days", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("public_key_algorithm", sa.String(length=32), nullable=False),
        sa.Column("public_key_bits", sa.Integer(), nullable=False),
        sa.Column("ec_curve", sa.String(length=64), nullable=True),
        sa.Column("signature_algorithm_oid", sa.String(length=64), nullable=False),
        sa.Column("security_bits", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("is_self_signed", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column(
            "san_dns", sa.JSON().with_variant(postgresql.JSONB(), "postgresql"), nullable=False
        ),
        sa.Column(
            "san_ip", sa.JSON().with_variant(postgresql.JSONB(), "postgresql"), nullable=False
        ),
        sa.Column(
            "extensions_data",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
        ),
        sa.Column("raw_der", sa.LargeBinary(), nullable=False),
    )
    op.create_index("idx_certificates_fp", "certificates", ["fingerprint_sha256"])
    op.create_index("ix_certificates_spki_sha256", "certificates", ["spki_sha256"])

    # 4. sessions
    op.create_table(
        "sessions",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column(
            "analysis_id",
            sa.String(length=64),
            sa.ForeignKey("analyses.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("client_ip", sa.String(length=64), nullable=False),
        sa.Column("client_port", sa.Integer(), nullable=False),
        sa.Column("server_ip", sa.String(length=64), nullable=False),
        sa.Column("server_port", sa.Integer(), nullable=False),
        sa.Column("vlan_id", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(length=16), nullable=False),
        sa.Column("mode", sa.String(length=16), nullable=False),
        sa.Column(
            "protocol_detected_by", sa.String(length=16), nullable=False, server_default="content"
        ),
        sa.Column("port_is_standard_mail", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column(
            "starttls_state", sa.String(length=32), nullable=False, server_default="S0_TCP_EST"
        ),
        sa.Column("server_banner", sa.String(length=255), nullable=True),
        sa.Column("ehlo_domain", sa.String(length=255), nullable=True),
        sa.Column("ja3", sa.String(length=32), nullable=True),
        sa.Column("ja3s", sa.String(length=32), nullable=True),
        sa.Column("ja4", sa.String(length=64), nullable=True),
        sa.Column("c2s_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("s2c_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("first_seen", sa.Float(), nullable=False),
        sa.Column("last_seen", sa.Float(), nullable=False),
        sa.Column("duration_sec", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column(
            "handshake_data",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "fsm_transitions",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "quality_metrics",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
        ),
    )
    op.create_index("ix_sessions_client_ip", "sessions", ["client_ip"])
    op.create_index("ix_sessions_server_ip", "sessions", ["server_ip"])
    op.create_index("ix_sessions_server_port", "sessions", ["server_port"])
    op.create_index("ix_sessions_risk_score", "sessions", ["risk_score"])
    op.create_index("idx_sessions_analysis_risk", "sessions", ["analysis_id", "risk_score"])
    op.create_index("idx_sessions_ja3", "sessions", ["ja3"])

    # 5. session_certificates (join table)
    op.create_table(
        "session_certificates",
        sa.Column(
            "session_id",
            sa.String(length=64),
            sa.ForeignKey("sessions.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "certificate_id",
            sa.String(length=64),
            sa.ForeignKey("certificates.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("chain_position", sa.Integer(), nullable=False, server_default="0"),
    )

    # 6. findings
    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column(
            "analysis_id",
            sa.String(length=64),
            sa.ForeignKey("analyses.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "session_id",
            sa.String(length=64),
            sa.ForeignKey("sessions.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.String(length=1024), nullable=False),
        sa.Column("evidence_offset", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("evidence_bytes", sa.LargeBinary(), nullable=False),
        sa.Column("standards_ref", sa.String(length=255), nullable=False, server_default=""),
        sa.Column(
            "evidence_summary",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
        ),
    )
    op.create_index("ix_findings_rule_id", "findings", ["rule_id"])

    # 7. ml_results
    op.create_table(
        "ml_results",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column(
            "analysis_id",
            sa.String(length=64),
            sa.ForeignKey("analyses.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "session_id",
            sa.String(length=64),
            sa.ForeignKey("sessions.id", ondelete="CASCADE"),
            unique=True,
            nullable=False,
        ),
        sa.Column("anomaly_score", sa.Float(), nullable=False),
        sa.Column("is_outlier", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column(
            "feature_vector",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "explanation", sa.JSON().with_variant(postgresql.JSONB(), "postgresql"), nullable=False
        ),
    )

    # 8. tasks
    op.create_table(
        "tasks",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("task_type", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="PENDING"),
        sa.Column("progress", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("error_message", sa.String(length=1024), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("tasks")
    op.drop_table("ml_results")
    op.drop_table("findings")
    op.drop_table("session_certificates")
    op.drop_table("sessions")
    op.drop_table("certificates")
    op.drop_table("pcaps")
    op.drop_table("analyses")
