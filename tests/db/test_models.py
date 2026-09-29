"""Unit tests for database models, cascades, and relational schemas."""

from __future__ import annotations

import datetime

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session as DBSession
from sqlalchemy.orm import sessionmaker

from pecff.db.models import (
    Analysis,
    Base,
    Certificate,
    Finding,
    MLResult,
    Pcap,
    Session,
    Task,
)


class TestDatabaseModels:
    """Validate SQLite / PostgreSQL relational schema creation and cascade behaviors."""

    def test_schema_creation_and_relations(self) -> None:
        # Use in-memory SQLite engine for fast isolation testing
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)

        session_factory = sessionmaker(bind=engine)
        db: DBSession = session_factory()

        now = datetime.datetime.now(datetime.UTC)

        # 1. Create Analysis and Pcap
        pcap = Pcap(
            id="pcap_001",
            filename="capture.pcap",
            sha256="a" * 64,
            size_bytes=10240,
            file_format="pcap",
            snaplen=65535,
            packet_count=100,
        )
        analysis = Analysis(
            id="analysis_001",
            pcap_filename="capture.pcap",
            pcap_sha256="a" * 64,
            status="COMPLETED",
            total_packets=100,
            total_sessions=1,
            overall_risk_score=25.0,
            summary_data={"notes": "clean capture"},
        )
        db.add_all([pcap, analysis])
        db.commit()

        # 2. Create Certificate
        cert = Certificate(
            id="cert_001",
            fingerprint_sha256="b" * 64,
            spki_sha256="c" * 64,
            serial_number="123456",
            version=3,
            subject_dn="CN=mail.example.com",
            issuer_dn="CN=mail.example.com",
            not_before=now,
            not_after=now + datetime.timedelta(days=365),
            lifetime_days=365,
            public_key_algorithm="RSA",
            public_key_bits=2048,
            signature_algorithm_oid="1.2.840.113549.1.1.11",
            security_bits=112,
            is_self_signed=True,
            raw_der=b"DER_BYTES",
        )
        db.add(cert)
        db.commit()

        # 3. Create Session with joined Certificate
        sess = Session(
            id="sess_001",
            analysis_id=analysis.id,
            client_ip="192.168.1.100",
            client_port=49152,
            server_ip="192.168.1.10",
            server_port=25,
            protocol="SMTP",
            mode="EXPLICIT",
            risk_score=25.0,
            first_seen=1000.0,
            last_seen=1005.0,
            ja3="d" * 32,
        )
        sess.certificates.append(cert)

        # 4. Create Finding and ML Result
        finding = Finding(
            id="find_001",
            analysis_id=analysis.id,
            session_id=sess.id,
            rule_id="WEAK_CIPHER",
            severity="MEDIUM",
            title="Weak Cipher Suite",
            description="3DES cipher negotiated",
        )
        ml = MLResult(
            id="ml_001",
            analysis_id=analysis.id,
            session_id=sess.id,
            anomaly_score=0.85,
            is_outlier=True,
            feature_vector={"feat1": 1.0},
            explanation={"top_feat": "duration"},
        )
        task = Task(
            id="task_001",
            task_type="PCAP_INGEST",
            status="SUCCESS",
            progress=1.0,
        )

        db.add_all([sess, finding, ml, task])
        db.commit()

        # 5. Query and Assert
        stmt = select(Analysis).where(Analysis.id == "analysis_001")
        retrieved_analysis = db.scalar(stmt)
        assert retrieved_analysis is not None
        assert len(retrieved_analysis.sessions) == 1
        assert len(retrieved_analysis.findings) == 1
        assert len(retrieved_analysis.ml_results) == 1

        retrieved_sess = retrieved_analysis.sessions[0]
        assert len(retrieved_sess.certificates) == 1
        assert retrieved_sess.certificates[0].subject_dn == "CN=mail.example.com"
        assert retrieved_sess.ml_result is not None
        assert retrieved_sess.ml_result.is_outlier is True

        db.close()
