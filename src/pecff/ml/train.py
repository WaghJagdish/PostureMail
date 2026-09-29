"""Offline calibration and training pipeline for PECFF ML anomaly detection artifacts.

Trains and exports:
1. `data/models/vectorizer.joblib`: Pre-fitted SessionFeatureVectorizer with QuantileTransformer.
2. `data/models/anomaly_detector.joblib`: Pre-fitted IsolationForest anomaly model.
"""

from __future__ import annotations

import datetime
from pathlib import Path
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.utils.validation import check_is_fitted

from pecff.config import settings
from pecff.crypto.x509_parser import ParsedCertificate
from pecff.ml.features import (
    RawSessionFeatures,
    SessionFeatureExtractor,
    SessionFeatureVectorizer,
)
from pecff.parse.tls_decoder import (
    ClientHelloInfo,
    ServerHelloInfo,
    TLSExtension,
    TLSHandshakeSummary,
)


def generate_calibration_samples(n_samples: int = 200) -> list[RawSessionFeatures]:
    """Generate diverse forensic session feature instances for calibration."""
    extractor = SessionFeatureExtractor()
    rng = np.random.default_rng(settings.ml_random_seed)
    samples: list[RawSessionFeatures] = []

    now = datetime.datetime.now(datetime.UTC)
    cert_clean = ParsedCertificate(
        fingerprint_sha256="a" * 64,
        spki_sha256="b" * 64,
        serial_number="123456",
        version=3,
        subject_dn="CN=mail.example.org",
        issuer_dn="CN=Let's Encrypt Authority X3",
        not_before=now - datetime.timedelta(days=10),
        not_after=now + datetime.timedelta(days=80),
        lifetime_days=90,
        signature_algorithm_oid="1.2.840.113549.1.1.11",
        signature_hash="SHA256",
        public_key_algorithm="RSA",
        public_key_bits=2048,
        ec_curve=None,
        security_bits=112,
        is_self_signed=False,
        san_dns=["mail.example.org"],
        sct_count=2,
    )

    common_ciphers = [
        [0x1301, 0x1302, 0x1303, 0xC02F, 0xC030],
        [0xC02F, 0xC030, 0xC02B, 0xC02C],
        [0x1301, 0xC02F],
        [0xC014, 0x002F, 0x0035],  # legacy
    ]

    for i in range(n_samples):
        is_legacy = bool(i % 20 == 0)
        is_cleartext = bool(i % 40 == 0)

        dst_port = int(rng.choice([25, 465, 587, 993, 110]))
        c2s_bytes = int(rng.integers(500, 25000))
        s2c_bytes = int(rng.integers(1000, 100000))
        duration = float(rng.uniform(0.05, 4.0))

        if is_cleartext:
            hs = None
            cert = None
            risk_score = 100.0 if i % 80 == 0 else 70.0
            st_state = "S0_TCP_EST"
        else:
            ciphers = common_ciphers[3] if is_legacy else common_ciphers[i % 3]
            sel_cipher = ciphers[0]
            sel_ver = 0x0301 if is_legacy else (0x0304 if (i % 2 == 0) else 0x0303)
            risk_score = 65.0 if is_legacy else float(rng.uniform(0.0, 20.0))
            st_state = "S4_TLS_READY"

            ch_exts: dict[int, TLSExtension] = {
                0: TLSExtension(0, "server_name", 16, b"", f"mail{i % 10}.example.com"),
                10: TLSExtension(10, "supported_groups", 6, b"", [29, 23]),
                16: TLSExtension(16, "alpn", 6, b"", ["smtp"]),
            }
            sh_exts: dict[int, TLSExtension] = {}
            if sel_ver == 0x0304:
                sh_exts[51] = TLSExtension(51, "key_share", 4, b"\x00\x1d\x00\x02", 0x001D)

            ch = ClientHelloInfo(
                legacy_version=771,
                random=b"\x01" * 32,
                session_id=b"\x02" * 32,
                cipher_suites=ciphers,
                compression_methods=[0],
                extensions=ch_exts,
                supported_groups=[29, 23],
                alpn_protocols=["smtp"],
                server_name=f"mail{i % 10}.example.com",
            )
            sh = ServerHelloInfo(
                legacy_version=771,
                selected_version=sel_ver,
                random=b"\x03" * 32,
                session_id_echo=b"\x02" * 32,
                selected_cipher=sel_cipher,
                selected_compression=0,
                extensions=sh_exts,
                selected_alpn="smtp",
            )
            hs = TLSHandshakeSummary(
                client_hello=ch,
                server_hello=sh,
                certificates_der=[b"mock_der"] if sel_ver != 0x0304 else [],
                cert_analysis_possible=bool(sel_ver != 0x0304),
                handshake_completed=True,
            )
            cert = cert_clean if sel_ver != 0x0304 else None

        pkt_sizes = [int(rng.integers(64, 1500)) for _ in range(int(rng.integers(4, 20)))]
        pkt_ts = list(np.sort(rng.uniform(0.0, duration, len(pkt_sizes))))

        feat = extractor.extract_features(
            handshake_summary=hs,
            leaf_cert=cert,
            risk_score=risk_score,
            starttls_state=st_state,
            dst_port=dst_port,
            c2s_bytes=c2s_bytes,
            s2c_bytes=s2c_bytes,
            duration_sec=duration,
            pkt_sizes=pkt_sizes,
            pkt_timestamps=pkt_ts,
            src_ip_session_count=int(rng.integers(1, 10)),
            distinct_sni_count=int(rng.integers(1, 3)),
            is_periodic=bool(i % 15 == 0),
        )
        samples.append(feat)

    return samples


def train_and_save_artifacts(
    model_output_path: Path | str | None = None,
    vectorizer_output_path: Path | str | None = None,
    n_samples: int = 300,
) -> tuple[Path, Path]:
    """Calibrate vectorizer and train IsolationForest anomaly model."""
    m_path = Path(model_output_path or settings.ml_model_path)
    v_path = Path(vectorizer_output_path or settings.ml_vectorizer_path)

    m_path.parent.mkdir(parents=True, exist_ok=True)
    v_path.parent.mkdir(parents=True, exist_ok=True)

    samples = generate_calibration_samples(n_samples=n_samples)

    # 1. Fit and save Vectorizer
    vectorizer = SessionFeatureVectorizer()
    matrix = vectorizer.fit_transform(samples)
    assert matrix.shape == (n_samples, 94), f"Feature matrix shape mismatch: {matrix.shape}"
    vectorizer.save(v_path)

    # 2. Fit and save Isolation Forest
    model = IsolationForest(
        contamination=settings.ml_contamination_rate,
        random_state=settings.ml_random_seed,
        n_estimators=100,
    )
    model.fit(matrix)
    check_is_fitted(model)
    joblib.dump(model, m_path)

    return m_path, v_path


if __name__ == "__main__":
    m_p, v_p = train_and_save_artifacts()
    print(f"Artifacts successfully generated:\n  Model: {m_p}\n  Vectorizer: {v_p}")
