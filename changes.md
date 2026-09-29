# PostureMail (PECFF) - Changelog & Audit Fixes

This document provides a complete, forensic record of all modifications, bug fixes, and architectural refinements implemented in **PostureMail** (Passive Email Cryptographic Forensics Framework).

---

## Phase 1: SIH Correctness, Dataflow Wiring & Trustworthy Forensics

### 1. Pre-Trained ML Model Loading & Fitted Validation
- **Problem:** `celery_app.preload_ml_model_in_worker()` was instantiating an un-fitted `IsolationForest()` instance on worker startup. When inference ran, calling `.score_samples()` threw `NotFittedError`, which was silently swallowed by an unhandled `except Exception` block, leaving `s["is_anomaly"] = False` and `s["ml_result"] = None`.
- **Fix:**
  - Implemented `load_ml_model_from_disk(settings.ml_model_path)` in `src/pecff/tasks/celery_app.py`.
  - Added scikit-learn fitted-model validation check via `check_is_fitted(model)`.
  - Added explicit degradation mode: if the pre-trained artifact is missing or unfitted, `ml_scoring_task` in `src/pecff/tasks/pipeline.py` updates the task state to `"ML anomaly scoring DEGRADED: pre-trained model or vectorizer artifact unavailable"`, marks `s["is_anomaly"] = False` and `s["ml_result"] = None`, and logs an explicit warning rather than masking errors or claiming successful ML inference.
  - Generated calibrated baseline model artifacts at `data/models/anomaly_detector.joblib` via `src/pecff/ml/train.py`.

### 2. Decoupled Feature Vectorizer Preprocessing (Eliminating Auto-Fitting Leakage)
- **Problem:** `SessionFeatureVectorizer.transform()` in `src/pecff/ml/features.py` checked `if not self._is_fitted:` and automatically executed `.fit()` on the current inference batch. For small PCAPs with fewer than 100 sessions, `QuantileTransformer` raised warnings (`n_quantiles > n_samples`), leaked inference data into preprocessing parameters, and introduced train/test contamination.
- **Fix:**
  - Removed auto-fitting logic from `SessionFeatureVectorizer.transform()`.
  - Calling `transform()` on an unfitted vectorizer now strictly raises `sklearn.exceptions.NotFittedError`.
  - Added explicit `fit_transform()`, `save()`, and `load()` methods on `SessionFeatureVectorizer`.
  - Added `ml_vectorizer_path` to centralized `Settings` in `src/pecff/config.py`.
  - Implemented pre-fitted vectorizer loading in Celery workers via `load_vectorizer_from_disk()`.
  - Saved fitted vectorizer artifact at `data/models/vectorizer.joblib`.
  - Enforced exact 94-dimensional matrix output invariant `(N, 94)`.

### 3. TLS Handshake $\rightarrow$ ML Pipeline Dataflow
- **Problem:** `ml_scoring_task` in `src/pecff/tasks/pipeline.py` previously invoked `extractor.extract_features(handshake_summary=None, ...)`. Because Celery tasks pass JSON-serializable dictionaries across worker boundaries, the decoded `TLSHandshakeSummary` was discarded after the shard task. Consequently, all 32 fingerprint hash bins, cipher profiles, SNI, ALPN, and extension profiles were computed from empty defaults.
- **Fix:**
  - Implemented `serialize_handshake_summary(summary)` and `deserialize_handshake_summary(data)` in `src/pecff/tasks/pipeline.py`.
  - Serialized ClientHello, ServerHello, extension lists, selected ciphers, and certificate DERs into the session dictionary (`s["tls_handshake"]`).
  - In `ml_scoring_task`, reconstructed `TLSHandshakeSummary` and `ParsedCertificate` (via `X509Parser.parse_der`), passing real handshake metadata to `SessionFeatureExtractor.extract_features()`.
  - Wired session `risk_score` directly into `raw.deterministic_risk_score`.

### 4. TLS $\rightarrow$ NIST SP 800-57 Risk Engine Dataflow
- **Problem:** In `parse_and_score_shard_task`, `SessionCryptoParameters` was instantiated with only `protocol_version`, `dst_port`, `handshake_completed`, and `cert_analysis_possible`. Real negotiated cipher suite IDs, key exchange algorithms, named groups, leaf certificates, and session hygiene flags were omitted. Consequently:
  - **Component C2 (Cipher & Hash):** Always evaluated to 0 (clean), even for weak 3DES, RC4, or NULL ciphers.
  - **Component C3 (Key Exchange):** Always evaluated to 0.
  - **Component C4 (Certificate):** Leaf certificates were never passed or validated.
  - **Component C5 (Session Hygiene):** Hygiene extension flags were never checked.
- **Fix:**
  - Populated `SessionCryptoParameters` with real fields:
    - `cipher_id` (e.g., `0xC02F`, `0x000A`) and `cipher_info` retrieved from `cipher_db` $\rightarrow$ activates C2 risk evaluation.
    - `kex_algorithm` and `named_group` resolved from ServerHello key_share / ClientHello supported groups using `NAMED_GROUP_MAP` $\rightarrow$ activates C3 risk evaluation.
    - `leaf_certificate` parsed via `X509Parser.parse_der(tls_summary.certificates_der[0])` $\rightarrow$ activates C4 certificate evaluation.
    - `encrypt_then_mac`, `extended_master_secret`, and `secure_renegotiation` flags $\rightarrow$ activates C5 hygiene evaluation.
  - Aligned standalone CLI analyzer in `src/pecff/cli.py` with identical parameter extraction.

### 5. Extended TLS Protocol Version Mapping & `PROTO-UNKNOWN` Penalty
- **Problem:** Protocol version resolution used a binary check: if `selected_version == 0x0304` then `"TLS 1.3"`, else `"TLS 1.2"`. Deprecated versions like SSL 3.0, TLS 1.0, and TLS 1.1, as well as unknown or experimental versions, were misclassified as TLS 1.2.
- **Fix:**
  - Defined explicit version mapping table `TLS_VERSION_MAP` supporting `0x0200` (SSL 2.0), `0x0300` (SSL 3.0), `0x0301` (TLS 1.0), `0x0302` (TLS 1.1), `0x0303` (TLS 1.2), and `0x0304` (TLS 1.3).
  - Unrecognized versions are mapped to `UNKNOWN (0xXXXX)`.
  - Added `unknown_version` rule (`PROTO-UNKNOWN`, penalty 70) to `C1_RULES` in `src/pecff/crypto/risk_engine.py` so unknown versions are penalized rather than silently treated as secure.

### 6. STARTTLS Cleartext Credential Observation & Context Multiplier
- **Problem:** `StarttlsFSM` tracked `fsm.credentials_in_cleartext` and `fsm.auth_mechanisms_used`, but these attributes were never passed to `SessionCryptoParameters`. As a result, observed plaintext passwords never triggered the NIST risk multiplier $\Omega = 1.25$ or the mandatory categorical floor veto (`PROTO-NO-TLS-AUTH`).
- **Fix:**
  - Extracted `fsm.credentials_in_cleartext` and `fsm.auth_mechanisms_used` in both `pipeline.py` and `cli.py`.
  - Passed `cleartext_credentials_observed` and `has_auth` into `SessionCryptoParameters`.
  - Stored `server_banner` and `ehlo_domain` in session dictionaries for forensics.
  - Correctly triggers $\Omega = 1.25$ context multiplier and score 100 veto (`PROTO-NO-TLS-AUTH`) when cleartext credentials are observed on unencrypted streams.

### 7. PCAP Sharding Optimization for SIH Evaluation
- **Problem:** Celery dispatched 4 shard tasks per PCAP (`num_shards = 4`). Each worker reopened and read the entire capture file from disk from byte 0 to EOF, multiplying disk I/O four-fold ($4\times$) while discarding $75\%$ of packets per worker.
- **Fix:**
  - Set default `num_shards = 1` in `run_forensic_pipeline` (`src/pecff/tasks/pipeline.py`), eliminating redundant multi-worker disk passes during live evaluation while preserving the complete Celery canvas chord architecture.

### 8. Canonical 5-Tuple + VLAN Flow Hash
- **Problem:** The previous shard filter in `parse_and_score_shard_task` hashed only IP addresses (`zlib.crc32(min(src_ip, dst_ip) + max(src_ip, dst_ip))`). Ports, VLAN tags, and protocols were ignored, causing distinct TCP flows between the same host pair to collide and risk state corruption.
- **Fix:**
  - Implemented `compute_canonical_flow_hash(payload, vlan_id)` in `src/pecff/tasks/pipeline.py`:
    $$\text{CRC32}(\min(\text{ep}_a, \text{ep}_b) + \max(\text{ep}_a, \text{ep}_b) + \text{protocol} + \text{VLAN})$$
  - Matches `StreamReassembler.FlowKey` exactly, guaranteeing bidirectional symmetry ($A \rightarrow B$ and $B \rightarrow A$ produce identical hashes) and port-level isolation.

### 9. Offline Model Calibration & Training Utility
- **File:** `src/pecff/ml/train.py`
- Implemented an offline calibration utility that synthesizes representative baseline mail sessions, extracts 94-dimensional feature vectors, fits the `SessionFeatureVectorizer`, trains an `IsolationForest`, verifies fitted state via `check_is_fitted()`, and exports production artifacts to `data/models/`.

### 10. Focused Phase 1 Regression Suite
- **File:** `tests/regression/test_phase1_fixes.py`
- Implemented 12 comprehensive unit and integration tests covering:
  - TLS version mapping table and `PROTO-UNKNOWN` penalty.
  - Cipher suite propagation to Component C2.
  - STARTTLS cleartext credential propagation to $\Omega = 1.25$ and score 100 veto.
  - TLS handshake serialization and deserialization roundtrip.
  - Pre-trained ML inference and explicit degradation on missing artifacts.
  - Feature vectorizer 94-dimensional shape invariant and `NotFittedError` enforcement.
  - Canonical 5-tuple + VLAN flow hash symmetry across packet directions.

---

## Phase 0: Initial Frontend & API Correctness Fixes

Prior to the deep audit, 8 application-level frontend and API issues were identified and resolved:
1. **Session Detail Modal Mapping:** Fixed frontend attribute mismatch between backend API responses and React component state.
2. **Analysis Progress Polling:** Resolved Celery task state polling stall by synchronizing task IDs between upload responses and state stores.
3. **Canvas Pipeline Chord Assembly:** Fixed Celery chord signature to properly pass intermediate shard results to `finalize_corpus_task`.
4. **MinIO Local Storage Fallback:** Ensured robust fallback to local disk storage (`data/storage/`) when MinIO S3 is offline or unreachable.
5. **NIST Finding Severity Mapping:** Aligned backend severity strings (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) with frontend badge renderers.
6. **Feature Store Parquet Persistence:** Fixed schema column ordering when persisting partitioned Parquet tables under `data/features/{analysis_id}/`.
7. **Forensic Report Generation:** Resolved WeasyPrint / ReportLab PDF generation formatting for offline audit reports.
8. **JWT Authentication & Token Persistence:** Ensured token headers are retained across page reloads in the React dashboard.
