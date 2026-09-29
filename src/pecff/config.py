"""PECFF centralized configuration management via pydantic-settings.

All limits, buffer sizes, port sets, timeouts, and thresholds are centralized
here with zero magic numbers scattered across the codebase.
"""

from pathlib import Path
from typing import Final

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration class for the PECFF system."""

    model_config = SettingsConfigDict(
        env_prefix="PECFF_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # -------------------------------------------------------------------------
    # Ingestion & Packet Reading Constants & Limits
    # -------------------------------------------------------------------------
    max_packet_size_bytes: int = Field(
        default=262144,  # 256 KiB
        description="Maximum supported single packet size in bytes.",
    )
    min_recommended_snaplen: int = Field(
        default=262144,
        description="Threshold snaplen below which a warning is issued for truncated TLS records.",
    )
    corrupt_packet_budget_ratio: float = Field(
        default=0.05,
        description="Maximum allowed ratio of corrupt/malformed records before CaptureTooCorrupt is raised.",
    )
    sha256_chunk_size_bytes: int = Field(
        default=65536,  # 64 KiB
        description="Streaming hash chunk size in bytes to prevent reading entire file into RAM.",
    )
    reader_buffer_size_bytes: int = Field(
        default=65536,  # 64 KiB
        description="Default internal I/O stream buffer size.",
    )
    max_pcap_size_bytes: int = Field(
        default=10 * 1024 * 1024 * 1024,  # 10 GiB
        description="Hard maximum PCAP file size accepted by the ingestion pipeline.",
    )

    # -------------------------------------------------------------------------
    # TCP Stream Reassembly Memory Caps (Hard Constraint 4: Bounded Memory)
    # -------------------------------------------------------------------------
    max_flows: int = Field(
        default=200000,
        description="Maximum concurrent TCP flows tracked in flow table before LRU eviction.",
    )
    max_active_streams: int = Field(
        default=10000,
        description="Maximum number of active streams in fast lookup table.",
    )
    max_session_buffer_bytes: int = Field(
        default=8 * 1024 * 1024,  # 8 MiB across both halves
        description="Hard maximum combined buffer size for a single TCP session before payload truncation.",
    )
    max_buffer_per_stream_bytes: int = Field(
        default=4 * 1024 * 1024,  # 4 MiB per half-stream
        description="Hard ceiling on buffered payload bytes per directional TCP stream.",
    )
    ooo_cap_bytes: int = Field(
        default=2 * 1024 * 1024,  # 2 MiB
        description="Hard ceiling on out-of-order buffered payload bytes before forcing a gap.",
    )
    max_out_of_order_segments_per_stream: int = Field(
        default=500,
        description="Maximum number of unacknowledged out-of-order segments buffered per flow.",
    )
    gap_timeout_seconds: float = Field(
        default=30.0,
        description="Capture clock seconds after which an unfulfilled TCP hole is forced as a gap.",
    )
    stream_idle_timeout_seconds: float = Field(
        default=300.0,
        description="Stream inactivity duration in capture time after which stream is pruned/finalized.",
    )
    reaper_packet_interval: int = Field(
        default=1000,
        description="Invoke SessionReaper every Nth processed packet.",
    )
    max_reassembled_payload_bytes: int = Field(
        default=16 * 1024 * 1024,  # 16 MiB
        description="Maximum total reassembled application layer message size.",
    )

    # -------------------------------------------------------------------------
    # IP Defragmentation Configuration
    # -------------------------------------------------------------------------
    max_fragment_entries: int = Field(
        default=10000,
        description="Maximum concurrent IP fragmented datagrams tracked before pruning.",
    )
    fragment_timeout_seconds: float = Field(
        default=60.0,
        description="Capture clock seconds after which incomplete IP fragments are expired.",
    )

    # -------------------------------------------------------------------------
    # Network Protocol & Port Configuration
    # -------------------------------------------------------------------------
    custom_ports_path: Path = Field(
        default=Path("config/custom_ports.yaml"),
        description="Path to optional operator overrides for protocol port mapping.",
    )
    smtp_ports: list[int] = Field(
        default_factory=lambda: [25, 465, 587, 2525],
        description="TCP ports recognized as SMTP / SMTPS.",
    )
    imap_ports: list[int] = Field(
        default_factory=lambda: [143, 993],
        description="TCP ports recognized as IMAP / IMAPS.",
    )
    pop3_ports: list[int] = Field(
        default_factory=lambda: [110, 995],
        description="TCP ports recognized as POP3 / POP3S.",
    )
    implicit_tls_ports: list[int] = Field(
        default_factory=lambda: [465, 993, 995],
        description="Ports where TLS handshake begins immediately without plaintext negotiation.",
    )

    # -------------------------------------------------------------------------
    # Downgrade & Forensic Detectors Configuration
    # -------------------------------------------------------------------------
    retain_pii: bool = Field(
        default=False,
        description="When False, cleartext credentials are hashed with SHA-256 + salt; when True, raw credentials are saved (audit-logged).",
    )
    pii_salt: str = Field(
        default="pecff-forensic-salt-v1",
        description="Deployment salt for hashing cleartext authentication credentials.",
    )
    silent_failure_timeout_seconds: float = Field(
        default=10.0,
        description="Timeout in capture seconds after S2_CMD before flagging D2 SILENT_FAILURE.",
    )
    banner_mutation_threshold: int = Field(
        default=8,
        description="Levenshtein distance threshold between banners from same IP:port for D8 BANNER_MUTATION.",
    )
    mta_sts_cache_dir: Path = Field(
        default=Path("data/mta_sts_cache"),
        description="Offline cache directory for pre-synced MTA-STS and TLSA policies.",
    )

    # -------------------------------------------------------------------------
    # Cryptographic & Trust Constraints (Hard Constraint 1: Strictly Passive)
    # -------------------------------------------------------------------------
    offline_mode: bool = Field(
        default=True,
        description="Strictly passive mode; forbids any network I/O, DNS, or AIA/OCSP lookups.",
    )
    trust_store_path: Path = Field(
        default=Path("data/trust_store/cacert.pem"),
        description="Path to local offline PEM certificate bundle of trusted Root CAs.",
    )
    enterprise_roots_path: Path = Field(
        default=Path("/etc/pecff/enterprise_roots.d"),
        description="Directory containing operator enterprise root CA certificates.",
    )
    expected_interception_proxies: set[str] = Field(
        default_factory=set,
        description="Allowlist of authorized enterprise TLS inspection proxy identifiers / fingerprints.",
    )
    intermediate_cache_path: Path = Field(
        default=Path("data/intermediate_cache"),
        description="Directory containing pre-harvested intermediate CA certificates.",
    )
    crl_cache_path: Path = Field(
        default=Path("/var/lib/pecff/crl"),
        description="Directory containing pre-synced offline CRL files.",
    )
    crl_cache_dir: Path = Field(
        default=Path("data/crl_cache"),
        description="Directory containing pre-synced offline CRLs.",
    )
    max_certificates_per_chain: int = Field(
        default=20,
        description="Maximum number of certificates parsed in a single TLS certificate chain.",
    )
    min_rsa_key_bits: int = Field(
        default=2048,
        description="Minimum secure RSA key size in bits per NIST SP 800-57.",
    )
    min_ecc_key_bits: int = Field(
        default=224,
        description="Minimum secure ECC key size in bits per NIST SP 800-57.",
    )
    min_dh_group_bits: int = Field(
        default=2048,
        description="Minimum secure Diffie-Hellman group size in bits per NIST SP 800-57.",
    )

    # -------------------------------------------------------------------------
    # Deterministic Risk Scoring Thresholds (NIST SP 800-57)
    # -------------------------------------------------------------------------
    risk_score_clean_max: int = Field(
        default=20,
        description="Maximum score classified as CLEAN / LOW RISK.",
    )
    risk_score_low_max: int = Field(
        default=40,
        description="Maximum score classified as LOW RISK.",
    )
    risk_score_medium_max: int = Field(
        default=65,
        description="Maximum score classified as MEDIUM RISK.",
    )
    risk_score_high_max: int = Field(
        default=85,
        description="Maximum score classified as HIGH RISK (above is CRITICAL).",
    )

    # -------------------------------------------------------------------------
    # Machine Learning Anomaly Detection Configuration
    # -------------------------------------------------------------------------
    ml_model_path: Path = Field(
        default=Path("data/models/anomaly_detector.joblib"),
        description="Path to serialized scikit-learn anomaly detection model.",
    )
    ml_vectorizer_path: Path = Field(
        default=Path("data/models/vectorizer.joblib"),
        description="Path to serialized fitted SessionFeatureVectorizer artifact.",
    )
    ml_contamination_rate: float = Field(
        default=0.05,
        description="Contamination rate hyperparameter for Isolation Forest / LOF.",
    )
    ml_random_seed: int = Field(
        default=42,
        description="Fixed random seed ensuring deterministic ML training and inference.",
    )

    # -------------------------------------------------------------------------
    # Infrastructure & Persistence Endpoints
    # -------------------------------------------------------------------------
    database_url: str = Field(
        default="postgresql+asyncpg://pecff:pecff@localhost:5432/pecff",
        description="Async SQLAlchemy database connection URL.",
    )
    sync_database_url: str = Field(
        default="postgresql://pecff:pecff@localhost:5432/pecff",
        description="Sync SQLAlchemy database connection URL for Alembic migrations and CLI.",
    )
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL for Celery broker and caching.",
    )
    elasticsearch_url: str = Field(
        default="http://localhost:9200",
        description="Elasticsearch cluster endpoint URL.",
    )
    minio_endpoint: str = Field(
        default="localhost:9000",
        description="MinIO S3-compatible object storage host:port.",
    )
    minio_access_key: str = Field(
        default="minioadmin",
        description="MinIO access key.",
    )
    minio_secret_key: str = Field(
        default="minioadmin",
        description="MinIO secret key.",
    )
    minio_bucket_pcaps: str = Field(
        default="pecff-pcaps",
        description="MinIO bucket name for raw PCAP artifacts.",
    )
    minio_bucket_reports: str = Field(
        default="pecff-reports",
        description="MinIO bucket name for generated forensic reports.",
    )
    minio_secure: bool = Field(
        default=False,
        description="Whether to use TLS (HTTPS) when connecting to MinIO.",
    )

    # -------------------------------------------------------------------------
    # API, Auth & Security Runtime
    # -------------------------------------------------------------------------
    api_host: str = Field(default="0.0.0.0", description="FastAPI bind address.")
    api_port: int = Field(default=8000, description="FastAPI bind port.")
    api_log_level: str = Field(default="info", description="Logging level.")
    secret_key: str = Field(
        default="pecff-insecure-development-secret-key-for-jwt-signing-minimum-32b",
        description="Secret key for JWT token encoding/decoding in development.",
    )
    oidc_issuer: str | None = Field(default=None, description="Optional OIDC IdP issuer URL.")
    oidc_audience: str = Field(default="pecff-api", description="OIDC expected audience.")
    rate_limit_per_minute: int = Field(
        default=120,
        description="Maximum requests per minute allowed per authenticated principal.",
    )
    max_queue_depth: int = Field(
        default=500,
        description="Maximum Celery queue depth threshold before API returns 429 Retry-After backpressure.",
    )
    celery_task_time_limit_sec: int = Field(
        default=3600,
        description="Hard timeout for Celery forensic analysis jobs.",
    )
    celery_task_soft_time_limit_sec: int = Field(
        default=3300,
        description="Soft timeout for Celery forensic analysis jobs.",
    )
    deployment_salt: str = Field(
        default="pecff_default_deployment_salt_2026",
        description="Deployment salt for pseudonymous PII and credential hashing.",
    )


# Immutable global settings instance
settings: Final[Settings] = Settings()


def get_settings() -> Settings:
    """Return the global Settings instance."""
    return settings
