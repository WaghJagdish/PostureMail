"""Celery Application instance, queue topology, and task lifecycle management.

Queue Topology (§5.2):
- pecff.ingest: Capture file streaming, flow-safe shard dispatch (2 workers, concurrency=1)
- pecff.score: Parallel TCP reassembly, STARTTLS FSM tracking, NIST risk scoring (4 workers)
- pecff.ml: Unsupervised anomaly scoring with preloaded model (2 workers)
- pecff.report: Forensic PDF/HTML report generation (2 workers)
- pecff.dlq: Dead-letter queue for unrecoverable errors with full traceback capture
"""

from __future__ import annotations

import logging
from typing import Any

from celery import Celery
from celery.signals import worker_process_init
from kombu import Exchange, Queue

from pecff.config import settings

logger = logging.getLogger("pecff.tasks")

# Celery Application Instance
celery_app = Celery(
    "pecff",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["pecff.tasks.pipeline"],
)

# Define Exchanges and Queues
default_exchange = Exchange("pecff", type="direct")
dlq_exchange = Exchange("pecff.dlq", type="direct")

celery_app.conf.update(
    task_default_queue="pecff.ingest",
    task_default_exchange="pecff",
    task_default_routing_key="pecff.ingest",
    task_queues=[
        Queue(
            "pecff.ingest",
            exchange=default_exchange,
            routing_key="pecff.ingest",
            queue_arguments={"x-dead-letter-exchange": "pecff.dlq"},
        ),
        Queue(
            "pecff.score",
            exchange=default_exchange,
            routing_key="pecff.score",
            queue_arguments={"x-dead-letter-exchange": "pecff.dlq"},
        ),
        Queue(
            "pecff.ml",
            exchange=default_exchange,
            routing_key="pecff.ml",
            queue_arguments={"x-dead-letter-exchange": "pecff.dlq"},
        ),
        Queue(
            "pecff.report",
            exchange=default_exchange,
            routing_key="pecff.report",
            queue_arguments={"x-dead-letter-exchange": "pecff.dlq"},
        ),
        Queue(
            "pecff.dlq",
            exchange=dlq_exchange,
            routing_key="pecff.dlq",
        ),
    ],
    task_routes={
        "pecff.tasks.pipeline.run_forensic_pipeline": {"queue": "pecff.ingest"},
        "pecff.tasks.pipeline.parse_and_score_shard_task": {"queue": "pecff.score"},
        "pecff.tasks.pipeline.finalize_corpus_task": {"queue": "pecff.score"},
        "pecff.tasks.pipeline.ml_scoring_task": {"queue": "pecff.ml"},
        "pecff.tasks.pipeline.index_and_persist_task": {"queue": "pecff.report"},
    },
    # Task Reliability & Deadlines
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_soft_time_limit=settings.celery_task_soft_time_limit_sec,
    task_time_limit=settings.celery_task_time_limit_sec,
    worker_prefetch_multiplier=1,
    worker_max_memory_per_child=6000000,  # 6 GB memory ceiling before recycling worker
    result_serializer="json",
    task_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
)

# Global preloaded ML model and vectorizer references
_PRELOADED_ML_MODEL: Any | None = None
_PRELOADED_VECTORIZER: Any | None = None


def load_ml_model_from_disk(model_path: Path | str | None = None) -> Any | None:
    """Load and validate pre-trained ML anomaly detector model from disk.

    Performs scikit-learn fitted-model validation check. If artifact does not exist
    or is not fitted, returns None rather than silently using an unfitted instance.
    """
    from pathlib import Path
    import joblib
    from sklearn.utils.validation import check_is_fitted

    target_path = Path(model_path) if model_path is not None else settings.ml_model_path
    if not target_path.exists():
        logger.warning("ML model artifact not found at %s", target_path)
        return None

    try:
        loaded = joblib.load(target_path)
        # Unwrap dictionary if stored with metadata
        model = loaded["model"] if isinstance(loaded, dict) and "model" in loaded else loaded
        check_is_fitted(model)
        logger.info("Successfully loaded and validated pre-trained ML model from %s", target_path)
        return model
    except Exception as err:
        logger.warning("ML model validation failed for %s: %s", target_path, err)
        return None


def load_vectorizer_from_disk(vectorizer_path: Path | str | None = None) -> Any | None:
    """Load and validate pre-fitted SessionFeatureVectorizer artifact from disk.

    If artifact does not exist or is not fitted, returns None.
    """
    from pathlib import Path
    from pecff.ml.features import SessionFeatureVectorizer

    target_path = (
        Path(vectorizer_path) if vectorizer_path is not None else settings.ml_vectorizer_path
    )
    if not target_path.exists():
        logger.warning("ML vectorizer artifact not found at %s", target_path)
        return None

    try:
        vec = SessionFeatureVectorizer.load(target_path)
        logger.info("Successfully loaded pre-fitted ML vectorizer from %s", target_path)
        return vec
    except Exception as err:
        logger.warning("ML vectorizer validation failed for %s: %s", target_path, err)
        return None


@worker_process_init.connect
def preload_ml_model_in_worker(**kwargs: Any) -> None:
    """Preload pre-trained ML model and vectorizer artifacts in worker process startup."""
    global _PRELOADED_ML_MODEL, _PRELOADED_VECTORIZER
    _PRELOADED_ML_MODEL = load_ml_model_from_disk()
    _PRELOADED_VECTORIZER = load_vectorizer_from_disk()
    if _PRELOADED_ML_MODEL is not None and _PRELOADED_VECTORIZER is not None:
        logger.info(
            "Preloaded ML model and vectorizer in worker process (PID: %d)", kwargs.get("pid", 0)
        )
    else:
        logger.warning(
            "Worker process (PID: %d) ML artifacts: model=%s, vectorizer=%s",
            kwargs.get("pid", 0),
            "loaded" if _PRELOADED_ML_MODEL is not None else "missing/unfitted",
            "loaded" if _PRELOADED_VECTORIZER is not None else "missing/unfitted",
        )


def get_preloaded_ml_model() -> Any | None:
    """Access the worker process-level preloaded ML model."""
    global _PRELOADED_ML_MODEL
    if _PRELOADED_ML_MODEL is None:
        _PRELOADED_ML_MODEL = load_ml_model_from_disk()
    return _PRELOADED_ML_MODEL


def get_preloaded_vectorizer() -> Any | None:
    """Access the worker process-level preloaded vectorizer."""
    global _PRELOADED_VECTORIZER
    if _PRELOADED_VECTORIZER is None:
        _PRELOADED_VECTORIZER = load_vectorizer_from_disk()
    return _PRELOADED_VECTORIZER
