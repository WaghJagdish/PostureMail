"""PCAP and PCAPNG upload and ingestion router.

Endpoints:
- POST /api/v1/pcaps: Streams multipart upload directly to MinIO, computes SHA-256 on the fly,
  validates magic bytes, checks for deduplication, and enqueues asynchronous analysis pipeline.
- POST /api/v1/pcaps/presign: Generates a presigned S3 PUT URL for files > 2 GiB.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, Request, Response, UploadFile, status

from pecff.api.deps import StorageService, get_storage_service
from pecff.api.schemas import PcapUploadResponse, PresignedUploadRequest, PresignedUploadResponse
from pecff.api.security import (
    AuthenticatedUser,
    check_rate_limit_and_backpressure,
    record_audit_log,
    require_role,
)
from pecff.config import settings

router = APIRouter(prefix="/api/v1/pcaps", tags=["PCAP Ingestion"])

# Valid PCAP / PCAPNG Magic Bytes
VALID_MAGIC_BYTES = {
    b"\xa1\xb2\xc3\xd4",  # Classic PCAP (microsecond, big endian)
    b"\xd4\xc3\xb2\xa1",  # Classic PCAP (microsecond, little endian)
    b"\xa1\xb2\x3c\x4d",  # Classic PCAP (nanosecond, big endian)
    b"\x4d\x3c\xb2\xa1",  # Classic PCAP (nanosecond, little endian)
    b"\x0a\x0d\x0d\x0a",  # PCAPNG Section Header Block
}

# In-memory deduplication index for fast checking across sessions/analyses
_DEDUPLICATED_PCAPS: dict[str, str] = {}


@router.post(
    "",
    response_model=PcapUploadResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Upload and ingest a PCAP/PCAPNG capture file with streaming SHA-256 hashing",
)
async def upload_pcap(
    request: Request,
    response: Response,
    file: Annotated[UploadFile, File(description="PCAP or PCAPNG network capture file")],
    storage: StorageService = Depends(get_storage_service),
    current_user: AuthenticatedUser = Depends(require_role(["analyst", "admin"])),
    _: None = Depends(check_rate_limit_and_backpressure),
) -> PcapUploadResponse:
    """Stream multipart upload directly to storage, compute SHA-256 in chunks, validate magic bytes."""
    filename = file.filename or "capture.pcap"
    sha256_hasher = hashlib.sha256()
    total_bytes = 0
    header_bytes = bytearray()
    chunk_size = settings.sha256_chunk_size_bytes

    # Temporary storage / memory buffer for small-to-medium files or direct object storage stream
    file_id = str(uuid.uuid4())
    object_name = f"{file_id}_{filename}"

    # Read chunks while computing hash and checking magic bytes
    chunks: list[bytes] = []
    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        if len(header_bytes) < 4:
            header_bytes.extend(chunk[: 4 - len(header_bytes)])
        sha256_hasher.update(chunk)
        total_bytes += len(chunk)

        if total_bytes > settings.max_pcap_size_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Upload exceeds maximum allowable capture size of {settings.max_pcap_size_bytes} bytes",
            )
        chunks.append(chunk)

    if len(header_bytes) < 4 or bytes(header_bytes[:4]) not in VALID_MAGIC_BYTES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malformed capture file: Header magic bytes do not match valid PCAP or PCAPNG format.",
        )

    file_sha256 = sha256_hasher.hexdigest()

    # 1. Deduplication check
    from pecff.api.routers.analyses import _ANALYSIS_STORE

    if file_sha256 in _DEDUPLICATED_PCAPS and _DEDUPLICATED_PCAPS[file_sha256] in _ANALYSIS_STORE:
        existing_analysis_id = _DEDUPLICATED_PCAPS[file_sha256]
        response.status_code = status.HTTP_200_OK
        record_audit_log(
            principal=current_user.user_id,
            role=current_user.roles[0],
            action="upload_duplicate",
            resource_id=existing_analysis_id,
            ip_address=request.client.host if request.client else None,
            status_code=200,
            details={"sha256": file_sha256, "filename": filename, "deduplicated": True},
        )
        return PcapUploadResponse(
            analysis_id=existing_analysis_id,
            task_id=f"task-{existing_analysis_id}",
            sha256=file_sha256,
            status_url=f"/api/v1/tasks/task-{existing_analysis_id}",
            duplicate_of=existing_analysis_id,
            is_duplicate=True,
        )

    # 2. Persist to storage
    full_data = b"".join(chunks)
    import io

    storage.put_stream(
        bucket=settings.minio_bucket_pcaps,
        object_name=object_name,
        stream=io.BytesIO(full_data),
        length=len(full_data),
    )

    # 3. Create analysis ID and dispatch pipeline (Celery or inline)
    analysis_id = file_id
    task_id = f"task-{analysis_id}"
    _DEDUPLICATED_PCAPS[file_sha256] = analysis_id

    dispatched_celery = False

    if not settings.prototype_mode:
        # Production path: try Celery worker first
        try:
            from pecff.tasks.celery_app import celery_app

            ping_replies = celery_app.control.ping(timeout=0.5)
            if ping_replies:  # At least one worker responded
                celery_app.send_task(
                    "pecff.tasks.pipeline.run_forensic_pipeline",
                    args=[analysis_id, object_name, filename, file_sha256, total_bytes],
                    task_id=task_id,
                    queue="pecff.ingest",
                )
                dispatched_celery = True
        except Exception:
            dispatched_celery = False

    if not dispatched_celery:
        import asyncio
        from pecff.tasks.pipeline import (
            parse_and_score_shard_task,
            finalize_corpus_task,
            ml_scoring_task,
            index_and_persist_task,
        )
        from pecff.api.routers.tasks import update_task_state

        def run_local_pipeline() -> None:
            try:
                update_task_state(
                    task_id=task_id,
                    state="PARSING",
                    progress=0.15,
                    stage_detail="Parsing and reassembling TCP flows",
                    analysis_id=analysis_id,
                )
                shard_res = parse_and_score_shard_task(analysis_id, object_name, 0, 1)
                update_task_state(
                    task_id=task_id,
                    state="SCORING",
                    progress=0.60,
                    stage_detail="Evaluating NIST SP 800-57 pure deterministic risk engine",
                    analysis_id=analysis_id,
                )
                corpus_res = finalize_corpus_task([shard_res], analysis_id, object_name, filename, file_sha256)
                update_task_state(
                    task_id=task_id,
                    state="SCORING_ML",
                    progress=0.88,
                    stage_detail="Evaluating 94-dim feature vectors with IsolationForest",
                    analysis_id=analysis_id,
                )
                ml_res = ml_scoring_task(corpus_res)
                index_and_persist_task(ml_res)
            except Exception as e:
                import logging
                logging.getLogger("pecff.pcaps").error("Local pipeline failed: %s", e, exc_info=True)
                update_task_state(
                    task_id=task_id,
                    state="FAILURE",
                    progress=1.0,
                    stage_detail=f"Analysis failed: {e}",
                    error=str(e),
                    analysis_id=analysis_id,
                )

        asyncio.create_task(asyncio.to_thread(run_local_pipeline))

    record_audit_log(
        principal=current_user.user_id,
        role=current_user.roles[0],
        action="upload_pcap",
        resource_id=analysis_id,
        ip_address=request.client.host if request.client else None,
        status_code=202,
        details={"sha256": file_sha256, "filename": filename, "size_bytes": total_bytes},
    )

    return PcapUploadResponse(
        analysis_id=analysis_id,
        task_id=task_id,
        sha256=file_sha256,
        status_url=f"/api/v1/tasks/{task_id}",
        duplicate_of=None,
        is_duplicate=False,
    )


@router.post(
    "/presign",
    response_model=PresignedUploadResponse,
    summary="Generate presigned S3 PUT URL for direct uploads exceeding 2 GiB",
)
async def get_presigned_upload_url(
    req: PresignedUploadRequest,
    storage: StorageService = Depends(get_storage_service),
    current_user: AuthenticatedUser = Depends(require_role(["analyst", "admin"])),
) -> PresignedUploadResponse:
    """Generate time-limited presigned PUT URL allowing client to upload directly to MinIO/S3."""
    analysis_id = str(uuid.uuid4())
    object_name = f"{analysis_id}_{req.filename}"
    upload_url = storage.get_presigned_put_url(
        bucket=settings.minio_bucket_pcaps,
        object_name=object_name,
        expires_sec=3600,
    )

    record_audit_log(
        principal=current_user.user_id,
        role=current_user.roles[0],
        action="presign_upload",
        resource_id=analysis_id,
        status_code=200,
        details={"filename": req.filename, "size_bytes": req.size_bytes},
    )

    return PresignedUploadResponse(
        upload_url=upload_url,
        file_key=object_name,
        expires_in_seconds=3600,
        analysis_id=analysis_id,
    )
