"""Forensic verdict submission and security audit log inspection router."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, status

from pecff.api.schemas import (
    AuditLogEntrySchema,
    VerdictSubmissionRequest,
    VerdictSubmissionResponse,
)
from pecff.api.security import (
    AuthenticatedUser,
    get_audit_logs,
    record_audit_log,
    require_role,
)

router = APIRouter(prefix="/api/v1", tags=["Verdicts & Audit Logs"])

# In-memory verdicts repository
_VERDICTS_STORE: dict[str, dict[str, Any]] = {}


@router.post(
    "/sessions/{session_id}/verdict",
    response_model=VerdictSubmissionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit analyst forensic verdict and ground-truth label for a session",
)
async def submit_session_verdict(
    session_id: str,
    req: VerdictSubmissionRequest,
    current_user: AuthenticatedUser = Depends(require_role(["analyst", "admin"])),
) -> VerdictSubmissionResponse:
    """Record an analyst ground-truth verdict with forensic notes and confidence score."""
    verdict_id = str(uuid.uuid4())
    now = datetime.now(UTC)

    _VERDICTS_STORE[verdict_id] = {
        "verdict_id": verdict_id,
        "session_id": session_id,
        "analyst_id": current_user.user_id,
        "submitted_at": now,
        "verdict": req.verdict,
        "confidence": req.confidence,
        "notes": req.notes,
        "tags": req.tags,
    }

    record_audit_log(
        principal=current_user.user_id,
        role=current_user.roles[0],
        action="submit_verdict",
        resource_id=session_id,
        status_code=201,
        details={"verdict": req.verdict, "confidence": req.confidence, "verdict_id": verdict_id},
    )

    return VerdictSubmissionResponse(
        verdict_id=verdict_id,
        session_id=session_id,
        analyst_id=current_user.user_id,
        submitted_at=now,
        verdict=req.verdict,
        status="RECORDED",
    )


@router.get(
    "/audit/logs",
    response_model=list[AuditLogEntrySchema],
    summary="Retrieve forensic security audit log entries (admin role required)",
)
async def list_audit_logs(
    current_user: AuthenticatedUser = Depends(require_role(["admin"])),
) -> list[AuditLogEntrySchema]:
    """Retrieve immutable audit event logs."""
    raw_logs = get_audit_logs()
    entries: list[AuditLogEntrySchema] = []
    for i, item in enumerate(raw_logs):
        entries.append(
            AuditLogEntrySchema(
                id=f"audit-{i}",
                timestamp=datetime.fromisoformat(item["timestamp"]),
                principal=item["principal"],
                role=item["role"],
                action=item["action"],
                resource_id=item["resource_id"],
                ip_address=item.get("ip_address"),
                status_code=item.get("status_code", 200),
                details=item.get("details", {}),
            )
        )
    return entries
