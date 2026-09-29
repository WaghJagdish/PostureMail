"""Task status tracking, revocation, and real-time WebSocket progress streaming."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect

from pecff.api.schemas import TaskState, TaskStatusResponse, TaskStreamEvent
from pecff.api.security import AuthenticatedUser, record_audit_log, require_role

router = APIRouter(prefix="/api/v1/tasks", tags=["Task Tracking"])

# In-memory task tracking state repository
_TASK_STORE: dict[str, dict[str, Any]] = {}


def update_task_state(
    task_id: str,
    state: TaskState,
    progress: float = 0.0,
    stage_detail: str = "",
    packets_processed: int = 0,
    total_packets: int | None = None,
    eta_seconds: float | None = None,
    error: str | None = None,
    analysis_id: str | None = None,
) -> None:
    """Helper to update internal task tracking state."""
    _TASK_STORE[task_id] = {
        "task_id": task_id,
        "state": state,
        "progress": progress,
        "stage_detail": stage_detail,
        "packets_processed": packets_processed,
        "total_packets": total_packets,
        "eta_seconds": eta_seconds,
        "error": error,
        "analysis_id": analysis_id or _TASK_STORE.get(task_id, {}).get("analysis_id"),
    }


def get_task_info(task_id: str) -> TaskStatusResponse:
    """Retrieve current task execution metrics from Celery or internal store."""
    # 1. Check internal store first
    if task_id in _TASK_STORE:
        info = _TASK_STORE[task_id]
        return TaskStatusResponse(**info)

    # 2. Check Celery AsyncResult
    try:
        from celery.result import AsyncResult

        res = AsyncResult(task_id)
        celery_state = res.state

        state_mapping: dict[str, TaskState] = {
            "PENDING": "PENDING",
            "STARTED": "PARSING",
            "PARSING": "PARSING",
            "SCORING": "SCORING",
            "SCORING_ML": "SCORING_ML",
            "SUCCESS": "SUCCESS",
            "FAILURE": "FAILURE",
            "REVOKED": "REVOKED",
        }
        mapped_state = state_mapping.get(celery_state, "PENDING")
        progress = 0.0
        stage_detail = f"Stage: {celery_state}"
        error = str(res.result) if mapped_state == "FAILURE" else None
        analysis_id = None

        if isinstance(res.info, dict):
            progress = float(res.info.get("progress", 0.0))
            stage_detail = str(res.info.get("stage_detail", stage_detail))
            analysis_id = res.info.get("analysis_id")

        return TaskStatusResponse(
            task_id=task_id,
            state=mapped_state,
            progress=progress,
            stage_detail=stage_detail,
            error=error,
            analysis_id=analysis_id,
        )
    except Exception:
        # Default pending state
        return TaskStatusResponse(
            task_id=task_id,
            state="PENDING",
            progress=0.0,
            stage_detail="Queued in broker",
        )


@router.get(
    "/{task_id}",
    response_model=TaskStatusResponse,
    summary="Retrieve real-time execution progress, stage, and completion state",
)
async def get_task_status(
    task_id: str,
    current_user: AuthenticatedUser = Depends(require_role(["analyst", "admin", "readonly"])),
) -> TaskStatusResponse:
    """Query current pipeline execution state, stage details, packet counts, and ETA."""
    return get_task_info(task_id)


@router.delete(
    "/{task_id}",
    response_model=TaskStatusResponse,
    summary="Revoke and cancel an ongoing analysis task",
)
async def revoke_task(
    task_id: str,
    current_user: AuthenticatedUser = Depends(require_role(["analyst", "admin"])),
) -> TaskStatusResponse:
    """Terminate and revoke an active analysis task."""
    try:
        from pecff.tasks.celery_app import celery_app

        celery_app.control.revoke(task_id, terminate=True, signal="SIGKILL")
    except Exception:
        pass

    update_task_state(
        task_id=task_id,
        state="REVOKED",
        progress=0.0,
        stage_detail="Task revoked by operator",
    )

    record_audit_log(
        principal=current_user.user_id,
        role=current_user.roles[0],
        action="revoke_task",
        resource_id=task_id,
        status_code=200,
    )

    return get_task_info(task_id)


@router.websocket("/{task_id}/stream")
async def stream_task_progress(websocket: WebSocket, task_id: str) -> None:
    """Push real-time progress events over WebSocket until task completion or termination."""
    await websocket.accept()
    try:
        last_progress = -1.0
        last_state = ""
        while True:
            status_info = get_task_info(task_id)
            if status_info.progress != last_progress or status_info.state != last_state:
                last_progress = status_info.progress
                last_state = status_info.state

                event_type = "progress"
                if status_info.state in {"SUCCESS", "FAILURE", "REVOKED"}:
                    event_type = "complete" if status_info.state == "SUCCESS" else "error"
                elif status_info.state != last_state:
                    event_type = "state_change"

                event = TaskStreamEvent(
                    event=event_type,  # type: ignore[arg-type]
                    payload=status_info,
                )
                await websocket.send_json(event.model_dump(mode="json"))

                if status_info.state in {"SUCCESS", "FAILURE", "REVOKED"}:
                    break

            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        pass
    except Exception:
        await websocket.close()
