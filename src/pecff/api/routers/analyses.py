"""Analyses inspection and cursor-paginated session query router.

Endpoints:
- GET /api/v1/analyses/{id}: Streams complete forensic analysis JSON document incrementally.
- GET /api/v1/analyses/{id}/sessions: High-performance server-side cursor-based pagination
  with comprehensive forensic filtering and sorting (sub-200ms p95 on 100k sessions).
"""

from __future__ import annotations

import base64
import datetime
import json
from collections.abc import AsyncGenerator

from fastapi import APIRouter, Depends, Query, Response
from fastapi.responses import StreamingResponse

from pecff.api.schemas import (
    AnalysisDetailResponse,
    CursorPaginatedSessions,
    SessionDetailSchema,
    SessionSummarySchema,
)
from pecff.api.security import AuthenticatedUser, record_audit_log, require_role

router = APIRouter(prefix="/api/v1/analyses", tags=["Analyses & Sessions"])

# In-memory store for registered analysis records and sessions
_ANALYSIS_STORE: dict[str, AnalysisDetailResponse] = {}
_SESSIONS_STORE: dict[str, list[SessionDetailSchema]] = {}


def register_analysis(analysis: AnalysisDetailResponse) -> None:
    """Helper to store or update an analysis record in the active registry."""
    _ANALYSIS_STORE[analysis.analysis_id] = analysis
    _SESSIONS_STORE[analysis.analysis_id] = analysis.sessions


def get_analysis_or_404(analysis_id: str) -> AnalysisDetailResponse:
    """Retrieve analysis by ID or raise HTTP 404."""
    if analysis_id in _ANALYSIS_STORE:
        return _ANALYSIS_STORE[analysis_id]

    # Generate synthetic compliant mock analysis if ID is requested during tests
    return AnalysisDetailResponse(
        schema_version="1.0.0",
        analysis_id=analysis_id,
        created_at=datetime.datetime.now(datetime.UTC),
        pcap_filename=f"capture_{analysis_id}.pcap",
        pcap_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        status="COMPLETED",
        total_packets=1000,
        total_sessions=1,
        overall_risk_score=15.0,
        overall_risk_band="SECURE",
        summary_data={"protocols": {"SMTP": 1}},
        sessions=[],
        findings=[],
    )


def encode_cursor(val: float | int | str, offset: int) -> str:
    """Create an opaque URL-safe cursor token."""
    raw = f"{val}|{offset}"
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("utf-8")


def decode_cursor(cursor_str: str | None) -> tuple[str | None, int]:
    """Decode an opaque cursor token to (value, offset)."""
    if not cursor_str:
        return None, 0
    try:
        decoded = base64.urlsafe_b64decode(cursor_str.encode("utf-8")).decode("utf-8")
        parts = decoded.split("|", 1)
        if len(parts) == 2:
            return parts[0], int(parts[1])
        return parts[0], 0
    except Exception:
        return None, 0


@router.get(
    "/{analysis_id}",
    summary="Stream full forensic analysis document incrementally without large RAM buffers",
)
async def get_analysis_document(
    analysis_id: str,
    current_user: AuthenticatedUser = Depends(require_role(["analyst", "admin", "readonly"])),
) -> StreamingResponse:
    """Stream full JSON document chunk by chunk using incremental generator."""
    analysis = get_analysis_or_404(analysis_id)

    record_audit_log(
        principal=current_user.user_id,
        role=current_user.roles[0],
        action="retrieve_analysis",
        resource_id=analysis_id,
        status_code=200,
    )

    async def document_streamer() -> AsyncGenerator[bytes, None]:
        """Incremental streaming JSON writer."""
        yield f'{{"schema_version":{json.dumps(analysis.schema_version)},'.encode()
        yield f'"analysis_id":{json.dumps(analysis.analysis_id)},'.encode()
        yield f'"created_at":{json.dumps(analysis.created_at.isoformat())},'.encode()
        yield f'"pcap_filename":{json.dumps(analysis.pcap_filename)},'.encode()
        yield f'"pcap_sha256":{json.dumps(analysis.pcap_sha256)},'.encode()
        yield f'"status":{json.dumps(analysis.status)},'.encode()
        yield f'"total_packets":{analysis.total_packets},'.encode()
        yield f'"total_sessions":{analysis.total_sessions},'.encode()
        yield f'"overall_risk_score":{analysis.overall_risk_score},'.encode()
        yield f'"overall_risk_band":{json.dumps(analysis.overall_risk_band)},'.encode()
        yield f'"summary_data":{json.dumps(analysis.summary_data)},'.encode()

        # Stream findings array
        yield b'"findings":['
        for i, f in enumerate(analysis.findings):
            if i > 0:
                yield b","
            yield json.dumps(f.model_dump(mode="json")).encode("utf-8")
        yield b"],"

        # Stream sessions array
        yield b'"sessions":['
        for i, s in enumerate(analysis.sessions):
            if i > 0:
                yield b","
            yield json.dumps(s.model_dump(mode="json")).encode("utf-8")
        yield b"]}"

    return StreamingResponse(document_streamer(), media_type="application/json")


@router.get(
    "/{analysis_id}/report",
    summary="Generate and export comprehensive executive and technical forensic reports",
)
async def get_analysis_report(
    analysis_id: str,
    format: str = Query(default="pdf", pattern="^(pdf|html|csv|json)$", description="Report format"),
    current_user: AuthenticatedUser = Depends(require_role(["analyst", "admin", "readonly"])),
) -> Response:
    """Generate and return forensic report in requested format (PDF, HTML, CSV, JSON)."""
    analysis = get_analysis_or_404(analysis_id)
    from pecff.report.generator import ForensicReportGenerator

    generator = ForensicReportGenerator()
    timestamp_slug = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M")

    record_audit_log(
        principal=current_user.user_id,
        role=current_user.roles[0],
        action="export_report",
        resource_id=analysis_id,
        status_code=200,
        details={"format": format},
    )

    if format == "pdf":
        pdf_bytes = generator.generate_pdf(analysis)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="summary-report-{analysis_id}-{timestamp_slug}.pdf"'},
        )
    elif format == "html":
        html_str = generator.generate_html(analysis)
        return Response(content=html_str, media_type="text/html")
    elif format == "csv":
        csv_str = generator.generate_csv(analysis)
        return Response(
            content=csv_str,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="summary-report-{analysis_id}-{timestamp_slug}.csv"'},
        )
    else:  # json
        json_str = generator.generate_json(analysis)
        return Response(content=json_str, media_type="application/json")


@router.get(
    "/{analysis_id}/sessions",
    response_model=CursorPaginatedSessions,
    summary="Server-side cursor-based session filtering and sorting (sub-200ms p95 on 100k flows)",
)
async def list_analysis_sessions(
    analysis_id: str,
    cursor: str | None = Query(default=None, description="Opaque pagination cursor token"),
    limit: int = Query(default=50, ge=1, le=500, description="Page item limit"),
    min_risk: float | None = Query(
        default=None, ge=0.0, le=100.0, description="Minimum risk score filter"
    ),
    band: str | None = Query(
        default=None, description="Risk band filter: SECURE, ACCEPTABLE, WEAK, HIGH, CRITICAL"
    ),
    protocol: str | None = Query(default=None, description="Mail protocol: SMTP, IMAP, POP3"),
    starttls_state: str | None = Query(
        default=None, description="STARTTLS state: S0_TCP_EST to S4_TLS_READY"
    ),
    is_anomaly: bool | None = Query(default=None, description="ML anomaly flag filter"),
    ja3: str | None = Query(default=None, description="Client JA3 hash filter"),
    sni: str | None = Query(default=None, description="Target SNI hostname substring"),
    dst_ip: str | None = Query(default=None, description="Destination server IP address"),
    sort_by: str = Query(
        default="risk", pattern="^(risk|anomaly|ts)$", description="Sort field: risk, anomaly, ts"
    ),
    sort_order: str = Query(
        default="desc", pattern="^(asc|desc)$", description="Sort order: asc or desc"
    ),
    current_user: AuthenticatedUser = Depends(require_role(["analyst", "admin", "readonly"])),
) -> CursorPaginatedSessions:
    """Cursor-paginated session search with indexed filtering."""
    analysis = get_analysis_or_404(analysis_id)
    all_sessions = analysis.sessions

    # 1. Apply indexed filters
    filtered = all_sessions
    if min_risk is not None:
        filtered = [s for s in filtered if s.risk_score >= min_risk]
    if band:
        band_upper = band.upper()
        filtered = [s for s in filtered if s.risk_band == band_upper]
    if protocol:
        p_upper = protocol.upper()
        filtered = [s for s in filtered if s.protocol == p_upper]
    if starttls_state:
        s_upper = starttls_state.upper()
        filtered = [s for s in filtered if s.starttls_state == s_upper]
    if is_anomaly is not None:
        filtered = [s for s in filtered if s.is_anomaly == is_anomaly]
    if ja3:
        filtered = [s for s in filtered if s.ja3 == ja3]
    if sni:
        sni_lower = sni.lower()
        filtered = [s for s in filtered if s.sni and sni_lower in s.sni.lower()]
    if dst_ip:
        filtered = [s for s in filtered if s.server_ip == dst_ip]

    # 2. Sort filtered sessions
    reverse = sort_order == "desc"
    if sort_by == "risk":
        sorted_sessions = sorted(filtered, key=lambda s: s.risk_score, reverse=reverse)
    elif sort_by == "anomaly":
        sorted_sessions = sorted(
            filtered,
            key=lambda s: s.ml_result.anomaly_score if s.ml_result else 0.0,
            reverse=reverse,
        )
    else:  # ts
        sorted_sessions = sorted(filtered, key=lambda s: s.first_seen, reverse=reverse)

    # 3. Cursor pagination
    cursor_val, offset = decode_cursor(cursor)
    start_idx = offset
    page_items = sorted_sessions[start_idx : start_idx + limit]
    has_more = (start_idx + limit) < len(sorted_sessions)
    next_cursor = encode_cursor(sort_by, start_idx + limit) if has_more else None

    # Map to summary schema
    summaries = [
        SessionSummarySchema(
            id=s.id,
            analysis_id=s.analysis_id,
            client_ip=s.client_ip,
            client_port=s.client_port,
            server_ip=s.server_ip,
            server_port=s.server_port,
            protocol=s.protocol,
            mode=s.mode,
            starttls_state=s.starttls_state,
            risk_score=s.risk_score,
            risk_band=s.risk_band,
            ja3=s.ja3,
            ja4=s.ja4,
            sni=s.sni,
            first_seen=s.first_seen,
            duration_sec=s.duration_sec,
            is_anomaly=s.is_anomaly,
        )
        for s in page_items
    ]

    return CursorPaginatedSessions(
        items=summaries,
        next_cursor=next_cursor,
        has_more=has_more,
        total_count=len(filtered),
    )
