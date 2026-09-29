"""PECFF FastAPI Application Factory & OpenAPI 3.1 Specification Provider."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from pecff.api.routers import analyses, pcaps, tasks, verdicts


def create_app() -> FastAPI:
    """Instantiate and configure the PECFF FastAPI application."""
    app = FastAPI(
        title="PECFF - Passive Email Cryptographic Forensics Framework",
        description=(
            "Passive network forensics and cryptographic analysis API for SMTP/IMAP/POP3 traffic. "
            "Implements pure deterministic NIST SP 800-57 risk scoring, JA3/JA4 TLS fingerprinting, "
            "unsupervised ML anomaly detection, and hostile-input hardened parsing."
        ),
        version="0.1.0",
        openapi_url="/api/v1/openapi.json",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register Routers
    app.include_router(pcaps.router)
    app.include_router(tasks.router)
    app.include_router(analyses.router)
    app.include_router(verdicts.router)

    # Global Health Check
    @app.get("/healthz", tags=["System"])
    async def health_check() -> dict[str, str]:
        return {"status": "HEALTHY", "version": "0.1.0"}

    @app.get("/api/v1/version", tags=["System"])
    async def get_version() -> dict[str, str]:
        return {
            "system": "PECFF",
            "version": "0.1.0",
            "schema_version": "1.0.0",
        }

    return app


app = create_app()


def export_openapi_schema(output_path: Path | None = None) -> Path:
    """Generate and write the OpenAPI 3.1 JSON specification."""
    target_path = output_path or (
        Path(__file__).resolve().parent.parent.parent.parent / "schema" / "openapi.json"
    )
    target_path.parent.mkdir(parents=True, exist_ok=True)
    openapi_dict = app.openapi()
    with open(target_path, "w", encoding="utf-8") as f:
        json.dump(openapi_dict, f, indent=2)
    return target_path
