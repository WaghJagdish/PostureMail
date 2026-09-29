"""Forensic report generator supporting JSON, HTML, and PDF formats.

Wraps ForensicReportEngine for backward-compatibility while exposing
full Chain-of-Custody and multi-template capabilities.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pecff.api.schemas import AnalysisDetailResponse
from pecff.report.engine import ForensicReportEngine


class ForensicReportGenerator:
    """Unified report generator for PECFF cryptographic audit results."""

    def __init__(self, templates_dir: Path | str | None = None) -> None:
        self._engine = ForensicReportEngine(templates_dir=templates_dir)

    def generate_json(
        self,
        analysis_data: AnalysisDetailResponse | dict[str, Any],
        output_path: Path | str | None = None,
        validate: bool = True,
    ) -> str:
        """Export analysis audit results to schema-compliant JSON."""
        return self._engine.generate_json(analysis_data, output_path=output_path, validate=validate)

    def generate_html(
        self,
        analysis_data: AnalysisDetailResponse | dict[str, Any],
        output_path: Path | str | None = None,
    ) -> str:
        """Render analysis audit results into a rich standalone HTML document."""
        return self._engine.generate_executive_html(analysis_data, output_path=output_path)

    def generate_technical_html(
        self,
        analysis_data: AnalysisDetailResponse | dict[str, Any],
        output_path: Path | str | None = None,
        risk_threshold: int = 0,
    ) -> str:
        """Render analysis audit results into a full technical HTML document."""
        return self._engine.generate_technical_html(analysis_data, output_path=output_path, risk_threshold=risk_threshold)

    def generate_compliance_html(
        self,
        analysis_data: AnalysisDetailResponse | dict[str, Any],
        output_path: Path | str | None = None,
    ) -> str:
        """Render compliance control mapping HTML document."""
        return self._engine.generate_compliance_html(analysis_data, output_path=output_path)

    def generate_pdf(
        self,
        analysis_data: AnalysisDetailResponse | dict[str, Any],
        output_path: Path | str | None = None,
    ) -> bytes:
        """Render analysis audit results into a print-ready executive PDF report."""
        return self._engine.generate_pdf(analysis_data, output_path=output_path)

    def generate_csv(
        self,
        analysis_data: AnalysisDetailResponse | dict[str, Any],
        output_path: Path | str | None = None,
    ) -> str:
        """Export session spreadsheet CSV."""
        return self._engine.generate_csv(analysis_data, output_path=output_path)

    def generate_stix2(
        self,
        analysis_data: AnalysisDetailResponse | dict[str, Any],
        output_path: Path | str | None = None,
    ) -> str:
        """Export STIX 2.1 Threat Intel bundle."""
        return self._engine.generate_stix2(analysis_data, output_path=output_path)

    def generate_misp(
        self,
        analysis_data: AnalysisDetailResponse | dict[str, Any],
        output_path: Path | str | None = None,
    ) -> str:
        """Export MISP Event JSON."""
        return self._engine.generate_misp(analysis_data, output_path=output_path)
