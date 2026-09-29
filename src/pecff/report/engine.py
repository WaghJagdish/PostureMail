"""Forensic Report Engine with non-optional Chain of Custody, privacy redaction, and multi-format exporters."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import BaseModel

from pecff.api.schemas import AnalysisDetailResponse
from pecff.report.chain_of_custody import ChainOfCustody
from pecff.report.compliance import evaluate_compliance_controls
from pecff.report.exporters.csv_exporter import export_csv
from pecff.report.exporters.json_exporter import export_validated_json
from pecff.report.exporters.misp_exporter import export_misp_event
from pecff.report.exporters.stix_exporter import export_stix2_bundle
from pecff.report.pdf_builder import build_pdf_report
from pecff.report.privacy import scrub_pii_from_analysis

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


class ForensicReportEngine:
    """Central engine for generating auditable forensic reports across multiple formats."""

    def __init__(self, templates_dir: Path | str | None = None) -> None:
        self.templates_dir = Path(templates_dir) if templates_dir else TEMPLATES_DIR
        self._jinja_env = Environment(
            loader=FileSystemLoader(self.templates_dir),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def _prepare_data_and_custody(
        self,
        analysis_data: AnalysisDetailResponse | dict[str, Any],
        operator: str = "pecff-forensic-analyst",
        retain_pii: bool = False,
        pii_justification: str | None = None,
        custody_override: ChainOfCustody | None = None,
    ) -> tuple[dict[str, Any], ChainOfCustody]:
        """Normalize analysis data, apply privacy scrubbing, and validate Chain of Custody."""
        raw_dict: dict[str, Any]
        if isinstance(analysis_data, BaseModel):
            raw_dict = analysis_data.model_dump(mode="json")
        else:
            raw_dict = analysis_data

        # 1. Apply PII scrubbing
        scrub_result = scrub_pii_from_analysis(
            raw_dict,
            retain_pii=retain_pii,
            justification=pii_justification,
        )
        sanitized = scrub_result.sanitized_data

        # 2. Build and strictly validate Chain of Custody
        if custody_override:
            custody_override.validate()
            custody = custody_override
        else:
            custody = ChainOfCustody.from_analysis_data(
                sanitized,
                operator=operator,
            )

        sanitized["chain_of_custody"] = custody.to_dict()
        sanitized["chain_of_custody_digest"] = custody.compute_digest()

        return sanitized, custody

    def generate_executive_html(
        self,
        analysis_data: AnalysisDetailResponse | dict[str, Any],
        output_path: Path | str | None = None,
        operator: str = "pecff-forensic-analyst",
        retain_pii: bool = False,
        pii_justification: str | None = None,
        custody_override: ChainOfCustody | None = None,
    ) -> str:
        """Render 1-2 page plain-language Executive Summary HTML."""
        data, custody = self._prepare_data_and_custody(
            analysis_data, operator, retain_pii, pii_justification, custody_override
        )

        # Compute risk band counts
        band_counts = {"CRITICAL": 0, "HIGH": 0, "WEAK": 0, "ACCEPTABLE": 0, "SECURE": 0}
        for s in data.get("sessions", []):
            b = s.get("risk_band", "SECURE")
            band_counts[b] = band_counts.get(b, 0) + 1

        # Calculate top 5 remediation actions ranked by affected session count
        remediation_map: dict[str, dict[str, Any]] = {}
        for f in data.get("findings", []):
            rule_id = f.get("rule_id", "VULN")
            if rule_id not in remediation_map:
                remediation_map[rule_id] = {
                    "title": f.get("title", rule_id),
                    "description": f.get("description", ""),
                    "severity": f.get("severity", "HIGH"),
                    "affected_count": 0,
                }
            remediation_map[rule_id]["affected_count"] += 1

        top_remediations = sorted(
            remediation_map.values(), key=lambda x: int(x["affected_count"]), reverse=True
        )[:5]

        template = self._jinja_env.get_template("executive.html")
        html_content = template.render(
            analysis=data,
            custody=custody,
            band_counts=band_counts,
            top_remediations=top_remediations,
        )

        if output_path:
            p = Path(output_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(html_content, encoding="utf-8")

        return html_content

    def generate_technical_html(
        self,
        analysis_data: AnalysisDetailResponse | dict[str, Any],
        output_path: Path | str | None = None,
        risk_threshold: int = 0,
        operator: str = "pecff-forensic-analyst",
        retain_pii: bool = False,
        pii_justification: str | None = None,
        custody_override: ChainOfCustody | None = None,
    ) -> str:
        """Render full Technical Forensics HTML with FSM tables, cert details, and provenance."""
        data, custody = self._prepare_data_and_custody(
            analysis_data, operator, retain_pii, pii_justification, custody_override
        )

        filtered_sessions = [
            s for s in data.get("sessions", []) if s.get("risk_score", 0) >= risk_threshold
        ]

        template = self._jinja_env.get_template("technical.html")
        html_content = template.render(
            analysis=data,
            custody=custody,
            risk_threshold=risk_threshold,
            filtered_sessions=filtered_sessions,
        )

        if output_path:
            p = Path(output_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(html_content, encoding="utf-8")

        return html_content

    def generate_compliance_html(
        self,
        analysis_data: AnalysisDetailResponse | dict[str, Any],
        output_path: Path | str | None = None,
        operator: str = "pecff-forensic-analyst",
        retain_pii: bool = False,
        pii_justification: str | None = None,
        custody_override: ChainOfCustody | None = None,
    ) -> str:
        """Render Compliance Control Mapping HTML for NIST 800-52r2, NIST 800-57, and PCI-DSS."""
        data, custody = self._prepare_data_and_custody(
            analysis_data, operator, retain_pii, pii_justification, custody_override
        )

        compliance_rows = evaluate_compliance_controls(data)

        template = self._jinja_env.get_template("compliance.html")
        html_content = template.render(
            analysis=data,
            custody=custody,
            compliance_rows=compliance_rows,
        )

        if output_path:
            p = Path(output_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(html_content, encoding="utf-8")

        return html_content

    def generate_pdf(
        self,
        analysis_data: AnalysisDetailResponse | dict[str, Any],
        output_path: Path | str | None = None,
        operator: str = "pecff-forensic-analyst",
        retain_pii: bool = False,
        pii_justification: str | None = None,
        custody_override: ChainOfCustody | None = None,
    ) -> bytes:
        """Render deterministic, byte-reproducible forensic audit PDF report."""
        data, _ = self._prepare_data_and_custody(
            analysis_data, operator, retain_pii, pii_justification, custody_override
        )
        pdf_bytes = build_pdf_report(data)

        if output_path:
            p = Path(output_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(pdf_bytes)

        return pdf_bytes

    def generate_json(
        self,
        analysis_data: AnalysisDetailResponse | dict[str, Any],
        output_path: Path | str | None = None,
        operator: str = "pecff-forensic-analyst",
        retain_pii: bool = False,
        pii_justification: str | None = None,
        validate: bool = True,
        custody_override: ChainOfCustody | None = None,
    ) -> str:
        """Export canonical JSON analysis document validated against JSON Schema."""
        data, _ = self._prepare_data_and_custody(
            analysis_data, operator, retain_pii, pii_justification, custody_override
        )
        return export_validated_json(data, output_path=output_path, validate=validate)

    def generate_csv(
        self,
        analysis_data: AnalysisDetailResponse | dict[str, Any],
        output_path: Path | str | None = None,
        operator: str = "pecff-forensic-analyst",
        retain_pii: bool = False,
        pii_justification: str | None = None,
        custody_override: ChainOfCustody | None = None,
    ) -> str:
        """Export flat session spreadsheet CSV."""
        data, _ = self._prepare_data_and_custody(
            analysis_data, operator, retain_pii, pii_justification, custody_override
        )
        return export_csv(data, output_path=output_path)

    def generate_stix2(
        self,
        analysis_data: AnalysisDetailResponse | dict[str, Any],
        output_path: Path | str | None = None,
        operator: str = "pecff-forensic-analyst",
        retain_pii: bool = False,
        pii_justification: str | None = None,
        custody_override: ChainOfCustody | None = None,
    ) -> str:
        """Export standard STIX 2.1 Threat Intel bundle."""
        data, _ = self._prepare_data_and_custody(
            analysis_data, operator, retain_pii, pii_justification, custody_override
        )
        return export_stix2_bundle(data, output_path=output_path)

    def generate_misp(
        self,
        analysis_data: AnalysisDetailResponse | dict[str, Any],
        output_path: Path | str | None = None,
        operator: str = "pecff-forensic-analyst",
        retain_pii: bool = False,
        pii_justification: str | None = None,
        custody_override: ChainOfCustody | None = None,
    ) -> str:
        """Export structured MISP Event JSON."""
        data, _ = self._prepare_data_and_custody(
            analysis_data, operator, retain_pii, pii_justification, custody_override
        )
        return export_misp_event(data, output_path=output_path)

    def generate_all_artifacts(
        self,
        analysis_data: AnalysisDetailResponse | dict[str, Any],
        output_dir: Path | str,
        operator: str = "pecff-forensic-analyst",
        retain_pii: bool = False,
        pii_justification: str | None = None,
    ) -> dict[str, Path]:
        """Generate all 8 forensic reporting artifacts into output directory."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        artifacts = {
            "executive_html": out / "executive_report.html",
            "technical_html": out / "technical_report.html",
            "compliance_html": out / "compliance_report.html",
            "pdf": out / "forensic_report.pdf",
            "json": out / "analysis.json",
            "csv": out / "sessions.csv",
            "stix2": out / "stix2_bundle.json",
            "misp": out / "misp_event.json",
        }

        self.generate_executive_html(analysis_data, artifacts["executive_html"], operator, retain_pii, pii_justification)
        self.generate_technical_html(analysis_data, artifacts["technical_html"], 0, operator, retain_pii, pii_justification)
        self.generate_compliance_html(analysis_data, artifacts["compliance_html"], operator, retain_pii, pii_justification)
        self.generate_pdf(analysis_data, artifacts["pdf"], operator, retain_pii, pii_justification)
        self.generate_json(analysis_data, artifacts["json"], operator, retain_pii, pii_justification, validate=True)
        self.generate_csv(analysis_data, artifacts["csv"], operator, retain_pii, pii_justification)
        self.generate_stix2(analysis_data, artifacts["stix2"], operator, retain_pii, pii_justification)
        self.generate_misp(analysis_data, artifacts["misp"], operator, retain_pii, pii_justification)

        return artifacts
