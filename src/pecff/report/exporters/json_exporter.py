"""JSON report exporter validating against §5.1 JSON Schema specification."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema


def get_schema_path() -> Path:
    """Resolve the path to the committed JSON Schema artifact."""
    root_dir = Path(__file__).resolve().parent.parent.parent.parent
    schema_file = root_dir / "schema" / "pecff-analysis-1.0.0.json"
    if not schema_file.exists():
        # Fallback to exporting schema dynamically
        from pecff.api.schemas import export_json_schema

        export_json_schema(schema_file)
    return schema_file


def validate_against_schema(analysis_dict: dict[str, Any]) -> None:
    """Validate forensic analysis dictionary against published JSON Schema."""
    schema_path = get_schema_path()
    with open(schema_path, encoding="utf-8") as f:
        schema = json.load(f)

    jsonschema.validate(instance=analysis_dict, schema=schema)


def export_validated_json(
    analysis_dict: dict[str, Any],
    output_path: Path | str | None = None,
    validate: bool = True,
) -> str:
    """Export canonical, schema-validated JSON analysis document."""
    if validate:
        validate_against_schema(analysis_dict)

    json_str = json.dumps(analysis_dict, indent=2, sort_keys=True, default=str)

    if output_path:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json_str, encoding="utf-8")

    return json_str
