"""Tests for PS159 ML V2 feature schema validation and fail-closed integrity.

Ensures:
1. Canonical schema file exists at data/models/v2/schema/schema.json.
2. Contains exactly 94 features in exact immutable order.
3. Feature names SHA256 matches frozen hash: 106d6bb406e7f081f50801dbe106259b10e52b30fb5cc821a7c45f933999cdfd.
4. Parity with data/feature_manifest.json.
5. All feature types, units, and missing semantics are specified.
6. Fail-closed schema validator behavior on malformed vectors.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np
import pytest

SCHEMA_PATH = Path("data/models/v2/schema/schema.json")
MANIFEST_PATH = Path("data/feature_manifest.json")
EXPECTED_SHA256 = "106d6bb406e7f081f50801dbe106259b10e52b30fb5cc821a7c45f933999cdfd"


@pytest.fixture
def schema_doc() -> dict:
    assert SCHEMA_PATH.exists(), f"Schema file not found at {SCHEMA_PATH}"
    with open(SCHEMA_PATH, encoding="utf-8") as f:
        return json.load(f)


def test_schema_feature_count(schema_doc: dict):
    assert schema_doc["total_dimensions"] == 94
    assert len(schema_doc["features"]) == 94


def test_schema_names_sha256(schema_doc: dict):
    feature_names = [f["feature_name"] for f in schema_doc["features"]]
    computed_hash = hashlib.sha256(",".join(feature_names).encode("utf-8")).hexdigest()
    assert computed_hash == EXPECTED_SHA256
    assert schema_doc["feature_names_sha256"] == EXPECTED_SHA256


def test_schema_parity_with_feature_manifest(schema_doc: dict):
    with open(MANIFEST_PATH, encoding="utf-8") as f:
        manifest = json.load(f)
    manifest_ordered = manifest["ordered_features"]
    schema_ordered = [f["feature_name"] for f in schema_doc["features"]]
    assert schema_ordered == manifest_ordered


def test_schema_feature_integrity(schema_doc: dict):
    seen_indices = set()
    seen_names = set()
    for feat in schema_doc["features"]:
        idx = feat["feature_index"]
        name = feat["feature_name"]
        assert idx not in seen_indices, f"Duplicate index {idx}"
        assert name not in seen_names, f"Duplicate name {name}"
        seen_indices.add(idx)
        seen_names.add(name)
        assert feat["dtype"] == "float32"
        assert feat["semantic_block"] in {
            "fingerprints",
            "cipher_profile",
            "extension_profile",
            "crypto_params",
            "session_metadata",
            "behavioral",
        }
        assert "missing_semantics" in feat
        assert "valid_range" in feat


def test_fail_closed_validation():
    """Verify that vector validation fails closed on invalid shapes or non-finite values."""
    from pecff.ml.v2.validator import validate_feature_vector

    valid_vector = np.zeros(94, dtype=np.float32)
    assert validate_feature_vector(valid_vector) is True

    # Wrong shape
    with pytest.raises(ValueError, match="Expected 94 dimensions"):
        validate_feature_vector(np.zeros(93, dtype=np.float32))

    with pytest.raises(ValueError, match="Expected 94 dimensions"):
        validate_feature_vector(np.zeros(95, dtype=np.float32))

    # NaN / Inf in vector without mask
    invalid_nan = np.zeros(94, dtype=np.float32)
    invalid_nan[10] = np.nan
    with pytest.raises(ValueError, match="contains NaN"):
        validate_feature_vector(invalid_nan, allow_nan=False)

    invalid_inf = np.zeros(94, dtype=np.float32)
    invalid_inf[10] = np.inf
    with pytest.raises(ValueError, match="contains non-finite"):
        validate_feature_vector(invalid_inf)
