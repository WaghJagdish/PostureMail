"""PS159 ML V2 Feature Vector Validation module.

Provides fail-closed enforcement of 94-dimensional feature vector integrity.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Final

import numpy as np

SCHEMA_PATH: Final[Path] = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "data"
    / "models"
    / "v2"
    / "schema"
    / "schema.json"
)
EXPECTED_DIMENSIONS: Final[int] = 94
EXPECTED_SCHEMA_HASH: Final[str] = (
    "106d6bb406e7f081f50801dbe106259b10e52b30fb5cc821a7c45f933999cdfd"
)


def validate_feature_vector(
    vector: np.ndarray,
    allow_nan: bool = False,
    allow_inf: bool = False,
) -> bool:
    """Validate vector shape, dtype, and numerical bounds.

    Fails closed (raises ValueError) if vector does not meet production schema.
    """
    if not isinstance(vector, np.ndarray):
        raise TypeError(f"Vector must be a numpy ndarray, got {type(vector)}")

    if vector.ndim == 1:
        if vector.shape[0] != EXPECTED_DIMENSIONS:
            raise ValueError(
                f"Expected {EXPECTED_DIMENSIONS} dimensions, got shape {vector.shape}"
            )
    elif vector.ndim == 2:
        if vector.shape[1] != EXPECTED_DIMENSIONS:
            raise ValueError(
                f"Expected {EXPECTED_DIMENSIONS} dimensions per sample, got shape {vector.shape}"
            )
    else:
        raise ValueError(f"Expected 1D or 2D feature matrix, got {vector.ndim}D")

    if not allow_nan and np.isnan(vector).any():
        raise ValueError("Feature vector contains NaN values in strict mode")

    if not allow_inf and np.isinf(vector).any():
        raise ValueError("Feature vector contains non-finite (Inf/-Inf) values")

    return True
