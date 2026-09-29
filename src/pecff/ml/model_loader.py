"""Supply-chain secure ML model loader and packaging engine using skops.

Provides tamper-resistant model persistence, explicit minimal trusted-type
allowlisting, training manifest provenance hashing, and operator authorization
checks for model retraining per §4.5 and §6 supply chain requirements.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import skops.io as sio


class SecurityError(Exception):
    """Raised when model integrity, manifest hash, or operator authorization fails."""


# Minimal explicit trusted types allowlist for scikit-learn anomaly / classifier models
EXPLICIT_TRUSTED_TYPES: list[str] = [
    "numpy.ndarray",
    "numpy.dtype",
    "numpy.core.multiarray._reconstruct",
    "numpy.core.multiarray.scalar",
    "sklearn.ensemble._iforest.IsolationForest",
    "sklearn.tree._classes.DecisionTreeClassifier",
    "sklearn.tree._tree.Tree",
    "sklearn.preprocessing._data.RobustScaler",
    "sklearn.preprocessing._data.QuantileTransformer",
]


def compute_manifest_hash(manifest_path_or_dict: Path | dict[str, Any]) -> str:
    """Compute deterministic SHA-256 digest of the feature manifest."""
    if isinstance(manifest_path_or_dict, Path):
        data = json.loads(manifest_path_or_dict.read_text(encoding="utf-8"))
    else:
        data = manifest_path_or_dict
    canon_bytes = json.dumps(data, sort_keys=True).encode("utf-8")
    return hashlib.sha256(canon_bytes).hexdigest()


def save_secure_model(
    model: Any,
    output_path: Path | str,
    manifest_hash: str,
    operator_approved: bool = True,
    operator_id: str = "pecff-operator",
) -> Path:
    """Serialize ML model using skops with embedded provenance metadata."""
    if not operator_approved:
        raise SecurityError("Model retraining requires explicit operator approval.")

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    metadata = {
        "manifest_hash": manifest_hash,
        "operator_id": operator_id,
        "operator_approved": operator_approved,
    }

    payload = {
        "model": model,
        "metadata": metadata,
    }

    sio.dump(payload, str(out))
    return out


def load_secure_model(
    model_path: Path | str,
    expected_manifest_hash: str | None = None,
    trusted_types: list[str] | None = None,
) -> tuple[Any, dict[str, Any]]:
    """Load an ML model using skops with strict type allowlisting and manifest verification."""
    p = Path(model_path)
    if not p.exists():
        raise FileNotFoundError(f"Model file not found: {p}")

    allowed_types = trusted_types if trusted_types is not None else list(EXPLICIT_TRUSTED_TYPES)

    try:
        # Load using skops with explicit trusted types
        loaded = sio.load(str(p), trusted=allowed_types)
    except Exception as e:
        raise SecurityError(f"Model loading rejected by skops security guard: {e}") from e

    if not isinstance(loaded, dict) or "model" not in loaded or "metadata" not in loaded:
        raise SecurityError("Model payload structure corrupted or missing metadata.")

    metadata = loaded["metadata"]
    if not metadata.get("operator_approved"):
        raise SecurityError("Model metadata lacks operator approval.")

    if expected_manifest_hash and metadata.get("manifest_hash") != expected_manifest_hash:
        raise SecurityError(
            f"Manifest hash mismatch: expected {expected_manifest_hash}, "
            f"found {metadata.get('manifest_hash')}"
        )

    return loaded["model"], metadata
