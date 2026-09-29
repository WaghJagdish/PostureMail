"""Fast Phase 2 Smoke Test: Uses indexed central directory offsets to fetch

and extract 100 PCAPs in parallel threads, runs them through production
PS159 extractor and vectorizer, validates 94-D shape, and saves Parquet.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path
import shutil
import sys
import time
from typing import Any

import numpy as np
import pandas as pd

# Add repository root to module search path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
  sys.path.insert(0, str(REPO_ROOT))

from pecff.ml.features import (
    RawSessionFeatures,
    SessionFeatureExtractor,
    SessionFeatureVectorizer,
)
from pecff.ml.v2.validator import validate_feature_vector
from scripts.fast_cs_indexer import extract_single_pcap
from scripts.pcap_to_features import extract_features_from_pcap

URL = "https://cspectrum.web.cse.unsw.edu.au/cipherspectrum/aes-128-gcm.zip"


def run_fast_smoke_test(
    target_sessions: int = 100, max_workers: int = 8
) -> dict[str, Any]:
  start_time = time.time()
  print(
      f"--- Phase 2 Smoke Test: Fast Index-Based Extraction of {target_sessions}"
      " Sessions ---"
  )

  index_file = Path("data/cipherspectrum_aes128_index.json")
  with open(index_file, "r", encoding="utf-8") as f:
    index_data: dict[str, list[int]] = json.load(f)

  # Group by domain for balanced sampling across 40 domains
  domain_map: dict[str, list[tuple[str, list[int]]]] = {}
  for fname, entry in index_data.items():
    parts = fname.split("/")
    if len(parts) > 2:
      d = parts[1]
      domain_map.setdefault(d, []).append((fname, entry))

  selected_items: list[tuple[str, list[int]]] = []
  domains = sorted(list(domain_map.keys()))
  while len(selected_items) < target_sessions and domain_map:
    for d in domains:
      if domain_map[d]:
        selected_items.append(domain_map[d].pop(0))
        if len(selected_items) >= target_sessions:
          break

  print(
      f"Selected {len(selected_items)} PCAPs across {len(domains)} distinct"
      " domains."
  )

  temp_dir = Path("data/temp_smoke_pcaps")
  if temp_dir.exists():
    shutil.rmtree(temp_dir)
  temp_dir.mkdir(parents=True, exist_ok=True)

  # Download in parallel using ThreadPoolExecutor
  print(f"Downloading {len(selected_items)} PCAPs with {max_workers} threads...")
  downloaded_files: list[Path] = []

  def _download(item: tuple[str, list[int]]) -> Path:
    fname, (offset, comp, uncomp) = item
    out_file = temp_dir / Path(fname).name
    extract_single_pcap(URL, offset, comp, out_file)
    return out_file

  with ThreadPoolExecutor(max_workers=max_workers) as pool:
    futures = [pool.submit(_download, item) for item in selected_items]
    for fut in as_completed(futures):
      downloaded_files.append(fut.result())

  print(f"Downloaded {len(downloaded_files)} PCAPs in {time.time()-start_time:.1f}s.")

  # Extract features through production pipeline
  print("Extracting features using production SessionFeatureExtractor...")
  extractor = SessionFeatureExtractor()
  raw_features: list[RawSessionFeatures] = []
  session_metadata: list[dict[str, Any]] = []
  failed_pcaps = 0

  for pcap_path in downloaded_files:
    try:
      results = extract_features_from_pcap(pcap_path, extractor)
      for meta, raw in results:
        meta["source_pcap"] = pcap_path.name
        session_metadata.append(meta)
        raw_features.append(raw)
    except Exception as e:
      failed_pcaps += 1

  print(
      f"Extracted {len(raw_features)} sessions from {len(downloaded_files)}"
      f" PCAPs (Failed: {failed_pcaps})"
  )
  assert (
      len(raw_features) >= target_sessions
  ), f"Expected at least {target_sessions}, got {len(raw_features)}"

  raw_features = raw_features[:target_sessions]
  session_metadata = session_metadata[:target_sessions]

  # Transform via SessionFeatureVectorizer
  print("Transforming into exact 94-D feature vectors...")
  vectorizer = SessionFeatureVectorizer()
  matrix = vectorizer.fit_transform(raw_features)

  print(f"Vector matrix shape: {matrix.shape}, dtype: {matrix.dtype}")
  assert matrix.shape == (target_sessions, 94)
  assert matrix.dtype == np.float32

  # Fail-closed validation
  validate_feature_vector(matrix, allow_nan=False, allow_inf=False)
  print("Fail-closed validation PASSED: All 94 dimensions valid and finite.")

  # Persist outputs
  out_dir = Path("data/datasets/smoke_test")
  out_dir.mkdir(parents=True, exist_ok=True)
  df = pd.DataFrame(matrix, columns=vectorizer.ordered_feature_names)
  df.to_parquet(out_dir / "features_94d.parquet", index=False)

  with open(out_dir / "session_manifest.json", "w", encoding="utf-8") as f:
    json.dump(session_metadata, f, indent=2)

  # Purge temporary PCAPs
  shutil.rmtree(temp_dir)
  print("Temporary PCAPs safely purged from disk.")

  elapsed = time.time() - start_time
  summary: dict[str, Any] = {
      "phase": "Phase 2 Smoke Test",
      "target_sessions": target_sessions,
      "sessions_extracted": len(raw_features),
      "feature_matrix_shape": list(matrix.shape),
      "failed_pcaps": failed_pcaps,
      "elapsed_seconds": round(elapsed, 2),
      "parquet_path": str(out_dir / "features_94d.parquet"),
      "status": "PASSED",
  }

  with open(out_dir / "smoke_test_summary.json", "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2)

  print(f"Phase 2 Smoke Test PASSED in {elapsed:.2f}s!")
  return summary


if __name__ == "__main__":
  run_fast_smoke_test(100)
