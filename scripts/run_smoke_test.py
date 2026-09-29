"""Phase 2 Smoke Test: Streams 100 real TLS 1.3 PCAPs from CipherSpectrum,

runs them through production extractor and vectorizer, verifies 94-D shape and
bounds,
persists compact Parquet representation, and purges raw PCAPs.
"""

from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json
import shutil
import time

import numpy as np
import pandas as pd

from pecff.ml.features import (
    FeatureStore,
    RawSessionFeatures,
    SessionFeatureExtractor,
    SessionFeatureVectorizer,
)
from pecff.ml.v2.validator import validate_feature_vector
from scripts.cs_extractor import HttpRangeFile, extract_batch
from scripts.pcap_to_features import extract_features_from_pcap



def run_phase_2_smoke_test(target_sessions: int = 100) -> dict:
  start_time = time.time()
  print(
      f"--- Starting Phase 2 Smoke Test: Processing {target_sessions} real"
      " CipherSpectrum sessions ---"
  )

  # 1. Load manifest and select 100 sessions across distinct domains
  manifest_path = Path("data/cipherspectrum_aes128_manifest.json")
  with open(manifest_path, "r", encoding="utf-8") as f:
    all_pcaps: list[str] = json.load(f)

  # Group by domain to ensure diverse multi-domain coverage
  domain_pcaps: dict[str, list[str]] = {}
  for p in all_pcaps:
    parts = p.split("/")
    if len(parts) > 2:
      d = parts[1]
      domain_pcaps.setdefault(d, []).append(p)

  selected_pcaps: list[str] = []
  domains = sorted(list(domain_pcaps.keys()))
  idx = 0
  while len(selected_pcaps) < target_sessions and domain_pcaps:
    for d in domains:
      if domain_pcaps[d]:
        selected_pcaps.append(domain_pcaps[d].pop(0))
        if len(selected_pcaps) >= target_sessions:
          break

  print(
      f"Selected {len(selected_pcaps)} PCAPs across {len(domains)} distinct"
      " domains."
  )

  # 2. Stage temporary extraction directory
  temp_pcap_dir = Path("data/temp_smoke_pcaps")
  temp_pcap_dir.mkdir(parents=True, exist_ok=True)
  url = "https://cspectrum.web.cse.unsw.edu.au/cipherspectrum/aes-128-gcm.zip"

  print("Streaming PCAP batch from remote archive...")
  pcap_paths = extract_batch(url, selected_pcaps, temp_pcap_dir)
  print(f"Extracted {len(pcap_paths)} PCAP files to disk.")

  # 3. Process sessions through production extractor
  extractor = SessionFeatureExtractor()
  raw_features_collected: list[RawSessionFeatures] = []
  session_metadata_collected: list[dict] = []
  failed_pcaps = 0

  for p in pcap_paths:
    try:
      results = extract_features_from_pcap(p, extractor)
      for meta, raw_feat in results:
        meta["source_pcap"] = p.name
        session_metadata_collected.append(meta)
        raw_features_collected.append(raw_feat)
    except Exception as e:
      failed_pcaps += 1
      print(f"Failed extracting {p.name}: {e}")

  print(
      f"Extraction complete: {len(raw_features_collected)} sessions extracted"
      f" from {len(pcap_paths)} files (Failures: {failed_pcaps})"
  )
  assert (
      len(raw_features_collected) >= target_sessions
  ), f"Expected at least {target_sessions} sessions, got {len(raw_features_collected)}"

  # Trim to exact target_sessions count
  raw_features_collected = raw_features_collected[:target_sessions]
  session_metadata_collected = session_metadata_collected[:target_sessions]

  # 4. Vectorize through SessionFeatureVectorizer
  print("Fitting and transforming via SessionFeatureVectorizer...")
  vectorizer = SessionFeatureVectorizer()
  matrix = vectorizer.fit_transform(raw_features_collected)

  print(f"Feature matrix shape: {matrix.shape}, dtype: {matrix.dtype}")
  assert matrix.shape == (
      target_sessions,
      94,
  ), f"Shape mismatch: {matrix.shape}"
  assert matrix.dtype == np.float32, f"Dtype mismatch: {matrix.dtype}"

  # 5. Fail-closed validation check
  validate_feature_vector(matrix, allow_nan=False, allow_inf=False)
  print("Fail-closed validation PASSED: Matrix is finite and matches schema.")

  # 6. Persist compact representations to Parquet & JSON
  output_dir = Path("data/datasets/smoke_test")
  output_dir.mkdir(parents=True, exist_ok=True)

  # Save features Parquet
  df_features = pd.DataFrame(matrix, columns=vectorizer.ordered_feature_names)
  features_parquet = output_dir / "features_94d.parquet"
  df_features.to_parquet(features_parquet, index=False)

  # Save metadata manifest
  manifest_out = output_dir / "session_manifest.json"
  with open(manifest_out, "w", encoding="utf-8") as f:
    json.dump(session_metadata_collected, f, indent=2)

  # 7. Clean up temporary PCAPs to maintain disk safety
  shutil.rmtree(temp_pcap_dir)
  print("Purged temporary PCAPs. Disk space reclaimed.")

  elapsed = time.time() - start_time
  summary = {
      "phase": "Phase 2 Smoke Test",
      "target_sessions": target_sessions,
      "sessions_extracted": len(raw_features_collected),
      "feature_matrix_shape": list(matrix.shape),
      "failed_pcaps": failed_pcaps,
      "elapsed_seconds": round(elapsed, 2),
      "parquet_path": str(features_parquet),
      "status": "PASSED",
  }

  summary_path = output_dir / "smoke_test_summary.json"
  with open(summary_path, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2)

  print(f"Smoke test completed successfully in {elapsed:.2f}s!")
  return summary


if __name__ == "__main__":
  run_phase_2_smoke_test(100)
