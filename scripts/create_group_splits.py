"""Phase 4: Construct Group-Aware Train / Validation / Test Splits.

Splits sessions strictly by DOMAIN / CAPTURE group to eliminate data leakage.
Partitions the 41 domains into:
- TRAIN: ~70% of groups (29 domains)
- VALIDATION: ~15% of groups (6 domains)
- TEST: ~15% of groups (6 domains)

Persists immutable manifests:
- data/splits/train_manifest.json
- data/splits/validation_manifest.json
- data/splits/test_manifest.json
- data/splits/split_config.json
- data/splits/split_hashes.json
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import random

import pandas as pd


def make_group_aware_splits(
    dataset_manifest_path: Path = Path(
        "data/datasets/quality_gate_1k/session_manifest.json"
    ),
    seed: int = 42,
) -> dict:
  print("=== Phase 4: Constructing Group-Aware Splits (Zero-Leakage) ===")

  with open(dataset_manifest_path, "r", encoding="utf-8") as f:
    sessions: list[dict] = json.load(f)

  # Extract group (domain) from each session
  # PCAP naming convention in CipherSpectrum: traffic_YYYY-MM-DD_domain_cipher_browser_run.pcap...
  domain_sessions: dict[str, list[dict]] = {}
  for s in sessions:
    pcap_name = s.get("source_pcap", "")
    parts = pcap_name.split("_")
    if len(parts) >= 3:
      domain = parts[2]
    else:
      domain = s.get("sni") or "unknown_domain"
    domain_sessions.setdefault(domain, []).append(s)

  all_domains = sorted(list(domain_sessions.keys()))
  print(
      f"Identified {len(all_domains)} distinct domain groups across"
      f" {len(sessions)} sessions."
  )

  # Deterministic domain shuffling with fixed seed
  rng = random.Random(seed)
  shuffled_domains = list(all_domains)
  rng.shuffle(shuffled_domains)

  n_domains = len(shuffled_domains)
  n_test = max(1, int(round(n_domains * 0.15)))
  n_val = max(1, int(round(n_domains * 0.15)))
  n_train = n_domains - n_test - n_val

  train_domains = sorted(shuffled_domains[:n_train])
  val_domains = sorted(shuffled_domains[n_train : n_train + n_val])
  test_domains = sorted(shuffled_domains[n_train + n_val :])

  print(
      f"Domain Split: Train={len(train_domains)}, Val={len(val_domains)},"
      f" Test={len(test_domains)}"
  )
  print(f"  Validation Domains (Unseen in Train): {val_domains}")
  print(f"  Test Domains (Strictly Immutable): {test_domains}")

  # Assign sessions by domain
  train_sessions: list[dict] = []
  val_sessions: list[dict] = []
  test_sessions: list[dict] = []

  for d in train_domains:
    train_sessions.extend(domain_sessions[d])
  for d in val_domains:
    val_sessions.extend(domain_sessions[d])
  for d in test_domains:
    test_sessions.extend(domain_sessions[d])

  print(
      f"Session Split: Train={len(train_sessions)}, Val={len(val_sessions)},"
      f" Test={len(test_sessions)}"
  )

  # Compute hashes for auditability and leakage verification
  def _hash_manifest(obj: list) -> str:
    serialized = json.dumps(obj, sort_keys=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

  train_hash = _hash_manifest(train_sessions)
  val_hash = _hash_manifest(val_sessions)
  test_hash = _hash_manifest(test_sessions)

  # Assert zero group overlap
  assert (
      set(train_domains).isdisjoint(set(val_domains))
  ), "Train and Validation domains overlap!"
  assert (
      set(train_domains).isdisjoint(set(test_domains))
  ), "Train and Test domains overlap!"
  assert (
      set(val_domains).isdisjoint(set(test_domains))
  ), "Validation and Test domains overlap!"

  splits_dir = Path("data/splits")
  splits_dir.mkdir(parents=True, exist_ok=True)

  with open(splits_dir / "train_manifest.json", "w", encoding="utf-8") as f:
    json.dump(
        {"domains": train_domains, "sessions": train_sessions}, f, indent=2
    )
  with open(
      splits_dir / "validation_manifest.json", "w", encoding="utf-8"
  ) as f:
    json.dump({"domains": val_domains, "sessions": val_sessions}, f, indent=2)
  with open(splits_dir / "test_manifest.json", "w", encoding="utf-8") as f:
    json.dump({"domains": test_domains, "sessions": test_sessions}, f, indent=2)

  split_config = {
      "strategy": "Domain/Group-Level Partitioning",
      "seed": seed,
      "train_domains_count": len(train_domains),
      "val_domains_count": len(val_domains),
      "test_domains_count": len(test_domains),
      "train_sessions_count": len(train_sessions),
      "val_sessions_count": len(val_sessions),
      "test_sessions_count": len(test_sessions),
      "train_domains": train_domains,
      "val_domains": val_domains,
      "test_domains": test_domains,
  }
  with open(splits_dir / "split_config.json", "w", encoding="utf-8") as f:
    json.dump(split_config, f, indent=2)

  split_hashes = {
      "train_manifest_sha256": train_hash,
      "validation_manifest_sha256": val_hash,
      "test_manifest_sha256": test_hash,
  }
  with open(splits_dir / "split_hashes.json", "w", encoding="utf-8") as f:
    json.dump(split_hashes, f, indent=2)

  print(
      f"Phase 4 Complete: Group splits locked and saved to {splits_dir} with"
      " SHA-256 manifests."
  )
  return split_config


if __name__ == "__main__":
  make_group_aware_splits()
