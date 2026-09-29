"""High-Throughput Parallel PCAP Downloader and Feature Extractor.

Batches requests across ThreadPoolExecutor workers and processes streams
using production SessionFeatureExtractor and SessionFeatureVectorizer.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path
import shutil
import sys
import time

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pecff.ml.features import (
    RawSessionFeatures,
    SessionFeatureExtractor,
    SessionFeatureVectorizer,
)
from scripts.fast_cs_indexer import extract_single_pcap
from scripts.pcap_to_features import extract_features_from_pcap

URL = "https://cspectrum.web.cse.unsw.edu.au/cipherspectrum/aes-128-gcm.zip"


def extract_batch_parallel(
    items: list[tuple[str, list[int]]],
    temp_dir: Path,
    extractor: SessionFeatureExtractor,
    max_workers: int = 16,
) -> tuple[list[RawSessionFeatures], list[dict]]:
  """Downloads and extracts features in parallel with immediate per-file disk purging."""
  temp_dir.mkdir(parents=True, exist_ok=True)
  raw_features: list[RawSessionFeatures] = []
  metas: list[dict] = []

  def _process_one(item):
    fname, (offset, comp, uncomp) = item
    p = temp_dir / Path(fname).name
    try:
      extract_single_pcap(URL, offset, comp, p)
      res = extract_features_from_pcap(p, extractor)
      return fname, res
    except Exception:
      return fname, []
    finally:
      if p.exists():
        p.unlink()

  with ThreadPoolExecutor(max_workers=max_workers) as pool:
    futures = [pool.submit(_process_one, item) for item in items]
    for fut in as_completed(futures):
      fname, res = fut.result()
      for meta, raw in res:
        meta["source_pcap"] = Path(fname).name
        metas.append(meta)
        raw_features.append(raw)

  return raw_features, metas
