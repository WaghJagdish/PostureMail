"""Range-based streaming reader and batch extractor for CipherSpectrum ZIP archives.

Provides:
- Manifest of all entries inside the archive (with domain, filename, size).
- Selective batch extraction of raw PCAPs to a temporary directory without downloading the entire 3.5GB archive.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import urllib.request
import zipfile
from typing import Final


class HttpRangeFile(io.RawIOBase):
  """Exposes a file-like seekable read-only stream over HTTP Range requests."""

  def __init__(self, url: str, headers: dict[str, str] | None = None) -> None:
    self.url: Final[str] = url
    self.headers: dict[str, str] = headers or {"User-Agent": "Mozilla/5.0"}
    self._pos = 0

    # Probe file size
    req = urllib.request.Request(self.url, headers=self.headers, method="HEAD")
    with urllib.request.urlopen(req, timeout=15) as resp:
      cl = resp.headers.get("Content-Length")
      if not cl:
        raise ValueError("Server does not advertise Content-Length")
      self._size = int(cl)

  def seekable(self) -> bool:
    return True

  def readable(self) -> bool:
    return True

  def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
    if whence == io.SEEK_SET:
      self._pos = offset
    elif whence == io.SEEK_CUR:
      self._pos += offset
    elif whence == io.SEEK_END:
      self._pos = self._size + offset
    else:
      raise ValueError(f"Invalid whence: {whence}")
    return self._pos

  def tell(self) -> int:
    return self._pos

  def read(self, size: int = -1) -> bytes:
    if size < 0:
      size = self._size - self._pos
    if self._pos >= self._size or size == 0:
      return b""

    end = min(self._pos + size - 1, self._size - 1)
    headers = dict(self.headers)
    headers["Range"] = f"bytes={self._pos}-{end}"

    req = urllib.request.Request(self.url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
      data = resp.read()
      self._pos += len(data)
      return data


def get_archive_manifest(url: str, output_path: Path) -> list[str]:
  """Extract full file list of PCAPs from remote ZIP central directory."""
  if output_path.exists():
    with open(output_path, "r", encoding="utf-8") as f:
      return json.load(f)

  f = HttpRangeFile(url)
  zf = zipfile.ZipFile(f)
  pcap_names = [
      n
      for n in zf.namelist()
      if n.endswith(".pcap") and not n.startswith("__MACOSX")
  ]

  output_path.parent.mkdir(parents=True, exist_ok=True)
  with open(output_path, "w", encoding="utf-8") as f_out:
    json.dump(pcap_names, f_out, indent=2)

  return pcap_names


def extract_batch(
    url: str, member_names: list[str], target_dir: Path
) -> list[Path]:
  """Stream and extract a selected list of member PCAPs directly into target_dir."""
  target_dir.mkdir(parents=True, exist_ok=True)
  f = HttpRangeFile(url)
  zf = zipfile.ZipFile(f)

  extracted_paths: list[Path] = []
  for member in member_names:
    filename = Path(member).name
    dest_path = target_dir / filename
    with zf.open(member) as src, open(dest_path, "wb") as dst:
      dst.write(src.read())
    extracted_paths.append(dest_path)

  return extracted_paths


if __name__ == "__main__":
  url = "https://cspectrum.web.cse.unsw.edu.au/cipherspectrum/aes-128-gcm.zip"
  manifest_file = Path("data/cipherspectrum_aes128_manifest.json")
  pcaps = get_archive_manifest(url, manifest_file)
  print(f"Total PCAPs indexed in AES-128 archive: {len(pcaps)}")
  domains = set(p.split("/")[1] for p in pcaps if len(p.split("/")) > 2)
  print(f"Total distinct domains: {len(domains)}")
  print(f"Domains sample: {sorted(list(domains))[:10]}")
