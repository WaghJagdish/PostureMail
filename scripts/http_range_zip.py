"""Range-based streaming reader for remote ZIP files.

Allows reading the central directory and extracting individual members without
downloading the full multi-gigabyte ZIP archive.
"""

from __future__ import annotations

import io
import struct
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


if __name__ == "__main__":
  url = "https://cspectrum.web.cse.unsw.edu.au/cipherspectrum/aes-128-gcm.zip"
  print("Probing remote zip with HttpRangeFile...")
  f = HttpRangeFile(url)
  print(f"Archive size: {f._size / (1024 * 1024 * 1024):.2f} GB")

  zf = zipfile.ZipFile(f)
  names = zf.namelist()
  print(f"Total entries in archive: {len(names)}")
  print("Sample first 10 entries:")
  for n in names[:10]:
    print(" ", n)
