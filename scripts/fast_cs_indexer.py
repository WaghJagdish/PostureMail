"""Optimized central directory reader for remote ZIP files over HTTP.

Directly fetches the End of Central Directory (EOCD) record at the end of the file,
then fetches the entire Central Directory in one single HTTP Range request.
This avoids thousands of small seeks and network roundtrips.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
import struct
import urllib.request
import zipfile


def read_central_directory_fast(
    url: str,
) -> tuple[dict[str, tuple[int, int, int]], int]:
  """Fetch the central directory in 2 HTTP Range requests.

  Returns (entries_dict, file_size) where entries_dict maps filename ->
  (offset_of_local_header, compressed_size, uncompressed_size).
  """
  headers = {"User-Agent": "Mozilla/5.0"}

  # Step 1: Probe file size
  req = urllib.request.Request(url, headers=headers, method="HEAD")
  with urllib.request.urlopen(req, timeout=15) as resp:
    size = int(resp.headers["Content-Length"])

  # Step 2: Read last 65KB to locate EOCD (End of Central Directory)
  probe_len = min(size, 65536)
  start_pos = size - probe_len
  req = urllib.request.Request(
      url, headers={**headers, "Range": f"bytes={start_pos}-{size-1}"}
  )
  with urllib.request.urlopen(req, timeout=20) as resp:
    tail = resp.read()

  # Find EOCD signature: 0x06054b50
  eocd_idx = tail.rfind(b"\x50\x4b\x05\x06")
  if eocd_idx == -1:
    raise ValueError("Could not find EOCD signature in ZIP tail")

  eocd = tail[eocd_idx : eocd_idx + 22]
  _, _, _, _, total_entries, cd_size, cd_offset, _ = struct.unpack(
      "<4sHHHHIIH", eocd
  )

  # Check if Zip64 is used (total_entries == 0xFFFF or cd_offset == 0xFFFFFFFF)
  if total_entries == 0xFFFF or cd_offset == 0xFFFFFFFF:
    # Locate Zip64 EOCD Locator: 0x07064b50
    zip64_loc_idx = tail.rfind(b"\x50\x4b\x06\x07", 0, eocd_idx)
    if zip64_loc_idx == -1:
      raise ValueError("Zip64 locator not found")
    loc = tail[zip64_loc_idx : zip64_loc_idx + 20]
    _, _, zip64_eocd_offset, _ = struct.unpack("<4sIIQ", loc)

    # Fetch Zip64 EOCD record
    req = urllib.request.Request(
        url,
        headers={
            **headers,
            "Range": f"bytes={zip64_eocd_offset}-{zip64_eocd_offset+56}",
        },
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
      zip64_eocd = resp.read()
    (
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        total_entries,
        cd_size,
        cd_offset,
    ) = struct.unpack("<4sQHHIIQQQQ", zip64_eocd[:56])

  print(
      f"Total entries: {total_entries}, CD Size: {cd_size} bytes, CD Offset:"
      f" {cd_offset}"
  )

  # Step 3: Fetch the entire Central Directory in ONE bulk request!
  req = urllib.request.Request(
      url,
      headers={**headers, "Range": f"bytes={cd_offset}-{cd_offset+cd_size-1}"},
  )
  with urllib.request.urlopen(req, timeout=60) as resp:
    cd_data = resp.read()

  # Parse Central Directory entries
  entries: dict[str, tuple[int, int, int]] = {}
  pos = 0
  cd_len = len(cd_data)
  while pos < cd_len:
    if cd_data[pos : pos + 4] != b"\x50\x4b\x01\x02":
      break
    (
        _,
        _,
        _,
        flags,
        method,
        _,
        _,
        crc,
        comp_size,
        uncomp_size,
        fname_len,
        extra_len,
        comment_len,
        _,
        _,
        _,
        local_hdr_offset,
    ) = struct.unpack("<4sHHHHHHIIIHHHHHII", cd_data[pos : pos + 46])

    fname_start = pos + 46
    fname_end = fname_start + fname_len
    filename = cd_data[fname_start:fname_end].decode("utf-8", errors="replace")

    pos = fname_end + extra_len + comment_len

    if filename.endswith(".pcap") and not filename.startswith("__MACOSX"):
      entries[filename] = (local_hdr_offset, comp_size, uncomp_size)

  return entries, size


def extract_single_pcap(
    url: str, local_hdr_offset: int, comp_size: int, output_file: Path
) -> None:
  """Fetch local header + compressed payload in 1 request and write decompressed PCAP."""
  headers = {"User-Agent": "Mozilla/5.0"}
  # 1. Fetch 30-byte fixed local header to determine exact variable header lengths
  req_hdr = urllib.request.Request(
      url,
      headers={
          **headers,
          "Range": f"bytes={local_hdr_offset}-{local_hdr_offset+29}",
      },
  )
  with urllib.request.urlopen(req_hdr, timeout=20) as resp:
    hdr_bytes = resp.read()

  if hdr_bytes[:4] != b"\x50\x4b\x03\x04":
    raise ValueError("Invalid local file header signature")

  _, _, _, method, _, _, _, _, _, fname_len, extra_len = struct.unpack(
      "<4sHHHHHIIIHH", hdr_bytes
  )
  data_start = local_hdr_offset + 30 + fname_len + extra_len
  data_end = data_start + comp_size - 1

  # 2. Fetch EXACT compressed payload in 1 Range request
  req_data = urllib.request.Request(
      url,
      headers={
          **headers,
          "Range": f"bytes={data_start}-{data_end}",
      },
  )
  with urllib.request.urlopen(req_data, timeout=30) as resp:
    payload = resp.read()

  if len(payload) != comp_size:
    raise ValueError(f"Payload truncated: expected {comp_size}, got {len(payload)}")

  if method == 0:  # Stored
    raw_pcap = payload
  elif method == 8:  # Deflated
    import zlib
    raw_pcap = zlib.decompress(payload, -15)
  else:
    raise ValueError(f"Unsupported compression method: {method}")

  output_file.parent.mkdir(parents=True, exist_ok=True)
  with open(output_file, "wb") as f_out:
    f_out.write(raw_pcap)



if __name__ == "__main__":
  url = "https://cspectrum.web.cse.unsw.edu.au/cipherspectrum/aes-128-gcm.zip"
  print("Fetching central directory in fast 2-step HTTP request...")
  entries, total_size = read_central_directory_fast(url)
  print(f"Successfully indexed {len(entries)} PCAPs!")

  # Save index to json
  out_path = Path("data/cipherspectrum_aes128_index.json")
  out_path.parent.mkdir(parents=True, exist_ok=True)
  with open(out_path, "w", encoding="utf-8") as f:
    json.dump(entries, f)
  print(f"Saved index to {out_path}")
