"""High-performance, passive PCAP and PCAPNG streaming ingestion layer.

This module provides a unified `PcapReader` abstraction yielding normalized
`RawPacket` records, streaming metadata calculation (including SHA-256),
strict magic byte validation, link layer normalization (Ethernet, Linux SLL/SLL2,
RAW IPv4, Loopback, 802.11), 802.1Q / QinQ VLAN unwrapping, truncation handling,
and malformed packet error budgets.
"""

from __future__ import annotations

import hashlib
import io
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Final

from pecff.config import settings

# -----------------------------------------------------------------------------
# PCAP Magic Constants
# -----------------------------------------------------------------------------
MAGIC_PCAP_MICROSECONDS_BE: Final[bytes] = b"\xa1\xb2\xc3\xd4"
MAGIC_PCAP_MICROSECONDS_LE: Final[bytes] = b"\xd4\xc3\xb2\xa1"
MAGIC_PCAP_NANOSECONDS_BE: Final[bytes] = b"\xa1\xb2\x3c\x4d"
MAGIC_PCAP_NANOSECONDS_LE: Final[bytes] = b"\x4d\x3c\xb2\xa1"
MAGIC_PCAPNG_SHB: Final[bytes] = b"\x0a\x0d\x0d\x0a"
PCAPNG_BYTE_ORDER_MAGIC_BE: Final[int] = 0x1A2B3C4D
PCAPNG_BYTE_ORDER_MAGIC_LE: Final[int] = 0x4D3C2B1A

# Link Layer Types (DLT / LinkType)
LINKTYPE_NULL: Final[int] = 0
LINKTYPE_ETHERNET: Final[int] = 1  # EN10MB
LINKTYPE_RAW_OLD: Final[int] = 101  # RAW IP
LINKTYPE_IEEE802_11: Final[int] = 105
LINKTYPE_LINUX_SLL: Final[int] = 113  # Linux cooked v1
LINKTYPE_IEEE802_11_RADIO: Final[int] = 127  # Radiotap
LINKTYPE_RAW: Final[int] = 228  # DLT_IPV4 / DLT_RAW
LINKTYPE_LINUX_SLL2: Final[int] = 276  # Linux cooked v2

# EtherTypes
ETHERTYPE_IPV4: Final[int] = 0x0800
ETHERTYPE_ARP: Final[int] = 0x0806
ETHERTYPE_VLAN_8021Q: Final[int] = 0x8100
ETHERTYPE_IPV6: Final[int] = 0x86DD
ETHERTYPE_VLAN_QINQ_88A8: Final[int] = 0x88A8
ETHERTYPE_VLAN_QINQ_9100: Final[int] = 0x9100
ETHERTYPE_VLAN_QINQ_9200: Final[int] = 0x9200


class PcapError(Exception):
    """Base exception for all PCAP ingestion failures."""


class UnsupportedCaptureFormat(PcapError):
    """Raised when file magic bytes do not match any recognized PCAP/PCAPNG format."""

    def __init__(self, message: str, observed_bytes: bytes) -> None:
        super().__init__(f"{message} (observed magic: {observed_bytes!r})")
        self.observed_bytes = observed_bytes


class CaptureTooCorrupt(PcapError):
    """Raised when the ratio of corrupt/malformed packets exceeds the allowed budget."""

    def __init__(self, corrupt_count: int, total_count: int, ratio: float, budget: float) -> None:
        super().__init__(
            f"Capture corruption budget exceeded: {corrupt_count}/{total_count} "
            f"({ratio:.2%}) corrupt records exceeds max allowed {budget:.2%}"
        )
        self.corrupt_count = corrupt_count
        self.total_count = total_count
        self.ratio = ratio
        self.budget = budget


@dataclass(frozen=True, slots=True)
class RawPacket:
    """Normalized raw packet representation with stripped L2 header."""

    index: int  # 0-based position in file
    ts: float  # epoch seconds, float64
    caplen: int
    wirelen: int
    vlan_id: int | None
    payload: memoryview  # points at the L3 header (IPv4/IPv6), VLAN/L2 stripped


@dataclass(frozen=True, slots=True)
class CaptureMetadata:
    """Forensic metadata summarizing capture file properties."""

    filename: str
    sha256: str
    size_bytes: int
    format: str  # 'pcap' or 'pcapng'
    link_type: int
    snaplen: int
    capture_start: float | None
    capture_end: float | None
    packet_count: int
    truncated: bool
    warnings: list[str]


class PcapReader:
    """Streaming reader for classic PCAP and PCAPNG files.

    Features:
    - Zero-allocation memoryview payload slicing.
    - Constant memory footprint independent of file size.
    - Streaming SHA-256 calculation.
    - Robust link-layer normalization & VLAN unwrapping.
    - Error budgeting with graceful corruption skipping.
    """

    def __init__(self, source: str | Path | BinaryIO | bytes) -> None:
        """Initialize reader from file path, stream, or bytes."""
        self._filename: str = "stream"
        self._stream: BinaryIO
        self._should_close: bool = False
        self._size_bytes: int = 0

        if isinstance(source, (str, Path)):
            p = Path(source)
            self._filename = str(p.name)
            self._size_bytes = p.stat().st_size if p.exists() else 0
            self._stream = open(p, "rb")  # noqa: SIM115
            self._should_close = True
        elif isinstance(source, bytes):
            self._filename = "memory.pcap"
            self._size_bytes = len(source)
            self._stream = io.BytesIO(source)
        else:
            self._stream = source
            # Try to get stream size if possible
            try:
                curr = self._stream.tell()
                self._stream.seek(0, io.SEEK_END)
                self._size_bytes = self._stream.tell()
                self._stream.seek(curr, io.SEEK_SET)
            except Exception:  # pragma: no cover
                self._size_bytes = 0

        self.warnings: list[str] = []
        self.truncated: bool = False
        self.format: str = "unknown"
        self.link_type: int = LINKTYPE_ETHERNET
        self.snaplen: int = settings.max_packet_size_bytes
        self.endianness: str = "<"  # '<' for little, '>' for big
        self.ts_is_nanoseconds: bool = False

        self._packet_count: int = 0
        self._malformed_count: int = 0
        self._capture_start: float | None = None
        self._capture_end: float | None = None

        # Pre-validate header and format
        self._init_header()

    def close(self) -> None:
        """Close underlying stream if owned by this instance."""
        if self._should_close:
            self._stream.close()

    def __enter__(self) -> PcapReader:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object | None,
    ) -> None:
        self.close()

    def _init_header(self) -> None:
        """Validate magic bytes and parse global header."""
        self._stream.seek(0, io.SEEK_SET)
        magic = self._stream.read(4)
        if len(magic) < 4:
            raise UnsupportedCaptureFormat("File truncated before magic bytes", magic)

        if magic == MAGIC_PCAP_MICROSECONDS_LE:
            self.format = "pcap"
            self.endianness = "<"
            self.ts_is_nanoseconds = False
            self._parse_classic_pcap_header()
        elif magic == MAGIC_PCAP_MICROSECONDS_BE:
            self.format = "pcap"
            self.endianness = ">"
            self.ts_is_nanoseconds = False
            self._parse_classic_pcap_header()
        elif magic == MAGIC_PCAP_NANOSECONDS_LE:
            self.format = "pcap"
            self.endianness = "<"
            self.ts_is_nanoseconds = True
            self._parse_classic_pcap_header()
        elif magic == MAGIC_PCAP_NANOSECONDS_BE:
            self.format = "pcap"
            self.endianness = ">"
            self.ts_is_nanoseconds = True
            self._parse_classic_pcap_header()
        elif magic == MAGIC_PCAPNG_SHB:
            self.format = "pcapng"
            self._parse_pcapng_shb()
        else:
            raise UnsupportedCaptureFormat(
                "Unrecognized capture magic bytes. Expected PCAP or PCAPNG header", magic
            )

        if self.snaplen < settings.min_recommended_snaplen:
            self.warnings.append(
                f"Snaplen {self.snaplen} is less than recommended {settings.min_recommended_snaplen} bytes; "
                "TLS handshake records may be cut mid-message."
            )

    def _parse_classic_pcap_header(self) -> None:
        """Parse classic PCAP 24-byte global header."""
        header_bytes = self._stream.read(20)  # already read 4 magic bytes
        if len(header_bytes) < 20:
            raise UnsupportedCaptureFormat("Truncated PCAP global header", header_bytes)

        fmt = f"{self.endianness}HHIIII"
        (
            _version_major,
            _version_minor,
            _thiszone,
            _sigfigs,
            self.snaplen,
            self.link_type,
        ) = struct.unpack(fmt, header_bytes)

    def _parse_pcapng_shb(self) -> None:
        """Parse initial PCAPNG Section Header Block and Interface Description Block."""
        # Read the rest of SHB
        block_len_bytes = self._stream.read(4)
        if len(block_len_bytes) < 4:
            raise UnsupportedCaptureFormat("Truncated PCAPNG Section Header Block", block_len_bytes)

        # Determine byte order from byte order magic at offset 8
        bom = self._stream.read(4)
        if len(bom) < 4:
            raise UnsupportedCaptureFormat("Truncated PCAPNG Byte Order Magic", bom)

        if bom == b"\x1a\x2b\x3c\x4d":
            self.endianness = ">"
        elif bom == b"\x4d\x3c\x2b\x1a":
            self.endianness = "<"
        else:
            raise UnsupportedCaptureFormat("Invalid PCAPNG Byte Order Magic", bom)

        (shb_len,) = struct.unpack(f"{self.endianness}I", block_len_bytes)
        if shb_len < 28:
            raise UnsupportedCaptureFormat("Invalid PCAPNG SHB length", block_len_bytes)

        # Skip remaining bytes of SHB (we already read 4 type + 4 len + 4 BOM = 12 bytes)
        remaining_shb = shb_len - 12
        shb_body = self._stream.read(remaining_shb)
        if len(shb_body) < remaining_shb:
            self.truncated = True
            return

        # Next block is typically Interface Description Block (IDB, type 0x00000001)
        # Scan forward to find first IDB
        saved_pos = self._stream.tell()
        block_hdr = self._stream.read(8)
        if len(block_hdr) == 8:
            b_type, b_len = struct.unpack(f"{self.endianness}II", block_hdr)
            if b_type == 1 and b_len >= 16:  # IDB
                idb_body = self._stream.read(b_len - 8)
                if len(idb_body) >= 8:
                    self.link_type, _reserved, self.snaplen = struct.unpack(
                        f"{self.endianness}HHI", idb_body[:8]
                    )
        self._stream.seek(saved_pos, io.SEEK_SET)

    def __iter__(self) -> Iterator[RawPacket]:
        """Iterate over packets in the capture."""
        return self.packets()

    def packets(self) -> Iterator[RawPacket]:
        """Yield normalized RawPacket instances from the capture stream.

        Never buffers more than one packet in memory.
        """
        if self.format == "pcap":
            yield from self._read_classic_packets()
        elif self.format == "pcapng":
            yield from self._read_pcapng_packets()

    def read_packets(self) -> Iterator[RawPacket]:
        """Alias for packets()."""
        return self.packets()

    def _read_classic_packets(self) -> Iterator[RawPacket]:
        """Iterate over classic PCAP records."""
        # Seek past 24-byte global header
        self._stream.seek(24, io.SEEK_SET)
        packet_idx = 0

        while True:
            hdr_bytes = self._stream.read(16)
            if not hdr_bytes:
                break  # Clean EOF

            if len(hdr_bytes) < 16:
                # Truncated record header at end of file
                self.truncated = True
                break

            ts_sec, ts_subsec, caplen, wirelen = struct.unpack(f"{self.endianness}IIII", hdr_bytes)

            # Caplen sanity check
            if caplen > settings.max_packet_size_bytes or caplen < 0:
                self._malformed_count += 1
                self.warnings.append(
                    f"Packet {packet_idx}: Declared caplen {caplen} exceeds max allowed {settings.max_packet_size_bytes}."
                )
                self._check_corrupt_budget(packet_idx + 1)
                break

            data = self._stream.read(caplen)
            if len(data) < caplen:
                self.truncated = True
                break

            # Calculate timestamp
            if self.ts_is_nanoseconds:
                ts = float(ts_sec) + (float(ts_subsec) / 1_000_000_000.0)
            else:
                ts = float(ts_sec) + (float(ts_subsec) / 1_000_000.0)

            # Update capture time bounds
            if self._capture_start is None or ts < self._capture_start:
                self._capture_start = ts
            if self._capture_end is None or ts > self._capture_end:
                self._capture_end = ts

            # Normalize Link Layer to L3 payload
            try:
                l3_offset, vlan_id = self._strip_link_layer(data, self.link_type)
                if l3_offset is None or l3_offset > len(data):
                    self._malformed_count += 1
                    self.warnings.append(
                        f"Packet {packet_idx}: Failed to parse link type {self.link_type}."
                    )
                    self._check_corrupt_budget(packet_idx + 1)
                    packet_idx += 1
                    continue

                mv = memoryview(data)[l3_offset:]
                yield RawPacket(
                    index=packet_idx,
                    ts=ts,
                    caplen=caplen,
                    wirelen=wirelen,
                    vlan_id=vlan_id,
                    payload=mv,
                )
            except Exception as e:
                self._malformed_count += 1
                self.warnings.append(f"Packet {packet_idx}: Malformed packet data ({e}).")
                self._check_corrupt_budget(packet_idx + 1)

            packet_idx += 1

        self._packet_count = packet_idx

    def _read_pcapng_packets(self) -> Iterator[RawPacket]:
        """Iterate over PCAPNG blocks and yield Enhanced / Simple Packet Blocks."""
        self._stream.seek(0, io.SEEK_SET)
        packet_idx = 0
        current_link_type = self.link_type
        if_tsresol_divisor = 1_000_000.0  # default 10^-6 (microseconds)

        while True:
            block_hdr = self._stream.read(8)
            if not block_hdr:
                break
            if len(block_hdr) < 8:
                self.truncated = True
                break

            block_type, block_len = struct.unpack(f"{self.endianness}II", block_hdr)
            if block_len < 12:
                self._malformed_count += 1
                self.warnings.append(
                    f"PCAPNG block length {block_len} is invalid at packet index {packet_idx}."
                )
                self._check_corrupt_budget(packet_idx + 1)
                break

            body_len = block_len - 12
            body = self._stream.read(body_len)
            trailer = self._stream.read(4)

            if len(body) < body_len or len(trailer) < 4:
                self.truncated = True
                break

            # Process block types
            if block_type == 1:  # Interface Description Block (IDB)
                if len(body) >= 8:
                    current_link_type, _reserved, snaplen = struct.unpack(
                        f"{self.endianness}HHI", body[:8]
                    )
                    self.link_type = current_link_type
                    self.snaplen = snaplen
                    # Parse options if present (e.g. if_tsresol)
                    opt_offset = 8
                    while opt_offset + 4 <= len(body):
                        opt_code, opt_len = struct.unpack(
                            f"{self.endianness}HH", body[opt_offset : opt_offset + 4]
                        )
                        if opt_code == 0:  # opt_endofopt
                            break
                        if opt_code == 9 and opt_len >= 1:  # if_tsresol
                            res_byte = body[opt_offset + 4]
                            if (res_byte & 0x80) == 0:
                                if_tsresol_divisor = 10.0 ** (res_byte & 0x7F)
                            else:
                                if_tsresol_divisor = 2.0 ** (res_byte & 0x7F)
                        padded_opt_len = (opt_len + 3) & ~3
                        opt_offset += 4 + padded_opt_len

            elif block_type == 6:  # Enhanced Packet Block (EPB)
                if len(body) >= 20:
                    _if_id, ts_high, ts_low, caplen, wirelen = struct.unpack(
                        f"{self.endianness}IIIII", body[:20]
                    )
                    raw_ts = (ts_high << 32) | ts_low
                    ts = float(raw_ts) / if_tsresol_divisor

                    if self._capture_start is None or ts < self._capture_start:
                        self._capture_start = ts
                    if self._capture_end is None or ts > self._capture_end:
                        self._capture_end = ts

                    pkt_data = body[20 : 20 + caplen]
                    if len(pkt_data) < caplen:
                        self.truncated = True
                        break

                    try:
                        l3_offset, vlan_id = self._strip_link_layer(pkt_data, current_link_type)
                        if l3_offset is None or l3_offset > len(pkt_data):
                            self._malformed_count += 1
                            self.warnings.append(
                                f"Packet {packet_idx}: Failed to parse link type {current_link_type}."
                            )
                            self._check_corrupt_budget(packet_idx + 1)
                            packet_idx += 1
                            continue

                        mv = memoryview(pkt_data)[l3_offset:]
                        yield RawPacket(
                            index=packet_idx,
                            ts=ts,
                            caplen=caplen,
                            wirelen=wirelen,
                            vlan_id=vlan_id,
                            payload=mv,
                        )
                    except Exception as e:
                        self._malformed_count += 1
                        self.warnings.append(f"Packet {packet_idx}: Malformed packet data ({e}).")
                        self._check_corrupt_budget(packet_idx + 1)

                    packet_idx += 1

            elif block_type == 3 and len(body) >= 4:  # Simple Packet Block (SPB)
                (wirelen,) = struct.unpack(f"{self.endianness}I", body[:4])
                caplen = min(wirelen, self.snaplen, len(body) - 4)
                pkt_data = body[4 : 4 + caplen]
                ts = self._capture_end or 0.0

                try:
                    l3_offset, vlan_id = self._strip_link_layer(pkt_data, current_link_type)
                    if l3_offset is not None and l3_offset <= len(pkt_data):
                        mv = memoryview(pkt_data)[l3_offset:]
                        yield RawPacket(
                            index=packet_idx,
                            ts=ts,
                            caplen=caplen,
                            wirelen=wirelen,
                            vlan_id=vlan_id,
                            payload=mv,
                        )
                except Exception as e:
                    self._malformed_count += 1
                    self.warnings.append(f"Packet {packet_idx}: Malformed SPB packet ({e}).")
                    self._check_corrupt_budget(packet_idx + 1)

                packet_idx += 1

        self._packet_count = packet_idx

    @staticmethod
    def _strip_link_layer(data: bytes, link_type: int) -> tuple[int | None, int | None]:
        """Strip L2 header, unwrap VLAN tags (802.1Q/QinQ), and return (l3_offset, vlan_id).

        Returns:
            (l3_offset, vlan_id) or (None, None) if parsing fails.
        """
        data_len = len(data)
        if data_len == 0:
            return None, None

        if link_type == LINKTYPE_ETHERNET:  # 1 (EN10MB)
            if data_len < 14:
                return None, None
            ethertype = struct.unpack_from(">H", data, 12)[0]
            offset = 14
            outer_vlan: int | None = None

            # Unwrap 802.1Q and QinQ tags
            while ethertype in (
                ETHERTYPE_VLAN_8021Q,
                ETHERTYPE_VLAN_QINQ_88A8,
                ETHERTYPE_VLAN_QINQ_9100,
                ETHERTYPE_VLAN_QINQ_9200,
            ):
                if offset + 4 > data_len:
                    return None, None
                tci, next_ethertype = struct.unpack_from(">HH", data, offset)
                if outer_vlan is None:
                    outer_vlan = tci & 0x0FFF
                ethertype = next_ethertype
                offset += 4

            return offset, outer_vlan

        elif link_type == LINKTYPE_LINUX_SLL:  # 113 (Linux cooked v1)
            if data_len < 16:
                return None, None
            protocol = struct.unpack_from(">H", data, 14)[0]
            offset = 16
            outer_vlan = None

            while protocol in (
                ETHERTYPE_VLAN_8021Q,
                ETHERTYPE_VLAN_QINQ_88A8,
                ETHERTYPE_VLAN_QINQ_9100,
                ETHERTYPE_VLAN_QINQ_9200,
            ):
                if offset + 4 > data_len:
                    return None, None
                tci, next_proto = struct.unpack_from(">HH", data, offset)
                if outer_vlan is None:
                    outer_vlan = tci & 0x0FFF
                protocol = next_proto
                offset += 4

            return offset, outer_vlan

        elif link_type == LINKTYPE_LINUX_SLL2:  # 276 (Linux cooked v2)
            if data_len < 20:
                return None, None
            protocol = struct.unpack_from(">H", data, 0)[0]
            offset = 20
            outer_vlan = None

            while protocol in (
                ETHERTYPE_VLAN_8021Q,
                ETHERTYPE_VLAN_QINQ_88A8,
                ETHERTYPE_VLAN_QINQ_9100,
                ETHERTYPE_VLAN_QINQ_9200,
            ):
                if offset + 4 > data_len:
                    return None, None
                tci, next_proto = struct.unpack_from(">HH", data, offset)
                if outer_vlan is None:
                    outer_vlan = tci & 0x0FFF
                protocol = next_proto
                offset += 4

            return offset, outer_vlan

        elif link_type in (LINKTYPE_RAW, LINKTYPE_RAW_OLD):  # 228, 101
            # Raw IPv4 / IPv6 directly
            return 0, None

        elif link_type == LINKTYPE_NULL:  # 0 (BSD loopback)
            if data_len < 4:
                return None, None
            return 4, None

        elif link_type == LINKTYPE_IEEE802_11:  # 105
            if data_len < 24:
                return None, None
            fc = struct.unpack_from("<H", data, 0)[0]
            frame_type = (fc >> 2) & 0x3
            if frame_type != 2:  # Data frame
                return None, None
            to_ds = (fc >> 8) & 0x1
            from_ds = (fc >> 9) & 0x1
            hdr_len = 30 if (to_ds and from_ds) else 24
            # Check QoS bit
            subtype = (fc >> 4) & 0xF
            if subtype & 0x8:
                hdr_len += 2  # QoS control field
            # Check LLC/SNAP header (8 bytes: AA AA 03 00 00 00 + EtherType)
            if (
                data_len >= hdr_len + 8
                and data[hdr_len : hdr_len + 6] == b"\xaa\xaa\x03\x00\x00\x00"
            ):
                hdr_len += 8
            return hdr_len, None

        elif link_type == LINKTYPE_IEEE802_11_RADIO:  # 127 (Radiotap)
            if data_len < 4:
                return None, None
            radiotap_len = struct.unpack_from("<H", data, 2)[0]
            if data_len < radiotap_len:
                return None, None
            dot11_data = data[radiotap_len:]
            sub_offset, vlan = PcapReader._strip_link_layer(dot11_data, LINKTYPE_IEEE802_11)
            if sub_offset is None:
                return None, None
            return radiotap_len + sub_offset, vlan

        # Fallback for unrecognized link layer
        return 0, None

    def _check_corrupt_budget(self, total: int) -> None:
        """Check if malformed packets exceed the corruption budget.

        Requires a minimum sample size (20 packets) to prevent small-sample
        variance false positives at the beginning of a capture.
        """
        if total >= 20:
            ratio = float(self._malformed_count) / float(total)
            if ratio > settings.corrupt_packet_budget_ratio:
                raise CaptureTooCorrupt(
                    corrupt_count=self._malformed_count,
                    total_count=total,
                    ratio=ratio,
                    budget=settings.corrupt_packet_budget_ratio,
                )

    def get_metadata(self) -> CaptureMetadata:
        """Compute and return complete forensic capture metadata.

        Calculates streaming SHA-256 without buffering the file into memory.
        """
        # Save position and compute SHA-256
        saved_pos = self._stream.tell()
        self._stream.seek(0, io.SEEK_SET)

        hasher = hashlib.sha256()
        chunk_size = settings.sha256_chunk_size_bytes
        total_read = 0

        while True:
            chunk = self._stream.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
            total_read += len(chunk)

        sha256_hex = hasher.hexdigest()
        file_size = self._size_bytes if self._size_bytes > 0 else total_read
        self._stream.seek(saved_pos, io.SEEK_SET)

        return CaptureMetadata(
            filename=self._filename,
            sha256=sha256_hex,
            size_bytes=file_size,
            format=self.format,
            link_type=self.link_type,
            snaplen=self.snaplen,
            capture_start=self._capture_start,
            capture_end=self._capture_end,
            packet_count=self._packet_count,
            truncated=self.truncated,
            warnings=list(self.warnings),
        )
