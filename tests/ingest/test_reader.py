"""Comprehensive test suite for PcapReader and PCAP/PCAPNG ingestion."""

import hashlib
import io
import struct
import tempfile

import pytest

from pecff.ingest.reader import (
    LINKTYPE_ETHERNET,
    LINKTYPE_LINUX_SLL,
    LINKTYPE_LINUX_SLL2,
    LINKTYPE_NULL,
    LINKTYPE_RAW,
    MAGIC_PCAP_MICROSECONDS_BE,
    MAGIC_PCAP_MICROSECONDS_LE,
    MAGIC_PCAP_NANOSECONDS_BE,
    MAGIC_PCAP_NANOSECONDS_LE,
    MAGIC_PCAPNG_SHB,
    CaptureTooCorrupt,
    PcapReader,
    UnsupportedCaptureFormat,
)


def create_classic_pcap(
    packets: list[tuple[float, bytes]],
    link_type: int = LINKTYPE_ETHERNET,
    snaplen: int = 262144,
    nanoseconds: bool = False,
    big_endian: bool = False,
) -> bytes:
    """Helper to construct binary classic PCAP data."""
    endian = ">" if big_endian else "<"
    if nanoseconds:
        magic = MAGIC_PCAP_NANOSECONDS_BE if big_endian else MAGIC_PCAP_NANOSECONDS_LE
    else:
        magic = MAGIC_PCAP_MICROSECONDS_BE if big_endian else MAGIC_PCAP_MICROSECONDS_LE

    # Global header (24 bytes)
    hdr = magic + struct.pack(f"{endian}HHIIII", 2, 4, 0, 0, snaplen, link_type)

    buf = bytearray(hdr)
    for ts, pkt_data in packets:
        ts_sec = int(ts)
        ts_subsec = (
            int((ts - ts_sec) * 1_000_000_000) if nanoseconds else int((ts - ts_sec) * 1_000_000)
        )

        caplen = len(pkt_data)
        wirelen = caplen
        buf.extend(struct.pack(f"{endian}IIII", ts_sec, ts_subsec, caplen, wirelen))
        buf.extend(pkt_data)

    return bytes(buf)


def create_pcapng(
    packets: list[tuple[float, bytes]],
    link_type: int = LINKTYPE_ETHERNET,
    snaplen: int = 262144,
) -> bytes:
    """Helper to construct binary PCAPNG data."""
    buf = bytearray()
    endian = "<"

    # 1. Section Header Block (SHB)
    bom = b"\x4d\x3c\x2b\x1a"  # LE BOM
    shb_body = bom + struct.pack(f"{endian}HHq", 1, 0, -1)
    shb_len = 12 + len(shb_body)
    buf.extend(MAGIC_PCAPNG_SHB)
    buf.extend(struct.pack(f"{endian}I", shb_len))
    buf.extend(shb_body)
    buf.extend(struct.pack(f"{endian}I", shb_len))

    # 2. Interface Description Block (IDB)
    idb_body = struct.pack(f"{endian}HHI", link_type, 0, snaplen)
    idb_len = 12 + len(idb_body)
    buf.extend(struct.pack(f"{endian}II", 1, idb_len))
    buf.extend(idb_body)
    buf.extend(struct.pack(f"{endian}I", idb_len))

    # 3. Enhanced Packet Blocks (EPB)
    for ts, pkt_data in packets:
        raw_ts = int(ts * 1_000_000)
        ts_high = (raw_ts >> 32) & 0xFFFFFFFF
        ts_low = raw_ts & 0xFFFFFFFF
        caplen = len(pkt_data)
        wirelen = caplen

        # Pad to 32-bit boundary
        pad_len = (4 - (caplen % 4)) % 4
        padded_pkt = pkt_data + (b"\x00" * pad_len)

        epb_body = struct.pack(f"{endian}IIIII", 0, ts_high, ts_low, caplen, wirelen) + padded_pkt
        epb_len = 12 + len(epb_body)

        buf.extend(struct.pack(f"{endian}II", 6, epb_len))
        buf.extend(epb_body)
        buf.extend(struct.pack(f"{endian}I", epb_len))

    return bytes(buf)


# Sample IPv4 TCP SYN Packet payload
SAMPLE_IPV4_PAYLOAD = (
    b"\x45\x00\x00\x3c\x1a\x2b\x40\x00\x40\x06\xb1\x2c"  # IP header
    b"\xc0\xa8\x01\x0a"  # Src: 192.168.1.10
    b"\xc0\xa8\x01\x01"  # Dst: 192.168.1.1
    b"\x04\xd2\x00\x19\x00\x00\x00\x01\x00\x00\x00\x00"  # TCP 1234 -> 25
    b"\xa0\x02\x72\x10\x00\x00\x00\x00"
    b"\x02\x04\x05\xb4\x01\x03\x03\x08\x01\x01\x04\x02"
)


class TestPcapReaderMagicValidation:
    """Test magic bytes validation and header rejection."""

    def test_empty_file_rejected(self) -> None:
        with pytest.raises(UnsupportedCaptureFormat, match="truncated before magic"):
            PcapReader(b"")

    def test_short_file_rejected(self) -> None:
        with pytest.raises(UnsupportedCaptureFormat, match="truncated before magic"):
            PcapReader(b"\xa1\xb2")

    def test_invalid_magic_rejected(self) -> None:
        with pytest.raises(UnsupportedCaptureFormat, match="Unrecognized capture magic"):
            PcapReader(b"RIFF\x00\x00\x00\x00\x00\x00\x00\x00")

    def test_truncated_global_header_rejected(self) -> None:
        # 4 valid magic bytes but only 10 bytes total (needs 24)
        truncated_hdr = MAGIC_PCAP_MICROSECONDS_LE + b"\x00" * 6
        with pytest.raises(UnsupportedCaptureFormat, match="Truncated PCAP global header"):
            PcapReader(truncated_hdr)


class TestPcapReaderLinkLayers:
    """Test link layer normalization across Ethernet, VLAN, SLL, SLL2, RAW, and Loopback."""

    def test_ethernet_link_layer(self) -> None:
        eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"  # EtherType 0x0800
        packet = eth_hdr + SAMPLE_IPV4_PAYLOAD
        raw_pcap = create_classic_pcap([(1700000000.123456, packet)], link_type=LINKTYPE_ETHERNET)

        with PcapReader(raw_pcap) as reader:
            pkts = list(reader.packets())
            assert len(pkts) == 1
            assert pkts[0].index == 0
            assert abs(pkts[0].ts - 1700000000.123456) < 1e-5
            assert pkts[0].vlan_id is None
            assert bytes(pkts[0].payload) == SAMPLE_IPV4_PAYLOAD

    def test_vlan_8021q_single_tag(self) -> None:
        # EtherType 0x8100, VLAN ID = 42 (0x002A), next EtherType 0x0800
        vlan_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x81\x00\x00\x2a\x08\x00"
        packet = vlan_hdr + SAMPLE_IPV4_PAYLOAD
        raw_pcap = create_classic_pcap([(1700000001.0, packet)], link_type=LINKTYPE_ETHERNET)

        with PcapReader(raw_pcap) as reader:
            pkts = list(reader.packets())
            assert len(pkts) == 1
            assert pkts[0].vlan_id == 42
            assert bytes(pkts[0].payload) == SAMPLE_IPV4_PAYLOAD

    def test_qinq_stacked_vlan_tags(self) -> None:
        # Outer VLAN: 0x88A8, ID = 100, Inner VLAN: 0x8100, ID = 200, EtherType 0x0800
        qinq_hdr = (
            b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb"
            b"\x88\xa8\x00\x64\x81\x00\x00\xc8\x08\x00"
        )
        packet = qinq_hdr + SAMPLE_IPV4_PAYLOAD
        raw_pcap = create_classic_pcap([(1700000002.0, packet)], link_type=LINKTYPE_ETHERNET)

        with PcapReader(raw_pcap) as reader:
            pkts = list(reader.packets())
            assert len(pkts) == 1
            assert pkts[0].vlan_id == 100  # Outermost VLAN ID preserved
            assert bytes(pkts[0].payload) == SAMPLE_IPV4_PAYLOAD

    def test_linux_sll_cooked_v1(self) -> None:
        # 16-byte Linux SLL header with protocol 0x0800 at offset 14
        sll_hdr = b"\x00\x00\x03\x04\x00\x06\x00\x11\x22\x33\x44\x55\x00\x00\x08\x00"
        packet = sll_hdr + SAMPLE_IPV4_PAYLOAD
        raw_pcap = create_classic_pcap([(1700000003.0, packet)], link_type=LINKTYPE_LINUX_SLL)

        with PcapReader(raw_pcap) as reader:
            pkts = list(reader.packets())
            assert len(pkts) == 1
            assert bytes(pkts[0].payload) == SAMPLE_IPV4_PAYLOAD

    def test_linux_sll2_cooked_v2(self) -> None:
        # 20-byte Linux SLL2 header with protocol 0x0800 at offset 0
        sll2_hdr = (
            b"\x08\x00\x00\x00\x00\x00\x00\x01\x00\x01\x00\x06\x00\x11\x22\x33\x44\x55\x00\x00"
        )
        packet = sll2_hdr + SAMPLE_IPV4_PAYLOAD
        raw_pcap = create_classic_pcap([(1700000004.0, packet)], link_type=LINKTYPE_LINUX_SLL2)

        with PcapReader(raw_pcap) as reader:
            pkts = list(reader.packets())
            assert len(pkts) == 1
            assert bytes(pkts[0].payload) == SAMPLE_IPV4_PAYLOAD

    def test_raw_ipv4_link_layer(self) -> None:
        packet = SAMPLE_IPV4_PAYLOAD
        raw_pcap = create_classic_pcap([(1700000005.0, packet)], link_type=LINKTYPE_RAW)

        with PcapReader(raw_pcap) as reader:
            pkts = list(reader.packets())
            assert len(pkts) == 1
            assert pkts[0].vlan_id is None
            assert bytes(pkts[0].payload) == SAMPLE_IPV4_PAYLOAD

    def test_null_loopback_link_layer(self) -> None:
        # 4-byte family header (AF_INET = 2)
        null_hdr = b"\x02\x00\x00\x00"
        packet = null_hdr + SAMPLE_IPV4_PAYLOAD
        raw_pcap = create_classic_pcap([(1700000006.0, packet)], link_type=LINKTYPE_NULL)

        with PcapReader(raw_pcap) as reader:
            pkts = list(reader.packets())
            assert len(pkts) == 1
            assert bytes(pkts[0].payload) == SAMPLE_IPV4_PAYLOAD

    def test_nanosecond_and_big_endian_pcap(self) -> None:
        eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
        packet = eth_hdr + SAMPLE_IPV4_PAYLOAD
        raw_pcap = create_classic_pcap(
            [(1700000007.987654321, packet)],
            link_type=LINKTYPE_ETHERNET,
            nanoseconds=True,
            big_endian=True,
        )

        with PcapReader(raw_pcap) as reader:
            assert reader.endianness == ">"
            assert reader.ts_is_nanoseconds is True
            pkts = list(reader.packets())
            assert len(pkts) == 1
            assert abs(pkts[0].ts - 1700000007.987654321) < 1e-8


class TestPcapngSupport:
    """Test reading from PCAPNG captures."""

    def test_pcapng_packet_parsing(self) -> None:
        eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
        packet = eth_hdr + SAMPLE_IPV4_PAYLOAD
        pcapng_data = create_pcapng(
            [(1700000010.5, packet), (1700000011.5, packet)],
            link_type=LINKTYPE_ETHERNET,
        )

        with PcapReader(pcapng_data) as reader:
            assert reader.format == "pcapng"
            pkts = list(reader.packets())
            assert len(pkts) == 2
            assert pkts[0].index == 0
            assert pkts[1].index == 1
            assert abs(pkts[0].ts - 1700000010.5) < 1e-4
            assert bytes(pkts[0].payload) == SAMPLE_IPV4_PAYLOAD


class TestPcapReaderRobustness:
    """Test truncation detection, corrupt budget, metadata, and streaming rules."""

    def test_truncation_detection(self) -> None:
        eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
        packet = eth_hdr + SAMPLE_IPV4_PAYLOAD
        raw_pcap = create_classic_pcap([(1700000000.0, packet), (1700000001.0, packet)])

        # Chop off the last 40 bytes
        chopped_pcap = raw_pcap[:-40]

        with PcapReader(chopped_pcap) as reader:
            pkts = list(reader.packets())
            # First packet parsed successfully, second was truncated
            assert len(pkts) == 1
            assert reader.truncated is True

    def test_corrupt_budget_within_tolerance(self) -> None:
        # Create 100 packets, with 4 malformed (4% <= 5% budget)
        eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
        good_pkt = eth_hdr + SAMPLE_IPV4_PAYLOAD
        corrupt_pkt = b"\x00\x00\x00"  # Too short for Ethernet (< 14 bytes)

        packet_list: list[tuple[float, bytes]] = []
        for i in range(100):
            if i in (24, 49, 74, 99):
                packet_list.append((float(1700000000 + i), corrupt_pkt))
            else:
                packet_list.append((float(1700000000 + i), good_pkt))

        raw_pcap = create_classic_pcap(packet_list)

        with PcapReader(raw_pcap) as reader:
            pkts = list(reader.packets())
            # 96 good packets yielded
            assert len(pkts) == 96
            assert len(reader.warnings) == 4

    def test_corrupt_budget_exceeded(self) -> None:
        # Create 100 packets, with 6 malformed (6% > 5% budget)
        eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
        good_pkt = eth_hdr + SAMPLE_IPV4_PAYLOAD
        corrupt_pkt = b"\x00\x00\x00"

        packet_list: list[tuple[float, bytes]] = []
        for i in range(100):
            if i in (3, 6, 9, 12, 15, 18, 21):
                packet_list.append((float(1700000000 + i), corrupt_pkt))
            else:
                packet_list.append((float(1700000000 + i), good_pkt))

        raw_pcap = create_classic_pcap(packet_list)

        with pytest.raises(CaptureTooCorrupt) as exc_info, PcapReader(raw_pcap) as reader:
            list(reader.packets())

        assert exc_info.value.corrupt_count >= 6

    def test_streaming_sha256_metadata_match(self) -> None:
        eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
        packet = eth_hdr + SAMPLE_IPV4_PAYLOAD
        raw_pcap = create_classic_pcap([(1700000000.0, packet), (1700000001.0, packet)])

        expected_sha256 = hashlib.sha256(raw_pcap).hexdigest()

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            tf.write(raw_pcap)
            tf.flush()
            temp_path = tf.name

        with PcapReader(temp_path) as reader:
            meta = reader.get_metadata()
            assert meta.sha256 == expected_sha256
            assert meta.size_bytes == len(raw_pcap)
            assert meta.format == "pcap"
            assert meta.link_type == LINKTYPE_ETHERNET

    def test_snaplen_warning_issued(self) -> None:
        eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
        packet = eth_hdr + SAMPLE_IPV4_PAYLOAD
        raw_pcap = create_classic_pcap([(1700000000.0, packet)], snaplen=1500)

        with PcapReader(raw_pcap) as reader:
            assert len(reader.warnings) >= 1
            assert "Snaplen 1500 is less than recommended" in reader.warnings[0]


class TestScapyFixturesRoundTrip:
    """Test round-tripping packets generated via Scapy."""

    def test_scapy_ethernet_tcp_roundtrip(self) -> None:
        from scapy.layers.inet import IP, TCP
        from scapy.layers.l2 import Ether
        from scapy.utils import wrpcap

        scapy_pkts = [
            Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000 + i, dport=25, flags="S")
            for i in range(10)
        ]

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            pcap_path = tf.name

        wrpcap(pcap_path, scapy_pkts)

        with PcapReader(pcap_path) as reader:
            pkts = list(reader.packets())
            assert len(pkts) == 10
            for idx, pkt in enumerate(pkts):
                assert pkt.index == idx
                assert pkt.vlan_id is None
                assert len(pkt.payload) > 0
                # First byte of IPv4 header is 0x45 (version 4, header len 5)
                assert pkt.payload[0] == 0x45

    def test_scapy_vlan_roundtrip(self) -> None:
        from scapy.layers.inet import IP, TCP
        from scapy.layers.l2 import Dot1Q, Ether
        from scapy.utils import wrpcap

        scapy_pkts = [
            Ether()
            / Dot1Q(vlan=50)
            / IP(src="192.168.1.5", dst="192.168.1.1")
            / TCP(sport=5000, dport=587)
        ]

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            pcap_path = tf.name

        wrpcap(pcap_path, scapy_pkts)

        with PcapReader(pcap_path) as reader:
            pkts = list(reader.packets())
            assert len(pkts) == 1
            assert pkts[0].vlan_id == 50
            assert pkts[0].payload[0] == 0x45


class TestMemoryFootprint:
    """Verify streaming reader maintains constant memory footprint on large captures."""

    def test_streaming_large_capture_memory_bounded(self) -> None:
        import os
        import resource

        # Generate a large PCAP with 50,000 packets
        eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
        packet = eth_hdr + SAMPLE_IPV4_PAYLOAD
        pkt_tuple = (1700000000.0, packet)

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            pcap_path = tf.name

        # Write 50,000 packets in chunks
        chunk = create_classic_pcap([pkt_tuple] * 1000)
        with open(pcap_path, "wb") as f:
            f.write(chunk[:24])  # Global header
            for _ in range(50):
                f.write(chunk[24:])  # 1000 packet records each iteration

        initial_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

        count = 0
        with PcapReader(pcap_path) as reader:
            for pkt in reader.packets():
                count += 1
                # Ensure we can read payload without retaining references
                _ = len(pkt.payload)

        final_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        assert count == 50000

        # Memory should stay bounded (macOS ru_maxrss is in bytes)
        # Verify peak memory increase is negligible (< 100MB)
        rss_diff_mb = (final_rss - initial_rss) / (1024 * 1024)
        assert rss_diff_mb < 100

        os.remove(pcap_path)


class TestExtendedLinkLayersAndStreams:
    """Test 802.11 Wi-Fi, Radiotap, and direct Stream inputs."""

    def test_ieee80211_wifi_and_radiotap(self) -> None:
        from pecff.ingest.reader import LINKTYPE_IEEE802_11, LINKTYPE_IEEE802_11_RADIO

        # Frame Control: type 2 (data, 0x08), flags: toDS=0, fromDS=0 (0x00) -> 24 byte header
        # Subtype: 0x8 (QoS data) -> +2 byte QoS -> 26 byte header
        # LLC/SNAP header: 8 bytes (AA AA 03 00 00 00 08 00) -> total 34 bytes L2 header
        fc = struct.pack("<H", 0x0088)  # Data frame, QoS
        wifi_hdr = fc + (b"\x00" * 22) + b"\x00\x00" + b"\xaa\xaa\x03\x00\x00\x00\x08\x00"
        packet = wifi_hdr + SAMPLE_IPV4_PAYLOAD

        raw_pcap = create_classic_pcap([(1700000000.0, packet)], link_type=LINKTYPE_IEEE802_11)

        with PcapReader(raw_pcap) as reader:
            pkts = list(reader.packets())
            assert len(pkts) == 1
            assert bytes(pkts[0].payload) == SAMPLE_IPV4_PAYLOAD

        # Test Radiotap (LinkType 127)
        # Radiotap header: version (1B), pad (1B), len (2B = 8), present flags (4B)
        radiotap_hdr = struct.pack("<BBHI", 0, 0, 8, 0)
        radiotap_packet = radiotap_hdr + packet
        radiotap_pcap = create_classic_pcap(
            [(1700000000.0, radiotap_packet)], link_type=LINKTYPE_IEEE802_11_RADIO
        )

        with PcapReader(radiotap_pcap) as reader:
            pkts = list(reader.packets())
            assert len(pkts) == 1
            assert bytes(pkts[0].payload) == SAMPLE_IPV4_PAYLOAD

    def test_direct_binary_stream_input(self) -> None:
        eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
        packet = eth_hdr + SAMPLE_IPV4_PAYLOAD
        raw_pcap = create_classic_pcap([(1700000000.0, packet)])

        stream = io.BytesIO(raw_pcap)
        with PcapReader(stream) as reader:
            pkts = list(reader.packets())
            assert len(pkts) == 1
            assert bytes(pkts[0].payload) == SAMPLE_IPV4_PAYLOAD
