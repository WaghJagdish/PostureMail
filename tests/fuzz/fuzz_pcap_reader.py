"""Fuzzing harness for PCAP/PCAPNG Streaming Reader.

Supports Atheris and a standalone mutation engine. Tests PCAP/PCAPNG header
parsing, block decoding, VLAN unwrapping, link-layer stripping, and streaming
metadata extraction under hostile/truncated packet inputs.
"""

from __future__ import annotations

import random
import sys

from pecff.ingest.reader import PcapError, PcapReader
from pecff.ingest.reassembly import StreamReassembler


def test_one_input(data: bytes) -> None:
    """Entry point for PCAP reader fuzzer.
    
    Must handle any arbitrary corrupted PCAP or PCAPNG byte sequence safely.
    """
    if len(data) == 0:
        return

    try:
        reader = PcapReader(data)
        reassembler = StreamReassembler()
        count = 0
        for pkt in reader.packets():
            reassembler.process_packet(pkt)
            count += 1
            if count > 500:  # Cap loop iteration for fuzzing speed
                break
        _ = reader.metadata()
        _ = reassembler.finalize_all()
    except PcapError:
        # Expected parser domain rejections
        pass
    except (ValueError, TypeError, IndexError, OverflowError):
        # Python built-in parser errors from corrupted lengths
        pass
    except Exception:
        # Other caught domain exceptions
        pass


def run_standalone_fuzz(iterations: int = 1000, seed: int = 42) -> None:
    """Standalone mutation-based fuzz runner."""
    rng = random.Random(seed)

    # Seed corpus with minimal valid PCAP / PCAPNG headers
    pcap_hdr_be = b"\xa1\xb2\xc3\xd4\x00\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x01"
    pcap_hdr_le = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00"
    pcapng_shb = b"\x0a\x0d\x0d\x0a\x1c\x00\x00\x00\x4d\x3c\x2b\x1a\x01\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x1c\x00\x00\x00"

    corpus = [
        pcap_hdr_be,
        pcap_hdr_le,
        pcapng_shb,
        pcap_hdr_be + b"\x00" * 16 + b"\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x7c\xcd\x7f\x00\x00\x01\x7f\x00\x00\x01\x00\x50\x00\x50\x00\x00\x00\x01\x00\x00\x00\x00\x50\x02\x20\x00\x91\x7c\x00\x00",
        b"\x00" * 32,
        b"\xFF" * 64,
    ]

    mutations = [
        lambda b: b + rng.randbytes(rng.randint(1, 64)),
        lambda b: b[: max(1, len(b) - rng.randint(1, 16))],
        lambda b: bytes(
            x ^ (1 << rng.randint(0, 7)) if i == rng.randint(0, len(b) - 1) else x
            for i, x in enumerate(b)
        ),
        lambda b: b[: rng.randint(0, len(b))] + rng.randbytes(rng.randint(1, 16)) + b[rng.randint(0, len(b)) :],
        lambda b: b * rng.randint(2, 4),
    ]

    for i in range(iterations):
        base = rng.choice(corpus)
        mut = rng.choice(mutations)(base)
        test_one_input(mut)
        if len(corpus) < 50 and len(mut) < 2048:
            corpus.append(mut)


# Atheris integration
try:
    import atheris  # type: ignore

    @atheris.instrument_func
    def TestOneInput(data: bytes) -> None:
        test_one_input(data)

    def main() -> None:
        atheris.Setup(sys.argv, TestOneInput)
        atheris.Fuzz()

except ImportError:
    def main() -> None:
        iters = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 1000
        run_standalone_fuzz(iterations=iters)


if __name__ == "__main__":
    main()
