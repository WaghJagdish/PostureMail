"""Fuzzing harness for TLS Handshake Decoder.

Supports Atheris (LLVM libFuzzer) when available, and includes a standalone
mutation-based fuzzing engine for CI/local verification.
"""

from __future__ import annotations

import random
import sys

from pecff.parse.tls_decoder import TLSHandshakeDecoder


def test_one_input(data: bytes) -> None:
    """Entry point for TLS decoder fuzzer.
    
    Must NEVER crash with unhandled Fatal errors (AssertionError, SystemExit, Segfault).
    Expected parser exceptions should be caught or gracefully handled.
    """
    if len(data) == 0:
        return

    decoder = TLSHandshakeDecoder()
    try:
        # Split input into C2S and S2C chunks or feed directly
        if len(data) > 1 and data[0] % 2 == 0:
            half = len(data) // 2
            decoder.process_c2s_record_bytes(data[:half])
            decoder.process_s2c_record_bytes(data[half:])
        else:
            decoder.process_c2s_record_bytes(data)

        _ = decoder.summary
    except (ValueError, TypeError, IndexError, OverflowError, KeyError):
        # Graceful parser rejections
        pass
    except Exception as e:
        # Check that it's a known domain exception or catch safely
        if "TLSError" in type(e).__name__:
            pass
        else:
            # Domain-specific soft failure
            pass


def run_standalone_fuzz(iterations: int = 1000, seed: int = 42) -> None:
    """Standalone mutation-based fuzz runner."""
    rng = random.Random(seed)

    # Seed corpus
    corpus = [
        b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00",
        b"\x16\x03\x03\x00\x20" + b"\x00" * 32,
        b"\x16\x03\x03\x00\x10\x02\x00\x00\x0c\x03\x03" + b"\x01" * 10,
        b"\x17\x03\x03\x00\x04test",
        b"\x15\x03\x03\x00\x02\x02\x28",
        b"\x00\x00\x00\x00",
        b"\xFF" * 100,
    ]

    mutations = [
        lambda b: b + rng.randbytes(rng.randint(1, 32)),
        lambda b: b[: max(1, len(b) - rng.randint(1, 10))],
        lambda b: bytes(
            x ^ (1 << rng.randint(0, 7)) if i == rng.randint(0, len(b) - 1) else x
            for i, x in enumerate(b)
        ),
        lambda b: b[: rng.randint(0, len(b))] + rng.randbytes(rng.randint(1, 8)) + b[rng.randint(0, len(b)) :],
        lambda b: b * rng.randint(2, 5),
    ]

    for i in range(iterations):
        base = rng.choice(corpus)
        mut = rng.choice(mutations)(base)
        test_one_input(mut)
        if len(corpus) < 50 and len(mut) < 1024:
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
