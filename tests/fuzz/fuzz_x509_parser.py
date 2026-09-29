"""Fuzzing harness for X.509 Certificate Parser.

Supports Atheris and a standalone mutation engine. Tests ASN.1 DER decoding,
lenient parsing, extension extraction, and DN normalization on hostile inputs.
"""

from __future__ import annotations

import random
import sys

from pecff.crypto.x509_parser import X509Parser


def test_one_input(data: bytes) -> None:
    """Entry point for X.509 certificate fuzzer.
    
    Must NEVER crash the interpreter or raise unhandled fatal errors.
    """
    if len(data) == 0:
        return

    parser = X509Parser()
    try:
        cert = parser.parse_der(data)
        if cert is not None:
            # Validate properties access
            _ = cert.fingerprint_sha256
            _ = cert.spki_sha256
            _ = cert.subject_dn
            _ = cert.issuer_dn
            _ = cert.san_dns
            _ = cert.san_ip
            _ = cert.security_bits
            _ = cert.is_self_signed
    except Exception:
        # Expected parsing errors are handled gracefully
        pass


def run_standalone_fuzz(iterations: int = 1000, seed: int = 42) -> None:
    """Standalone mutation-based fuzz runner."""
    rng = random.Random(seed)

    # Seed corpus
    corpus = [
        # Minimal ASN.1 sequence
        b"\x30\x00",
        b"\x30\x82\x01\x00" + b"\x00" * 256,
        b"\x30\x82\x02\x00\xa0\x03\x02\x01\x02\x02\x09\x00\x01",
        b"\x30\x10\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00",
        b"\x30\x82\x00\x10\x31\x0e\x30\x0c\x06\x03\x55\x04\x03\x13\x05\x74\x65\x73\x74\x31",
        b"\x00" * 64,
        b"\xFF" * 128,
    ]

    mutations = [
        lambda b: b + rng.randbytes(rng.randint(1, 64)),
        lambda b: b[: max(1, len(b) - rng.randint(1, 20))],
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
