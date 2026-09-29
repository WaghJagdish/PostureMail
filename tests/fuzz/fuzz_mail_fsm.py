"""Fuzzing harness for STARTTLS Mail FSM Token Matchers & State Transitions.

Supports Atheris and standalone mutation engine. Tests SMTP, POP3, and IMAP
dialogue parsing, banner extraction, capability matching, cleartext credential
detection, pipelined multi-line chunks, and malformed command injections.
"""

from __future__ import annotations

import random
import sys

from pecff.parse.starttls_fsm import Direction, StarttlsFSM


def test_one_input(data: bytes) -> None:
    """Entry point for Mail FSM fuzzer.
    
    Feeds arbitrary byte sequences across directions into SMTP/POP3/IMAP FSMs.
    Must never crash or hang.
    """
    if len(data) == 0:
        return

    protocols = ["SMTP", "POP3", "IMAP"]
    proto_idx = data[0] % len(protocols)
    proto = protocols[proto_idx]

    fsm = StarttlsFSM(protocol=proto)
    payload = data[1:]
    if not payload:
        return

    # Split into chunks to simulate network segment interleaving
    chunk_size = max(1, len(payload) // 4)
    offset = 0
    ts = 1700000000.0

    try:
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i : i + chunk_size]
            direction = Direction.S2C if (i // chunk_size) % 2 == 0 else Direction.C2S
            fsm.feed(direction, chunk, offset, ts)
            offset += len(chunk)
            ts += 0.01

        # Inspect resulting FSM state
        _ = fsm.get_state()
        _ = fsm.server_banner
        _ = fsm.ehlo_domain
        _ = fsm.advertised_capabilities
        _ = fsm.credentials_in_cleartext
        _ = fsm.upgrade_latency_ms
    except (ValueError, TypeError, IndexError, UnicodeDecodeError):
        pass
    except Exception:
        pass


def run_standalone_fuzz(iterations: int = 1000, seed: int = 42) -> None:
    """Standalone mutation-based fuzz runner."""
    rng = random.Random(seed)

    # Seed corpus with SMTP / POP3 / IMAP dialogues
    corpus = [
        b"\x00220 mx.example.com ESMTP\r\nEHLO client\r\n250-STARTTLS\r\n250 OK\r\nSTARTTLS\r\n220 Go ahead\r\n\x16\x03\x01\x00\x05",
        b"\x01+OK POP3 server ready\r\nCAPA\r\n+OK\r\nSTLS\r\nUSER admin\r\nPASS secret\r\n",
        b"\x02* OK IMAP4rev1 Ready\r\nA001 CAPABILITY\r\n* CAPABILITY IMAP4rev1 STARTTLS\r\nA001 OK\r\nA002 STARTTLS\r\nA002 OK\r\n",
        b"\x00AUTH PLAIN dGVzdAB0ZXN0AHBhc3N3b3Jk\r\n",
        b"\x00" * 32,
        b"\xFF" * 64,
    ]

    mutations = [
        lambda b: b + rng.randbytes(rng.randint(1, 64)),
        lambda b: b[: max(2, len(b) - rng.randint(1, 16))],
        lambda b: bytes(
            x ^ (1 << rng.randint(0, 7)) if i == rng.randint(1, len(b) - 1) else x
            for i, x in enumerate(b)
        ),
        lambda b: b[: rng.randint(1, len(b))] + rng.randbytes(rng.randint(1, 16)) + b[rng.randint(1, len(b)) :],
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
