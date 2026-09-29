"""Smoke tests for the continuous fuzzing targets.

Executes >= 1,000 deterministic mutation iterations against each parser/decoder
target to guarantee zero unhandled crashes or interpreter panics under hostile inputs.
"""

from __future__ import annotations

import pytest

from tests.fuzz.fuzz_mail_fsm import run_standalone_fuzz as fuzz_mail_fsm
from tests.fuzz.fuzz_pcap_reader import run_standalone_fuzz as fuzz_pcap_reader
from tests.fuzz.fuzz_tls_decoder import run_standalone_fuzz as fuzz_tls_decoder
from tests.fuzz.fuzz_x509_parser import run_standalone_fuzz as fuzz_x509_parser


class TestFuzzingSmokeSuite:
    """Continuous fuzzing smoke test suite verifying parser robustness."""

    @pytest.mark.parametrize("target_name,fuzz_fn", [
        ("tls_decoder", fuzz_tls_decoder),
        ("x509_parser", fuzz_x509_parser),
        ("pcap_reader", fuzz_pcap_reader),
        ("mail_fsm", fuzz_mail_fsm),
    ])
    def test_parser_fuzz_smoke_1000_iterations(
        self,
        target_name: str,
        fuzz_fn,
    ) -> None:
        """Run 1,000 mutation iterations on target and assert 0 unhandled fatal crashes."""
        try:
            fuzz_fn(iterations=1000, seed=1337)
        except Exception as e:
            pytest.fail(f"Fuzz target {target_name} crashed with unhandled exception: {e!r}")
