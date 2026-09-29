"""Global pytest fixtures and passive network isolation guarantees."""

from __future__ import annotations

import socket
from collections.abc import Iterator
from typing import Any

import pytest


class PassiveViolationError(RuntimeError):
    """Raised when active network I/O is attempted during strictly passive forensic analysis."""

    pass


def _blocked_connect(*args: Any, **kwargs: Any) -> Any:
    raise PassiveViolationError(
        "Active network connection attempted during strictly passive forensic analysis! "
        "PECFF enforces a strict passive air-gap guarantee."
    )


@pytest.fixture(autouse=True)
def enforce_passive_airgap(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Mechanically guarantees zero active network calls during test execution.

    Patches socket connect primitives so any unexpected network activity
    (e.g., live OCSP lookups, DNS resolution, CRL downloads, external telemetry)
    immediately fails the test.
    """
    monkeypatch.setattr(socket.socket, "connect", _blocked_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", _blocked_connect)
    yield
