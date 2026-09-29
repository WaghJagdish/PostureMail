"""STARTTLS upgrade finite state machine with auditable forensic transitions.

Tracks protocol progression across SMTP, IMAP, and POP3, recording full
state transitions with 64-byte evidence slices, banner extraction, capability
enumeration, cleartext credential detection, and upgrade latency tracking.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from pecff.ingest.reassembly import ReassemblyFinding


class Direction(StrEnum):
    """Direction of traffic in a bidirectional TCP session."""

    C2S = "C2S"  # Client to Server
    S2C = "S2C"  # Server to Client


class StarttlsState(StrEnum):
    """Canonical STARTTLS state machine states."""

    S_INIT = "S_INIT"
    S0_TCP_EST = "S0_TCP_EST"
    S1_GREETING = "S1_GREETING"
    S1B_CAPS_ADV = "S1B_CAPS_ADV"
    S2_CMD = "S2_CMD"
    S2_ACCEPTED = "S2_ACCEPTED"
    S_REFUSED = "S_REFUSED"
    S3_TLS_HS = "S3_TLS_HS"
    S4_ENCRYPTED = "S4_ENCRYPTED"
    S_PLAINTEXT = "S_PLAINTEXT"
    S_STRIP_DETECTED = "S_STRIP_DETECTED"


@dataclass(frozen=True, slots=True)
class StateTransition:
    """Forensic transition log entry capturing exact state change and evidence."""

    from_state: str
    to_state: str
    ts: float
    stream_offset: int
    evidence_slice: str  # Hex + ASCII representation (up to 64 bytes)
    evidence_bytes: bytes


# Protocol Regex Token Tables
RE_SMTP_GREETING: Final[re.Pattern[bytes]] = re.compile(rb"^220[ -]")
RE_POP3_GREETING: Final[re.Pattern[bytes]] = re.compile(rb"^\+OK")
RE_IMAP_GREETING: Final[re.Pattern[bytes]] = re.compile(rb"^\* OK")

RE_SMTP_CAPS_REQ: Final[re.Pattern[bytes]] = re.compile(rb"(?i)^(?:EHLO|HELO)\s+(\S+)")
RE_POP3_CAPS_REQ: Final[re.Pattern[bytes]] = re.compile(rb"(?i)^CAPA")
RE_IMAP_CAPS_REQ: Final[re.Pattern[bytes]] = re.compile(rb"(?i)^(\S+)\s+CAPABILITY")

RE_SMTP_UPGRADE: Final[re.Pattern[bytes]] = re.compile(rb"(?i)^STARTTLS(?:\r\n|\n|$)")
RE_POP3_UPGRADE: Final[re.Pattern[bytes]] = re.compile(rb"(?i)^STLS(?:\r\n|\n|$)")
RE_IMAP_UPGRADE: Final[re.Pattern[bytes]] = re.compile(rb"(?i)^(\S+)\s+STARTTLS(?:\r\n|\n|$)")

RE_SMTP_ACCEPT: Final[re.Pattern[bytes]] = re.compile(rb"^220[ -]")
RE_POP3_ACCEPT: Final[re.Pattern[bytes]] = re.compile(rb"^\+OK")
RE_IMAP_ACCEPT: Final[re.Pattern[bytes]] = re.compile(rb"(?i)^(\S+)\s+OK")

RE_SMTP_REJECT: Final[re.Pattern[bytes]] = re.compile(rb"^(?:4|5)\d\d")
RE_POP3_REJECT: Final[re.Pattern[bytes]] = re.compile(rb"^-ERR")
RE_IMAP_REJECT: Final[re.Pattern[bytes]] = re.compile(rb"(?i)^(\S+)\s+(?:NO|BAD)")

RE_TLS_RECORD_HEADER: Final[re.Pattern[bytes]] = re.compile(rb"^\x16\x03[\x00-\x04]")
RE_TLS_APP_DATA: Final[re.Pattern[bytes]] = re.compile(rb"^\x17\x03[\x00-\x04]")

# Cleartext authentication patterns
RE_AUTH_PLAIN_LOGIN: Final[re.Pattern[bytes]] = re.compile(
    rb"(?i)^AUTH\s+(PLAIN|LOGIN|CRAM-MD5|EXTERNAL)"
)
RE_POP3_USER: Final[re.Pattern[bytes]] = re.compile(rb"(?i)^USER\s+(\S+)")
RE_POP3_PASS: Final[re.Pattern[bytes]] = re.compile(rb"(?i)^PASS\s+(\S+)")
RE_IMAP_LOGIN: Final[re.Pattern[bytes]] = re.compile(rb"(?i)^\S+\s+LOGIN\s+(\S+)\s+(\S+)")


class StarttlsFSM:
    """Finite state machine for tracking email protocol STARTTLS handshakes."""

    def __init__(self, protocol: str = "SMTP", mode: str = "EXPLICIT") -> None:
        self.protocol: str = protocol.upper()
        self.mode: str = mode.upper()
        self.state: StarttlsState = (
            StarttlsState.S3_TLS_HS if self.mode == "IMPLICIT" else StarttlsState.S0_TCP_EST
        )

        self.transitions: list[StateTransition] = []
        self.findings: list[ReassemblyFinding] = []

        # Forensic metadata
        self.server_banner: str | None = None
        self.ehlo_domain: str | None = None
        self.advertised_capabilities: list[str] = []
        self.auth_mechanisms_used: list[str] = []
        self.credentials_in_cleartext: bool = False
        self.upgrade_latency_ms: float | None = None

        # Internal tracking
        self._s2_cmd_ts: float | None = None
        self._imap_upgrade_tag: str | None = None
        self._c2s_line_buffer: bytearray = bytearray()
        self._s2c_line_buffer: bytearray = bytearray()

    def get_state(self) -> StarttlsState:
        """Return the current FSM state."""
        return self.state

    def feed(
        self,
        direction: Direction,
        chunk: bytes,
        stream_offset: int,
        ts: float,
    ) -> None:
        """Feed a directional payload chunk into the STARTTLS state machine."""
        if len(chunk) == 0:
            return

        # Check for direct TLS record transition
        if RE_TLS_RECORD_HEADER.match(chunk) and self.state in (
            StarttlsState.S2_ACCEPTED,
            StarttlsState.S0_TCP_EST,
            StarttlsState.S1_GREETING,
        ):
            self._transition(StarttlsState.S3_TLS_HS, ts, stream_offset, chunk)
            if self._s2_cmd_ts is not None:
                self.upgrade_latency_ms = (ts - self._s2_cmd_ts) * 1000.0
            return

        # Check for TLS Application Data (S4_ENCRYPTED)
        if RE_TLS_APP_DATA.match(chunk) and self.state == StarttlsState.S3_TLS_HS:
            self._transition(StarttlsState.S4_ENCRYPTED, ts, stream_offset, chunk)
            return

        # If already encrypted, all payload is application data
        if self.state == StarttlsState.S4_ENCRYPTED:
            return

        # Split into lines for text protocol analysis
        target_buf = self._c2s_line_buffer if direction == Direction.C2S else self._s2c_line_buffer
        target_buf.extend(chunk)

        # Enforce hard line buffer cap (64 KiB) to prevent DoS from missing newlines
        if len(target_buf) > 65536:
            line = bytes(target_buf[:65536])
            del target_buf[:]
            self._process_line(direction, line, stream_offset, ts)

        while b"\n" in target_buf:
            line_end = target_buf.index(b"\n") + 1
            line = bytes(target_buf[:line_end])
            del target_buf[:line_end]
            self._process_line(direction, line, stream_offset, ts)

    def _process_line(
        self,
        direction: Direction,
        line: bytes,
        stream_offset: int,
        ts: float,
    ) -> None:
        """Process a single protocol line according to current state and direction."""
        stripped = line.strip()
        if len(stripped) == 0:
            return

        # Check cleartext credentials (if not in S4_ENCRYPTED)
        if (
            self.state != StarttlsState.S4_ENCRYPTED
            and direction == Direction.C2S
            and (
                RE_AUTH_PLAIN_LOGIN.match(stripped)
                or RE_POP3_USER.match(stripped)
                or RE_POP3_PASS.match(stripped)
                or RE_IMAP_LOGIN.match(stripped)
            )
        ):
            self.credentials_in_cleartext = True
            m_auth = RE_AUTH_PLAIN_LOGIN.match(stripped)
            if m_auth:
                mech = m_auth.group(1).decode("latin-1", errors="ignore").upper()
                if mech not in self.auth_mechanisms_used:
                    self.auth_mechanisms_used.append(mech)

        # ---------------------------------------------------------------------
        # S0_TCP_EST -> S1_GREETING
        # ---------------------------------------------------------------------
        if self.state == StarttlsState.S0_TCP_EST and direction == Direction.S2C:
            is_greeting = False
            if (
                self.protocol == "SMTP"
                and RE_SMTP_GREETING.match(stripped)
                or self.protocol == "POP3"
                and RE_POP3_GREETING.match(stripped)
                or self.protocol == "IMAP"
                and RE_IMAP_GREETING.match(stripped)
                or (
                    RE_SMTP_GREETING.match(stripped)
                    or RE_POP3_GREETING.match(stripped)
                    or RE_IMAP_GREETING.match(stripped)
                )
            ):
                is_greeting = True

            if is_greeting:
                self.server_banner = stripped.decode("latin-1", errors="ignore")
                self._transition(StarttlsState.S1_GREETING, ts, stream_offset, line)
                return

        # ---------------------------------------------------------------------
        # S1_GREETING -> S1B_CAPS_ADV
        # ---------------------------------------------------------------------
        if self.state in (StarttlsState.S1_GREETING, StarttlsState.S1B_CAPS_ADV):
            if direction == Direction.C2S:
                m_ehlo = RE_SMTP_CAPS_REQ.match(stripped)
                if m_ehlo:
                    self.ehlo_domain = m_ehlo.group(1).decode("latin-1", errors="ignore")
                elif RE_POP3_CAPS_REQ.match(stripped) or RE_IMAP_CAPS_REQ.match(stripped):
                    pass

            elif direction == Direction.S2C:
                # Capture capabilities (e.g. 250-STARTTLS, 250 AUTH PLAIN LOGIN)
                cap_line = stripped.decode("latin-1", errors="ignore")
                if self.protocol == "SMTP" and (
                    cap_line.startswith("250-") or cap_line.startswith("250 ")
                ):
                    cap = cap_line[4:].strip()
                    if cap and cap not in self.advertised_capabilities:
                        self.advertised_capabilities.append(cap)
                    if self.state != StarttlsState.S1B_CAPS_ADV:
                        self._transition(StarttlsState.S1B_CAPS_ADV, ts, stream_offset, line)
                elif (
                    self.protocol == "POP3"
                    and not cap_line.startswith("+OK")
                    and not cap_line.startswith(".")
                ):
                    if cap_line not in self.advertised_capabilities:
                        self.advertised_capabilities.append(cap_line)
                    if self.state != StarttlsState.S1B_CAPS_ADV:
                        self._transition(StarttlsState.S1B_CAPS_ADV, ts, stream_offset, line)
                elif self.protocol == "IMAP" and "CAPABILITY" in cap_line.upper():
                    caps = cap_line.split()
                    for c in caps:
                        if c not in self.advertised_capabilities:
                            self.advertised_capabilities.append(c)
                    if self.state != StarttlsState.S1B_CAPS_ADV:
                        self._transition(StarttlsState.S1B_CAPS_ADV, ts, stream_offset, line)

        # ---------------------------------------------------------------------
        # S1_GREETING / S1B_CAPS_ADV -> S2_CMD (Upgrade command sent by client)
        # ---------------------------------------------------------------------
        if (
            self.state in (StarttlsState.S1_GREETING, StarttlsState.S1B_CAPS_ADV)
            and direction == Direction.C2S
        ):
            is_upgrade_cmd = False
            if (
                self.protocol == "SMTP"
                and RE_SMTP_UPGRADE.match(stripped)
                or self.protocol == "POP3"
                and RE_POP3_UPGRADE.match(stripped)
            ):
                is_upgrade_cmd = True
            elif self.protocol == "IMAP":
                m_imap = RE_IMAP_UPGRADE.match(stripped)
                if m_imap:
                    is_upgrade_cmd = True
                    self._imap_upgrade_tag = m_imap.group(1).decode("latin-1", errors="ignore")
            elif (
                RE_SMTP_UPGRADE.match(stripped)
                or RE_POP3_UPGRADE.match(stripped)
                or RE_IMAP_UPGRADE.match(stripped)
            ):
                is_upgrade_cmd = True

            if is_upgrade_cmd:
                self._s2_cmd_ts = ts
                self._transition(StarttlsState.S2_CMD, ts, stream_offset, line)
                return

        # ---------------------------------------------------------------------
        # S2_CMD -> S2_ACCEPTED / S_REFUSED
        # ---------------------------------------------------------------------
        if self.state == StarttlsState.S2_CMD and direction == Direction.S2C:
            # Check accept
            is_accept = False
            if (
                self.protocol == "SMTP"
                and RE_SMTP_ACCEPT.match(stripped)
                or self.protocol == "POP3"
                and RE_POP3_ACCEPT.match(stripped)
            ):
                is_accept = True
            elif self.protocol == "IMAP":
                m_ok = RE_IMAP_ACCEPT.match(stripped)
                if m_ok:
                    resp_tag = m_ok.group(1).decode("latin-1", errors="ignore")
                    if self._imap_upgrade_tag and resp_tag != self._imap_upgrade_tag:
                        self.findings.append(
                            ReassemblyFinding(
                                rule_id="IMAP_TAG_MISMATCH",
                                rule_name="IMAP STARTTLS Response Tag Mismatch",
                                severity="MEDIUM",
                                description=(
                                    f"IMAP command tag '{self._imap_upgrade_tag}' does not match "
                                    f"server response tag '{resp_tag}'."
                                ),
                                evidence={
                                    "command_tag": self._imap_upgrade_tag,
                                    "response_tag": resp_tag,
                                },
                            )
                        )
                    is_accept = True
            elif (
                RE_SMTP_ACCEPT.match(stripped)
                or RE_POP3_ACCEPT.match(stripped)
                or RE_IMAP_ACCEPT.match(stripped)
            ):
                is_accept = True

            if is_accept:
                self._transition(StarttlsState.S2_ACCEPTED, ts, stream_offset, line)
                return

            # Check reject
            is_reject = False
            if (
                self.protocol == "SMTP"
                and RE_SMTP_REJECT.match(stripped)
                or self.protocol == "POP3"
                and RE_POP3_REJECT.match(stripped)
                or self.protocol == "IMAP"
                and RE_IMAP_REJECT.match(stripped)
            ):
                is_reject = True

            if is_reject:
                self._transition(StarttlsState.S_REFUSED, ts, stream_offset, line)
                return

        # ---------------------------------------------------------------------
        # Post-S2_ACCEPTED checks
        # ---------------------------------------------------------------------
        if (
            self.state == StarttlsState.S2_ACCEPTED
            and direction == Direction.C2S
            and not RE_TLS_RECORD_HEADER.match(line)
        ):
            # Client sent plaintext after STARTTLS was accepted!
            self._transition(StarttlsState.S_STRIP_DETECTED, ts, stream_offset, line)
            return

    def _transition(
        self,
        new_state: StarttlsState,
        ts: float,
        stream_offset: int,
        evidence: bytes,
    ) -> None:
        """Record state transition with 64-byte evidence formatting."""
        from_state_str = self.state.value
        to_state_str = new_state.value
        self.state = new_state

        evidence_slice_bytes = evidence[:64]
        evidence_slice_str = self._format_evidence(evidence_slice_bytes)

        transition = StateTransition(
            from_state=from_state_str,
            to_state=to_state_str,
            ts=ts,
            stream_offset=stream_offset,
            evidence_slice=evidence_slice_str,
            evidence_bytes=evidence_slice_bytes,
        )
        self.transitions.append(transition)

    @staticmethod
    def _format_evidence(b: bytes) -> str:
        """Format up to 64 bytes as hex + printable ASCII string."""
        hex_str = b.hex()
        ascii_chars: list[str] = []
        for byte_val in b:
            if 32 <= byte_val <= 126:
                ascii_chars.append(chr(byte_val))
            else:
                ascii_chars.append(".")
        ascii_str = "".join(ascii_chars)
        return f"{hex_str} | {ascii_str}"
