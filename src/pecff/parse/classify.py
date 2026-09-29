"""Two-stage mail protocol classification engine.

Implements two-stage protocol identification (port hint first, content confirmation
second). Content ALWAYS wins a conflict, and the winning decision factor is recorded
for auditable provenance.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import yaml

from pecff.config import settings
from pecff.ingest.reassembly import ReassembledSession, ReassemblyFinding

# Standard mail port sets
STANDARD_MAIL_PORTS: Final[set[int]] = {25, 110, 143, 465, 587, 993, 995, 2525}

# Content sniffing regular expressions on initial server-to-client bytes
RE_SMTP_GREETING: Final[re.Pattern[bytes]] = re.compile(rb"^220[ -]")
RE_POP3_GREETING: Final[re.Pattern[bytes]] = re.compile(rb"^\+OK")
RE_IMAP_GREETING: Final[re.Pattern[bytes]] = re.compile(rb"^\* OK")
RE_TLS_CLIENT_OR_SERVER_HELLO: Final[re.Pattern[bytes]] = re.compile(rb"^\x16\x03[\x00-\x04]")

# ALPN token set (RFC 7639 / RFC 7301)
MAIL_ALPN_PROTOCOLS: Final[dict[str, str]] = {
    "smtp": "SMTP",
    "imap": "IMAP",
    "pop3": "POP3",
    "submission": "SMTP",
}


@dataclass(frozen=True, slots=True)
class ProtocolClassification:
    """Forensic classification output with decision provenance."""

    protocol: str  # 'SMTP', 'IMAP', 'POP3', 'UNKNOWN'
    mode: str  # 'EXPLICIT', 'IMPLICIT', 'UNKNOWN'
    detected_by: str  # 'content', 'port', 'override', 'alpn'
    port_is_standard_mail: bool  # ML feature
    alpn: str | None = None
    finding: ReassemblyFinding | None = None


class ProtocolClassifier:
    """Two-stage mail protocol classifier with custom port override support."""

    def __init__(self, custom_ports_file: Path | None = None) -> None:
        self._custom_port_overrides: dict[int, tuple[str, str]] = {}
        target_path = custom_ports_file or settings.custom_ports_path
        self._load_custom_ports(target_path)

    def _load_custom_ports(self, path: Path) -> None:
        """Load operator port overrides from YAML if file exists."""
        if not path.exists():
            return
        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if isinstance(data, dict):
                    for port_str, info in data.items():
                        try:
                            port = int(port_str)
                            if isinstance(info, dict):
                                proto = str(info.get("protocol", "UNKNOWN")).upper()
                                mode = str(info.get("mode", "EXPLICIT")).upper()
                                self._custom_port_overrides[port] = (proto, mode)
                        except (ValueError, TypeError):
                            continue
        except Exception:
            # Silently ignore corrupt custom config and use system defaults
            pass

    def classify(self, stream: ReassembledSession) -> ProtocolClassification:
        """Convenience method to classify a ReassembledSession."""
        return self.classify_stream(
            server_port=stream.server_port,
            s2c_initial_bytes=bytes(stream.s2c_payload[:128]),
            c2s_initial_bytes=bytes(stream.c2s_payload[:128]),
        )

    def classify_stream(
        self,
        server_port: int,
        s2c_initial_bytes: bytes,
        c2s_initial_bytes: bytes = b"",
        alpn: str | None = None,
    ) -> ProtocolClassification:
        """Classify stream protocol and mode with two-stage resolution."""
        port_is_standard = server_port in STANDARD_MAIL_PORTS

        # Check ALPN (RFC 7639) - if ALPN is explicitly mail, it takes highest precedence
        if alpn:
            alpn_clean = alpn.lower().strip()
            if alpn_clean in MAIL_ALPN_PROTOCOLS:
                return ProtocolClassification(
                    protocol=MAIL_ALPN_PROTOCOLS[alpn_clean],
                    mode="IMPLICIT",
                    detected_by="alpn",
                    port_is_standard_mail=port_is_standard,
                    alpn=alpn_clean,
                )

        # ---------------------------------------------------------------------
        # Stage 1: Port Hint
        # ---------------------------------------------------------------------
        port_proto: str = "UNKNOWN"
        port_mode: str = "UNKNOWN"

        if server_port in self._custom_port_overrides:
            port_proto, port_mode = self._custom_port_overrides[server_port]
        elif server_port in (25, 587, 2525):
            port_proto, port_mode = "SMTP", "EXPLICIT"
        elif server_port == 465:
            port_proto, port_mode = "SMTP", "IMPLICIT"
        elif server_port == 110:
            port_proto, port_mode = "POP3", "EXPLICIT"
        elif server_port == 995:
            port_proto, port_mode = "POP3", "IMPLICIT"
        elif server_port == 143:
            port_proto, port_mode = "IMAP", "EXPLICIT"
        elif server_port == 993:
            port_proto, port_mode = "IMAP", "IMPLICIT"

        # ---------------------------------------------------------------------
        # Stage 2: Content Confirmation (Content ALWAYS wins conflicts)
        # ---------------------------------------------------------------------
        content_proto: str | None = None
        content_mode: str | None = None

        sniff_len = min(64, len(s2c_initial_bytes))
        s2c_sniff = s2c_initial_bytes[:sniff_len]

        # Check for implicit TLS record header
        if RE_TLS_CLIENT_OR_SERVER_HELLO.match(s2c_sniff) or (
            len(s2c_sniff) == 0 and RE_TLS_CLIENT_OR_SERVER_HELLO.match(c2s_initial_bytes)
        ):
            # TLS detected immediately
            content_proto = port_proto if port_proto != "UNKNOWN" else "UNKNOWN"
            content_mode = "IMPLICIT"

        elif RE_SMTP_GREETING.match(s2c_sniff):
            content_proto = "SMTP"
            content_mode = "EXPLICIT"
        elif RE_POP3_GREETING.match(s2c_sniff):
            content_proto = "POP3"
            content_mode = "EXPLICIT"
        elif RE_IMAP_GREETING.match(s2c_sniff):
            content_proto = "IMAP"
            content_mode = "EXPLICIT"

        # Content confirmation wins
        if content_proto is not None:
            detected_by = "content"
            final_proto = content_proto
            final_mode = content_mode or "EXPLICIT"
        elif port_proto != "UNKNOWN":
            detected_by = "override" if server_port in self._custom_port_overrides else "port"
            final_proto = port_proto
            final_mode = port_mode
        else:
            detected_by = "port"
            final_proto = "UNKNOWN"
            final_mode = "UNKNOWN"

        return ProtocolClassification(
            protocol=final_proto,
            mode=final_mode,
            detected_by=detected_by,
            port_is_standard_mail=port_is_standard,
            alpn=alpn,
        )

    def check_quic_transport(
        self,
        dest_port: int,
        udp_payload: bytes,
    ) -> ReassemblyFinding | None:
        """Check for unsupported QUIC transport on mail ports and return finding."""
        if (
            dest_port in STANDARD_MAIL_PORTS
            and len(udp_payload) > 0
            and (udp_payload[0] & 0x80) != 0
        ):
            return ReassemblyFinding(
                rule_id="UNSUPPORTED_TRANSPORT_QUIC",
                rule_name="Unsupported Transport QUIC on Mail Port",
                severity="INFO",
                description=(
                    f"Detected QUIC (UDP) traffic on standard mail port {dest_port}. "
                    "PECFF analysis is scoped to TCP STARTTLS/TLS."
                ),
                evidence={"port": dest_port, "header_byte": f"0x{udp_payload[0]:02x}"},
            )
        return None
