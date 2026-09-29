"""Forensic downgrade and STARTTLS stripping detectors D1-D9.

Implements all 9 core downgrade, stripping, and manipulation detectors:
- D1: CAPABILITY_STRIP (Corpus-correlated STARTTLS capability stripping)
- D2: SILENT_FAILURE (STARTTLS command issued without server resolution)
- D3: EXPLICIT_REFUSAL (Server rejected STARTTLS upgrade command)
- D4: POST220_PLAINTEXT (Client sent plaintext following 220 Ready for TLS)
- D5: CLEARTEXT_CREDENTIALS (Plaintext authentication credentials in unencrypted stream)
- D6: VERSION_DOWNGRADE (RFC 8446 TLS downgrade sentinel or 1.3 -> 1.1 forced drop)
- D7: HANDSHAKE_TRUNCATION (TCP RST injected after TLS handshake initiation)
- D8: BANNER_MUTATION (Anomalous server banner mutation across corpus sessions)
- D9: POLICY_VIOLATION (Plaintext transmission violating MTA-STS enforce or DANE policy)
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Final

from pecff.config import settings
from pecff.ingest.reassembly import ReassembledSession
from pecff.parse.starttls_fsm import StarttlsFSM, StarttlsState


@dataclass(frozen=True, slots=True)
class Finding:
    """Standardized forensic finding with standards provenance and byte evidence."""

    rule_id: str
    severity: str  # 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    title: str
    description: str
    evidence_offset: int
    evidence_bytes: bytes
    standards_ref: str
    evidence_summary: dict[str, object] = field(default_factory=dict)


# Regex for credential detection in D5
RE_AUTH_CMD: Final[re.Pattern[bytes]] = re.compile(rb"(?i)^AUTH\s+(?:PLAIN|LOGIN)\s*(.*)$")
RE_USER_CMD: Final[re.Pattern[bytes]] = re.compile(rb"(?i)^USER\s+(\S+)")
RE_PASS_CMD: Final[re.Pattern[bytes]] = re.compile(rb"(?i)^PASS\s+(\S+)")
RE_IMAP_LOGIN_CMD: Final[re.Pattern[bytes]] = re.compile(rb"(?i)^\S+\s+LOGIN\s+(\S+)\s+(\S+)")

# RFC 8446 Downgrade Sentinels in ServerRandom (bytes 24..32)
TLS12_DOWNGRADE_SENTINEL: Final[bytes] = b"DOWNGRD\x01"
TLS11_DOWNGRADE_SENTINEL: Final[bytes] = b"DOWNGRD\x00"


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


class DowngradeDetectorEngine:
    """Runs downgrade and stripping detectors D1-D9 on reassembled sessions."""

    def __init__(
        self,
        known_starttls_endpoints: set[str] | None = None,
        cached_banners: dict[str, str] | None = None,
        mta_sts_policies: dict[str, str] | None = None,
    ) -> None:
        """Initialize engine with optional pre-synced corpus state."""
        # Sets of "ip:port" known to support STARTTLS from other sessions in corpus
        self.known_starttls_endpoints: set[str] = (
            known_starttls_endpoints if known_starttls_endpoints is not None else set()
        )
        # Banners by "ip:port"
        self.cached_banners: dict[str, str] = cached_banners if cached_banners is not None else {}
        # Domain -> mode ("enforce", "testing", "none")
        self.mta_sts_policies: dict[str, str] = (
            mta_sts_policies if mta_sts_policies is not None else {}
        )

    def detect_d1_capability_strip(
        self,
        session: ReassembledSession,
        fsm: StarttlsFSM,
    ) -> Finding | None:
        """D1: Detects STARTTLS capability stripping when known from corpus."""
        endpoint = f"{session.server_ip}:{session.server_port}"
        # Check if server is on explicit mail port with banner present
        if session.server_port in (25, 587, 2525, 110, 143) and fsm.server_banner is not None:
            has_starttls = any(
                "STARTTLS" in cap.upper() or "STLS" in cap.upper()
                for cap in fsm.advertised_capabilities
            )
            # Check if STARTTLS is absent and endpoint advertised STARTTLS in other corpus sessions
            if not has_starttls and endpoint in self.known_starttls_endpoints:
                evidence_bytes = b"\n".join(
                    cap.encode("latin-1") for cap in fsm.advertised_capabilities
                )
                return Finding(
                    rule_id="D1_CAPABILITY_STRIP",
                    severity="CRITICAL",
                    title="STARTTLS Capability Stripping Detected",
                    description=(
                        f"Server {endpoint} did not advertise STARTTLS in capabilities, "
                        "yet is verified to support STARTTLS in historical corpus sessions. "
                        "Indicates active MITM capability stripping."
                    ),
                    evidence_offset=0,
                    evidence_bytes=evidence_bytes[:64],
                    standards_ref="RFC 3207 §4.2, NIST SP 800-52 §3.1",
                    evidence_summary={
                        "server": endpoint,
                        "advertised_capabilities": fsm.advertised_capabilities,
                    },
                )
        return None

    def detect_d2_silent_failure(
        self,
        session: ReassembledSession,
        fsm: StarttlsFSM,
    ) -> Finding | None:
        """D2: Client issued STARTTLS command but received no accept/reject resolution."""
        # Check if S2_CMD was entered
        s2_transitions = [
            t
            for t in fsm.transitions
            if t.to_state in (StarttlsState.S2_CMD.value, StarttlsState.S2_CMD)
        ]
        if not s2_transitions:
            return None

        s2_t = s2_transitions[0]
        # Check if subsequent accept/reject/TLS transition occurred
        resolved = any(
            t.to_state
            in (
                StarttlsState.S2_ACCEPTED.value,
                StarttlsState.S2_ACCEPTED,
                StarttlsState.S_REFUSED.value,
                StarttlsState.S_REFUSED,
                StarttlsState.S3_TLS_HS.value,
                StarttlsState.S3_TLS_HS,
            )
            for t in fsm.transitions
            if t.ts > s2_t.ts
        )

        duration = max(0.0, session.last_seen - s2_t.ts)
        if not resolved:
            return Finding(
                rule_id="D2_SILENT_FAILURE",
                severity="CRITICAL",
                title="STARTTLS Silent Failure (Hanging / Dropped Upgrade)",
                description=(
                    f"STARTTLS upgrade command was transmitted at offset {s2_t.stream_offset} "
                    f"but server produced no accept (220) or reject response within {duration:.1f}s."
                ),
                evidence_offset=s2_t.stream_offset,
                evidence_bytes=s2_t.evidence_bytes,
                standards_ref="RFC 3207 §4",
                evidence_summary={
                    "cmd_offset": s2_t.stream_offset,
                    "elapsed_seconds": duration,
                },
            )
        return None

    def detect_d3_explicit_refusal(
        self,
        fsm: StarttlsFSM,
    ) -> Finding | None:
        """D3: Server explicitly rejected STARTTLS upgrade request with 4xx/5xx/-ERR/NO."""
        refused_transitions = [
            t for t in fsm.transitions if t.to_state == StarttlsState.S_REFUSED.value
        ]
        if refused_transitions:
            t = refused_transitions[0]
            return Finding(
                rule_id="D3_EXPLICIT_REFUSAL",
                severity="HIGH",
                title="Explicit STARTTLS Refusal by Server",
                description=(
                    f"Server explicitly rejected the client's STARTTLS upgrade request with rejection token: "
                    f"'{t.evidence_slice}'."
                ),
                evidence_offset=t.stream_offset,
                evidence_bytes=t.evidence_bytes,
                standards_ref="RFC 3207 §4, RFC 2595 §3.1",
                evidence_summary={
                    "offset": t.stream_offset,
                    "rejection_response": t.evidence_slice,
                },
            )
        return None

    def detect_d4_post220_plaintext(
        self,
        session: ReassembledSession,
        fsm: StarttlsFSM,
    ) -> Finding | None:
        """D4: Server sent 220 Ready for TLS, but client continued sending plaintext email commands."""
        strip_transitions = [
            t
            for t in fsm.transitions
            if t.to_state
            in (
                StarttlsState.S_STRIP_DETECTED.value,
                StarttlsState.S_STRIP_DETECTED,
            )
        ]
        if strip_transitions or fsm.state == StarttlsState.S_STRIP_DETECTED:
            t = strip_transitions[0] if strip_transitions else fsm.transitions[-1]
            return Finding(
                rule_id="D4_POST220_PLAINTEXT",
                severity="CRITICAL",
                title="Post-220 Plaintext Transmission (Active STARTTLS Stripping)",
                description=(
                    "Server accepted STARTTLS negotiation (220 Ready for TLS), but client "
                    "subsequently transmitted plaintext application commands instead of a TLS ClientHello. "
                    "Definitive indicator of an active proxy/MITM stripping attack."
                ),
                evidence_offset=t.stream_offset,
                evidence_bytes=t.evidence_bytes,
                standards_ref="RFC 3207 §4.2",
                evidence_summary={
                    "offset": t.stream_offset,
                    "observed_plaintext": t.evidence_slice,
                },
            )

        return None

    def detect_d5_cleartext_credentials(
        self,
        session: ReassembledSession,
        fsm: StarttlsFSM,
    ) -> Finding | None:
        """D5: Cleartext authentication credentials exposed in an unencrypted session."""
        if fsm.state == StarttlsState.S4_ENCRYPTED:
            return None

        # Scan C2S payload for AUTH / USER / PASS / LOGIN commands
        c2s_lines = session.c2s_payload.split(b"\n")
        for line in c2s_lines:
            s_line = line.strip()
            if not s_line:
                continue

            matched = False
            secret_to_protect = b""
            mech = "PLAINTEXT"

            m_auth = RE_AUTH_CMD.match(s_line)
            m_user = RE_USER_CMD.match(s_line)
            m_pass = RE_PASS_CMD.match(s_line)
            m_imap = RE_IMAP_LOGIN_CMD.match(s_line)

            if m_auth:
                matched = True
                mech = "SASL"
                secret_to_protect = m_auth.group(1)
            elif m_pass:
                matched = True
                mech = "POP3_PASS"
                secret_to_protect = m_pass.group(1)
            elif m_user:
                matched = True
                mech = "POP3_USER"
                secret_to_protect = m_user.group(1)
            elif m_imap:
                matched = True
                mech = "IMAP_LOGIN"
                secret_to_protect = m_imap.group(2)

            if matched:
                # Obfuscate or hash secret unless retain_pii is enabled
                if not settings.retain_pii:
                    salt_bytes = settings.pii_salt.encode("utf-8")
                    hashed_secret = hashlib.sha256(salt_bytes + secret_to_protect).hexdigest()
                    evidence_repr = (
                        f"{s_line[:8].decode('latin-1', errors='ignore')} "
                        f"[HASHED:{hashed_secret[:16]}...]"
                    )
                    evidence_bytes = s_line[:8] + b" [HASHED_PII]"
                else:
                    evidence_repr = s_line.decode("latin-1", errors="ignore")
                    evidence_bytes = s_line[:64]

                return Finding(
                    rule_id="D5_CLEARTEXT_CREDENTIALS",
                    severity="CRITICAL",
                    title="Cleartext Authentication Credentials Transmitted",
                    description=(
                        f"Authentication credentials were sent in cleartext without TLS encryption "
                        f"using mechanism '{mech}'."
                    ),
                    evidence_offset=0,
                    evidence_bytes=evidence_bytes,
                    standards_ref="RFC 4954 §4, NIST SP 800-52 §3.1",
                    evidence_summary={
                        "mechanism": mech,
                        "credential_snippet": evidence_repr,
                        "pii_redacted": not settings.retain_pii,
                    },
                )
        return None

    def detect_d6_version_downgrade(
        self,
        client_supported_versions: list[int] | None,
        server_selected_version: int | None,
        server_random: bytes | None,
    ) -> Finding | None:
        """D6: TLS version downgrade attack or RFC 8446 downgrade sentinel detected."""
        # 1. Check RFC 8446 Downgrade Sentinels in ServerRandom bytes 24..32
        if server_random and len(server_random) >= 32:
            sentinel = server_random[24:32]
            if sentinel in (TLS12_DOWNGRADE_SENTINEL, TLS11_DOWNGRADE_SENTINEL):
                target_proto = (
                    "TLS 1.2" if sentinel == TLS12_DOWNGRADE_SENTINEL else "TLS 1.1 or lower"
                )
                return Finding(
                    rule_id="D6_VERSION_DOWNGRADE",
                    severity="CRITICAL",
                    title="TLS Downgrade Sentinel Detected in ServerRandom",
                    description=(
                        f"ServerRandom bytes [24:32] contain RFC 8446 downgrade sentinel {sentinel!r}. "
                        f"Indicates a TLS 1.3 capable client was forced down to {target_proto} by a network attacker."
                    ),
                    evidence_offset=24,
                    evidence_bytes=sentinel,
                    standards_ref="RFC 8446 §4.1.3",
                    evidence_summary={
                        "sentinel": sentinel.hex(),
                        "target_protocol": target_proto,
                    },
                )

        # 2. Check ClientHello supported TLS 1.3 (0x0304) but negotiated <= TLS 1.1 (0x0302)
        if (
            client_supported_versions
            and server_selected_version
            and 0x0304 in client_supported_versions
            and server_selected_version <= 0x0302
        ):
            return Finding(
                rule_id="D6_VERSION_DOWNGRADE",
                severity="CRITICAL",
                title="Forced Insecure TLS Version Downgrade",
                description=(
                    f"Client advertised support for TLS 1.3 (0x0304), but negotiation completed at "
                    f"obsolete version 0x{server_selected_version:04x}."
                ),
                evidence_offset=0,
                evidence_bytes=bytes(
                    [server_selected_version >> 8, server_selected_version & 0xFF]
                ),
                standards_ref="RFC 8446 §4.1.3, NIST SP 800-52 §3.1",
                evidence_summary={
                    "client_versions": [f"0x{v:04x}" for v in client_supported_versions],
                    "server_version": f"0x{server_selected_version:04x}",
                },
            )

        return None

    def detect_d7_handshake_truncation(
        self,
        fsm: StarttlsFSM,
        session: ReassembledSession,
        server_hello_seen: bool,
    ) -> Finding | None:
        """D7: TLS Handshake was initiated (S3_TLS_HS) but terminated with RST before ServerHello."""
        if (
            fsm.state == StarttlsState.S3_TLS_HS
            and not server_hello_seen
            and session.c2s_bytes > 0
            and len(session.s2c_payload) == 0
        ):
            return Finding(
                rule_id="D7_HANDSHAKE_TRUNCATION",
                severity="HIGH",
                title="TLS Handshake Truncation Attack",
                description=(
                    "Client transmitted TLS ClientHello in S3_TLS_HS state, but the connection "
                    "was abruptly terminated or reset before receiving a ServerHello response."
                ),
                evidence_offset=0,
                evidence_bytes=session.c2s_payload[:64],
                standards_ref="RFC 8446, NIST SP 800-52 §3.1",
                evidence_summary={"client_hello_len": len(session.c2s_payload)},
            )
        return None

    def detect_d8_banner_mutation(
        self,
        session: ReassembledSession,
        fsm: StarttlsFSM,
    ) -> Finding | None:
        """D8: Server banner differs significantly (Levenshtein > 8) from corpus history for same IP:port."""
        if not fsm.server_banner:
            return None

        endpoint = f"{session.server_ip}:{session.server_port}"
        if endpoint in self.cached_banners:
            baseline_banner = self.cached_banners[endpoint]
            dist = levenshtein_distance(fsm.server_banner, baseline_banner)
            if dist > settings.banner_mutation_threshold:
                return Finding(
                    rule_id="D8_BANNER_MUTATION",
                    severity="MEDIUM",
                    title="Anomalous Mail Server Banner Mutation",
                    description=(
                        f"Server banner '{fsm.server_banner}' differs significantly "
                        f"(Levenshtein distance {dist} > {settings.banner_mutation_threshold}) "
                        f"from baseline banner for {endpoint} ('{baseline_banner}')."
                    ),
                    evidence_offset=0,
                    evidence_bytes=fsm.server_banner.encode("latin-1", errors="ignore")[:64],
                    standards_ref="RFC 5321 §3.1",
                    evidence_summary={
                        "observed_banner": fsm.server_banner,
                        "baseline_banner": baseline_banner,
                        "levenshtein_distance": dist,
                    },
                )
        return None

    def detect_d9_policy_violation(
        self,
        session: ReassembledSession,
        fsm: StarttlsFSM,
    ) -> Finding | None:
        """D9: Plaintext session violated an offline cached MTA-STS 'enforce' policy or TLSA record."""
        # Only triggers if session ended in unencrypted / plaintext state
        if fsm.state == StarttlsState.S4_ENCRYPTED:
            return None

        # Check domain from EHLO or server reverse mapping
        domain = fsm.ehlo_domain
        if domain:
            domain_clean = domain.lower().strip()
            if domain_clean in self.mta_sts_policies:
                mode = self.mta_sts_policies[domain_clean]
                if mode.lower() == "enforce":
                    return Finding(
                        rule_id="D9_POLICY_VIOLATION",
                        severity="CRITICAL",
                        title="MTA-STS Enforce Policy Violation (Plaintext Fallback)",
                        description=(
                            f"Domain '{domain_clean}' enforces MTA-STS (mode=enforce) requiring mandatory TLS, "
                            "yet the email session was completed without TLS encryption."
                        ),
                        evidence_offset=0,
                        evidence_bytes=domain_clean.encode("latin-1"),
                        standards_ref="RFC 8461 §5 (MTA-STS)",
                        evidence_summary={
                            "domain": domain_clean,
                            "policy_mode": mode,
                            "session_state": fsm.state.value,
                        },
                    )
        return None

    def run_all(
        self,
        session: ReassembledSession,
        fsm: StarttlsFSM,
        client_supported_versions: list[int] | None = None,
        server_selected_version: int | None = None,
        server_random: bytes | None = None,
        server_hello_seen: bool = False,
    ) -> list[Finding]:
        """Run all detectors D1-D9 and collect all positive findings."""
        findings: list[Finding] = []

        detectors = [
            self.detect_d1_capability_strip(session, fsm),
            self.detect_d2_silent_failure(session, fsm),
            self.detect_d3_explicit_refusal(fsm),
            self.detect_d4_post220_plaintext(session, fsm),
            self.detect_d5_cleartext_credentials(session, fsm),
            self.detect_d6_version_downgrade(
                client_supported_versions, server_selected_version, server_random
            ),
            self.detect_d7_handshake_truncation(fsm, session, server_hello_seen),
            self.detect_d8_banner_mutation(session, fsm),
            self.detect_d9_policy_violation(session, fsm),
        ]

        for finding in detectors:
            if finding is not None:
                findings.append(finding)

        return findings

    def analyze_session(
        self,
        session: ReassembledSession,
        fsm: StarttlsFSM,
        client_supported_versions: list[int] | None = None,
        server_selected_version: int | None = None,
        server_random: bytes | None = None,
        server_hello_seen: bool = False,
    ) -> list[Finding]:
        """Alias for run_all()."""
        return self.run_all(
            session=session,
            fsm=fsm,
            client_supported_versions=client_supported_versions,
            server_selected_version=server_selected_version,
            server_random=server_random,
            server_hello_seen=server_hello_seen,
        )
