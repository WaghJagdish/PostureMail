"""Corpus-level beaconing, timing correlation, and cross-session detection engine.

Implements four corpus-wide detectors that only become meaningful once all
per-session shards are merged into a single session list:

    CB1  BEACONING           - periodic inter-arrival pattern from one src to one dst
    CB2  D8_BANNER_MUTATION  - EHLO banner change across sessions to the same server
    CB3  D1_CORPUS_STRIP     - server that offers STARTTLS to some clients but not others
    CB4  JA3_RARITY          - anomalous / singleton JA3 client fingerprints

Each detector is O(N) or O(N log N) in the number of sessions.  The engine
also computes per-session auxiliary statistics (src session count, distinct SNI
count per src) that are fed back into the 94-dim feature vector so that
is_periodic is no longer always False.

Public API
----------
run_corpus_correlation(sessions, findings) -> CorpusCorrelationResult
"""

from __future__ import annotations

import math
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from pecff.config import settings
from pecff.parse.downgrade_detectors import levenshtein_distance


# ---------------------------------------------------------------------------
# Result Types
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class BeaconGroup:
    """A group of sessions identified as periodic / beaconing."""

    src_ip: str
    dst_ip: str
    dst_port: int
    session_ids: list[str]
    inter_arrival_mean_s: float
    inter_arrival_std_s: float
    coefficient_of_variation: float
    period_estimate_s: float


@dataclass(slots=True)
class CorpusCorrelationResult:
    """Full result of one corpus-level correlation pass."""

    beacon_groups: list[BeaconGroup] = field(default_factory=list)
    new_findings: list[dict[str, Any]] = field(default_factory=list)

    # Per-session enrichment maps - keyed by session id
    session_is_periodic: dict[str, bool] = field(default_factory=dict)
    session_src_count: dict[str, int] = field(default_factory=dict)
    session_distinct_sni: dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Detector: CB1 - Periodic Beaconing
# ---------------------------------------------------------------------------

# Minimum sessions in a group to trigger beaconing analysis
MIN_SESSIONS_FOR_BEACON: int = 5

# CoV threshold - below this the traffic is suspiciously regular
COV_BEACON_THRESHOLD: float = 0.30


def _detect_beaconing(
    sessions: list[dict[str, Any]],
) -> tuple[list[BeaconGroup], set[str]]:
    """Group sessions by (src_ip, dst_ip, dst_port), sort by first_seen, compute
    inter-arrival deltas and Coefficient of Variation (CoV = std / mean).

    CoV < COV_BEACON_THRESHOLD on >= MIN_SESSIONS_FOR_BEACON sessions -> BEACON.

    Returns:
        beacon_groups:    list of BeaconGroup
        periodic_session_ids: set of session ids that are in a beacon group
    """
    groups: dict[tuple[str, str, int], list[dict[str, Any]]] = defaultdict(list)
    for s in sessions:
        src = s.get("client_ip", "")
        dst = s.get("server_ip", "")
        port = int(s.get("server_port", 0))
        if src and dst:
            groups[(src, dst, port)].append(s)

    beacon_groups: list[BeaconGroup] = []
    periodic_ids: set[str] = set()

    for (src, dst, port), grp in groups.items():
        if len(grp) < MIN_SESSIONS_FOR_BEACON:
            continue

        # Sort by capture timestamp
        sorted_grp = sorted(grp, key=lambda x: float(x.get("first_seen", 0.0)))
        timestamps = [float(s.get("first_seen", 0.0)) for s in sorted_grp]
        deltas = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]

        # Need at least 4 deltas for meaningful statistics
        if len(deltas) < 4:
            continue

        mean_delta = sum(deltas) / len(deltas)
        if mean_delta <= 0:
            continue

        variance = sum((d - mean_delta) ** 2 for d in deltas) / len(deltas)
        std_delta = math.sqrt(variance)
        cov = std_delta / mean_delta

        if cov < COV_BEACON_THRESHOLD:
            ids = [s["id"] for s in sorted_grp]
            bg = BeaconGroup(
                src_ip=src,
                dst_ip=dst,
                dst_port=port,
                session_ids=ids,
                inter_arrival_mean_s=mean_delta,
                inter_arrival_std_s=std_delta,
                coefficient_of_variation=cov,
                period_estimate_s=mean_delta,
            )
            beacon_groups.append(bg)
            periodic_ids.update(ids)

    return beacon_groups, periodic_ids


# ---------------------------------------------------------------------------
# Detector: CB2 - D8 Banner Mutation
# ---------------------------------------------------------------------------


def _detect_banner_mutation(sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Compare STARTTLS/EHLO banners across sessions to the same (server_ip, server_port).

    Levenshtein distance above the configured threshold -> D8_BANNER_MUTATION finding.
    """
    threshold: int = settings.banner_mutation_threshold
    banners_by_endpoint: dict[tuple[str, int], list[tuple[str, str]]] = defaultdict(list)

    for s in sessions:
        banner = s.get("ehlo_banner") or s.get("smtp_banner") or s.get("server_banner")
        if banner and isinstance(banner, str):
            key: tuple[str, int] = (
                str(s.get("server_ip", "")),
                int(s.get("server_port", 25)),
            )
            banners_by_endpoint[key].append((s["id"], banner))

    findings: list[dict[str, Any]] = []
    seen_pairs: set[tuple[str, str, str]] = set()

    for (srv_ip, srv_port), entries in banners_by_endpoint.items():
        if len(entries) < 2:
            continue
        for i in range(len(entries)):
            for j in range(i + 1, len(entries)):
                sid_a, ban_a = entries[i]
                sid_b, ban_b = entries[j]
                dist = levenshtein_distance(ban_a, ban_b)
                if dist >= threshold:
                    pair_key = (min(sid_a, sid_b), max(sid_a, sid_b), str(dist))
                    if pair_key in seen_pairs:
                        continue
                    seen_pairs.add(pair_key)
                    findings.append(
                        {
                            "id": str(uuid.uuid4()),
                            "session_id": sid_a,
                            "rule_id": "D8_BANNER_MUTATION",
                            "title": "Anomalous Server Banner Mutation Detected",
                            "description": (
                                f"Server {srv_ip}:{srv_port} presented banners with "
                                f"Levenshtein distance {dist} (threshold={threshold}) "
                                f"across sessions {sid_a} and {sid_b}. "
                                "This may indicate active MitM banner injection."
                            ),
                            "severity": "HIGH",
                            "standards_ref": "NIST SP 800-52r2 §3.1; RFC 3207 §4",
                            "evidence": {
                                "server_ip": srv_ip,
                                "server_port": srv_port,
                                "banner_a": ban_a[:256],
                                "banner_b": ban_b[:256],
                                "levenshtein_distance": dist,
                                "session_a": sid_a,
                                "session_b": sid_b,
                            },
                        }
                    )
    return findings


# ---------------------------------------------------------------------------
# Detector: CB3 - D1 Corpus-Level STARTTLS Capability Strip
# ---------------------------------------------------------------------------

_STARTTLS_CLEAN_STATES: frozenset[str] = frozenset(
    {"S3_STARTTLS_OK", "S4_TLS_READY", "S4_ENCRYPTED"}
)
_STARTTLS_ABSENT_STATES: frozenset[str] = frozenset(
    {"S0_TCP_EST", "S1_BANNER_SEEN", "S_NO_STARTTLS"}
)


def _detect_corpus_capability_strip(sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Identify servers where STARTTLS is offered to some clients but withheld from others."""
    endpoint_states: dict[tuple[str, int], dict[str, list[str]]] = defaultdict(
        lambda: {"clean": [], "absent": []}
    )

    for s in sessions:
        state = str(s.get("starttls_state", ""))
        srv: tuple[str, int] = (
            str(s.get("server_ip", "")),
            int(s.get("server_port", 25)),
        )
        if state in _STARTTLS_CLEAN_STATES:
            endpoint_states[srv]["clean"].append(s["id"])
        elif state in _STARTTLS_ABSENT_STATES:
            endpoint_states[srv]["absent"].append(s["id"])

    findings: list[dict[str, Any]] = []
    for (srv_ip, srv_port), buckets in endpoint_states.items():
        if buckets["clean"] and buckets["absent"]:
            findings.append(
                {
                    "id": str(uuid.uuid4()),
                    "session_id": buckets["absent"][0],
                    "rule_id": "D1_CORPUS_CAPABILITY_STRIP",
                    "title": "Corpus-Correlated STARTTLS Capability Stripping",
                    "description": (
                        f"Server {srv_ip}:{srv_port} successfully upgraded "
                        f"{len(buckets['clean'])} session(s) via STARTTLS but withheld "
                        f"the capability in {len(buckets['absent'])} other session(s). "
                        "This asymmetry strongly indicates active STARTTLS stripping."
                    ),
                    "severity": "CRITICAL",
                    "standards_ref": "NIST SP 800-52r2 §3.3.1; RFC 3207 §4",
                    "evidence": {
                        "server_ip": srv_ip,
                        "server_port": srv_port,
                        "sessions_with_starttls": buckets["clean"][:10],
                        "sessions_without_starttls": buckets["absent"][:10],
                        "stripped_count": len(buckets["absent"]),
                        "clean_count": len(buckets["clean"]),
                    },
                }
            )
    return findings


# ---------------------------------------------------------------------------
# Detector: CB4 - JA3 Rarity / Singleton Fingerprints
# ---------------------------------------------------------------------------

JA3_RARITY_COUNT_THRESHOLD: int = 2


def _detect_ja3_rarity(sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flag JA3 fingerprints that appear only once or twice across the entire corpus."""
    if len(sessions) < 10:
        return []

    ja3_counts: Counter[str] = Counter()
    ja3_to_sessions: dict[str, list[str]] = defaultdict(list)

    for s in sessions:
        ja3 = s.get("ja3")
        if ja3 and isinstance(ja3, str):
            ja3_counts[ja3] += 1
            ja3_to_sessions[ja3].append(s["id"])

    findings: list[dict[str, Any]] = []
    for ja3_hash, count in ja3_counts.items():
        if count <= JA3_RARITY_COUNT_THRESHOLD:
            sid = ja3_to_sessions[ja3_hash][0]
            findings.append(
                {
                    "id": str(uuid.uuid4()),
                    "session_id": sid,
                    "rule_id": "CB4_JA3_SINGLETON_FINGERPRINT",
                    "title": "Rare/Singleton JA3 TLS Client Fingerprint",
                    "description": (
                        f"JA3 fingerprint {ja3_hash} appeared only {count} time(s) "
                        f"across {len(sessions)} sessions. "
                        "Rare fingerprints may indicate novel malware, C2 beaconing, "
                        "or an unusual/misconfigured MTA client library."
                    ),
                    "severity": "MEDIUM",
                    "standards_ref": "NIST SP 800-52r2 §3.4; MITRE ATT&CK T1071.003",
                    "evidence": {
                        "ja3": ja3_hash,
                        "occurrence_count": count,
                        "corpus_session_count": len(sessions),
                        "rarity_percentile": round(100.0 * count / len(sessions), 4),
                        "affected_sessions": ja3_to_sessions[ja3_hash][:5],
                    },
                }
            )
    return findings


# ---------------------------------------------------------------------------
# Auxiliary stat computation - feeds back into 94-dim ML feature vector
# ---------------------------------------------------------------------------


def _compute_src_statistics(
    sessions: list[dict[str, Any]],
) -> tuple[dict[str, int], dict[str, int]]:
    """Compute per-src_ip session count and distinct SNI count.

    Returns:
        src_session_count:  { src_ip: int }
        src_distinct_sni:   { src_ip: int }
    """
    src_counts: Counter[str] = Counter()
    src_sni: dict[str, set[str]] = defaultdict(set)

    for s in sessions:
        src = str(s.get("client_ip", ""))
        if not src:
            continue
        src_counts[src] += 1
        sni = s.get("sni")
        if sni:
            src_sni[src].add(str(sni))

    src_distinct = {src: len(sni_set) for src, sni_set in src_sni.items()}
    return dict(src_counts), src_distinct


# ---------------------------------------------------------------------------
# Public Entry Point
# ---------------------------------------------------------------------------


def run_corpus_correlation(
    sessions: list[dict[str, Any]],
    existing_findings: list[dict[str, Any]],
) -> CorpusCorrelationResult:
    """Run all four corpus-level detectors over the merged session list.

    Called once in ``finalize_corpus_task`` after all per-shard results are
    merged.  Purely functional - does not mutate sessions in place.

    Args:
        sessions:          Merged list of all session dicts from all shards.
        existing_findings: Findings already generated by per-session detectors.

    Returns:
        CorpusCorrelationResult with beacon groups, new findings, and
        per-session auxiliary maps.
    """
    result = CorpusCorrelationResult()

    # CB1 - beaconing
    beacon_groups, periodic_ids = _detect_beaconing(sessions)
    result.beacon_groups = beacon_groups

    for bg in beacon_groups:
        result.new_findings.append(
            {
                "id": str(uuid.uuid4()),
                "session_id": bg.session_ids[0] if bg.session_ids else "",
                "rule_id": "CB1_BEACONING_PERIODIC_SESSIONS",
                "title": "Periodic Beaconing Traffic Pattern Detected",
                "description": (
                    f"{len(bg.session_ids)} sessions from {bg.src_ip} to "
                    f"{bg.dst_ip}:{bg.dst_port} show suspiciously regular "
                    f"inter-arrival timing (mean={bg.inter_arrival_mean_s:.1f}s, "
                    f"CoV={bg.coefficient_of_variation:.3f} < {COV_BEACON_THRESHOLD}). "
                    "This is consistent with automated C2 beacon or malware heartbeat traffic."
                ),
                "severity": "HIGH",
                "standards_ref": "NIST SP 800-52r2 §3.4; MITRE ATT&CK T1071.003",
                "evidence": {
                    "src_ip": bg.src_ip,
                    "dst_ip": bg.dst_ip,
                    "dst_port": bg.dst_port,
                    "session_count": len(bg.session_ids),
                    "period_estimate_s": round(bg.period_estimate_s, 3),
                    "inter_arrival_mean_s": round(bg.inter_arrival_mean_s, 3),
                    "inter_arrival_std_s": round(bg.inter_arrival_std_s, 3),
                    "coefficient_of_variation": round(bg.coefficient_of_variation, 4),
                    "session_ids": bg.session_ids[:10],
                },
            }
        )

    # CB2 - banner mutation
    result.new_findings.extend(_detect_banner_mutation(sessions))

    # CB3 - D1 corpus STARTTLS strip
    result.new_findings.extend(_detect_corpus_capability_strip(sessions))

    # CB4 - JA3 rarity
    result.new_findings.extend(_detect_ja3_rarity(sessions))

    # Per-session auxiliary stats
    src_counts, src_distinct_sni = _compute_src_statistics(sessions)

    for s in sessions:
        sid = s["id"]
        src = str(s.get("client_ip", ""))
        result.session_is_periodic[sid] = sid in periodic_ids
        result.session_src_count[sid] = src_counts.get(src, 1)
        result.session_distinct_sni[sid] = src_distinct_sni.get(src, 1)

    return result
