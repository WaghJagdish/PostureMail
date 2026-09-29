"""Temporal Behavioral Beacon and Automated Polling Detector.

This module provides deterministic, explainable temporal behavioral analysis
to identify regular automated communication / beaconing candidates across
extracted network sessions.

Architectural Guarantees:
- Operates strictly beside the existing deterministic forensic risk engine.
- Does not claim traffic is malicious or confirmed C2; flags behavioral regularity.
- Minimum event thresholds and safe handling of zero/invalid intervals.
- O(N log N) grouping and interval analysis per endpoint identity.
- Lightweight: Standard library statistics and math only.
"""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from enum import Enum
import statistics
from typing import Any, Sequence

logger = logging.getLogger("pecff.temporal_detector")

# ---------------------------------------------------------------------------
# Centralized Configuration Thresholds (§9, §12, §13, §14, §32)
# ---------------------------------------------------------------------------
MIN_EVENTS: int = 5
JITTER_REGULAR_THRESHOLD: float = 15.0      # percent (< 15% is regular)
JITTER_HIGHLY_REGULAR_THRESHOLD: float = 5.0 # percent (< 5% is highly regular)
CV_REGULAR_THRESHOLD: float = 0.15          # CoV (< 0.15 is regular)
SUSPICIOUS_SCORE_THRESHOLD: int = 40        # 40-69 SUSPICIOUS_TIMING
BEACON_CANDIDATE_SCORE_THRESHOLD: int = 70  # 70-100 BEACON_CANDIDATE
MIN_PERSISTENCE_SECONDS: float = 300.0      # 5 minutes duration persistence


class TemporalClassification(str, Enum):
    """Explicit behavioral classifications (§14, §15)."""

    NORMAL = "NORMAL"
    SUSPICIOUS_TIMING = "SUSPICIOUS_TIMING"
    BEACON_CANDIDATE = "BEACON_CANDIDATE"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


@dataclass(slots=True)
class TemporalAnalysisResult:
    """Structured temporal behavior analysis result (§16)."""

    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str

    event_count: int
    session_ids: list[str] = field(default_factory=list)

    mean_interval: float | None = None
    std_interval: float | None = None
    cv: float | None = None
    jitter_pct: float | None = None
    duration: float = 0.0

    behavior_score: int = 0
    classification: str = TemporalClassification.INSUFFICIENT_DATA.value
    explanation: list[str] = field(default_factory=list)
    analyst_note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def calculate_temporal_metrics(
    timestamps: Sequence[float],
) -> tuple[int, list[float], float | None, float | None, float | None, float | None, float]:
    """Sort timestamps, extract valid non-negative intervals, and compute statistics.

    Handles duplicates, zero intervals, negative delta skips, and single/few events safely.
    Returns:
        (event_count, intervals, mean_interval, std_interval, cv, jitter_pct, duration)
    """
    if not timestamps:
        return 0, [], None, None, None, None, 0.0

    # Filter invalid/None/NaN and sort chronologically
    clean_ts = sorted(
        float(t) for t in timestamps if t is not None and not math.isnan(float(t))
    )
    event_count = len(clean_ts)
    if event_count < 2:
        return event_count, [], None, None, None, None, 0.0

    duration = clean_ts[-1] - clean_ts[0]

    # Calculate inter-arrival intervals
    raw_intervals = [clean_ts[i] - clean_ts[i - 1] for i in range(1, event_count)]

    # Filter out duplicate zero timestamps and negative intervals safely (§8, §27)
    valid_intervals = [iv for iv in raw_intervals if iv > 0.0]

    if not valid_intervals:
        return event_count, [], None, None, None, None, duration

    mean_interval = statistics.mean(valid_intervals)

    if len(valid_intervals) >= 2:
        std_interval = statistics.stdev(valid_intervals)
    else:
        std_interval = 0.0

    if mean_interval > 0:
        cv = std_interval / mean_interval
        jitter_pct = cv * 100.0
    else:
        cv = None
        jitter_pct = None

    return event_count, valid_intervals, mean_interval, std_interval, cv, jitter_pct, duration


def score_and_classify_group(
    event_count: int,
    mean_interval: float | None,
    std_interval: float | None,
    cv: float | None,
    jitter_pct: float | None,
    duration: float,
) -> tuple[int, TemporalClassification, list[str], str]:
    """Compute deterministic explainable score, classification, and reasoning (§13, §14, §21).

    Scoring formula:
    - Base event sufficiency: +20 points (event_count >= MIN_EVENTS)
    - Valid recurrence period: +20 points (mean_interval is valid and > 0)
    - Low jitter (< 15%): +30 points
    - Low CV (< 0.15): +20 points
    - Persistence (duration >= 300s): +10 points
    """
    if event_count < MIN_EVENTS:
        return (
            0,
            TemporalClassification.INSUFFICIENT_DATA,
            [f"Only {event_count} communication events observed (minimum threshold is {MIN_EVENTS})."],
            "Insufficient observations to perform reliable temporal timing analysis.",
        )

    score = 0
    reasons: list[str] = []

    # 1. Event count check
    if event_count >= MIN_EVENTS:
        score += 20
        reasons.append(f"{event_count} communication events observed (>= {MIN_EVENTS})")

    # 2. Mean interval
    if mean_interval is not None and mean_interval > 0:
        score += 20
        reasons.append(f"Mean inter-arrival interval: {mean_interval:.2f}s")
    else:
        reasons.append("Mean interval could not be established.")

    # 3. Jitter percentage
    if jitter_pct is not None:
        if jitter_pct < JITTER_REGULAR_THRESHOLD:
            score += 30
            if jitter_pct < JITTER_HIGHLY_REGULAR_THRESHOLD:
                reasons.append(f"Highly regular timing: Jitter is {jitter_pct:.2f}% (< {JITTER_HIGHLY_REGULAR_THRESHOLD}%)")
            else:
                reasons.append(f"Regular timing: Jitter is {jitter_pct:.2f}% (< {JITTER_REGULAR_THRESHOLD}%)")
        else:
            reasons.append(f"Irregular timing: Jitter is {jitter_pct:.2f}% (>= {JITTER_REGULAR_THRESHOLD}%)")

    # 4. Coefficient of Variation
    if cv is not None:
        if cv < CV_REGULAR_THRESHOLD:
            score += 20
            reasons.append(f"Low timing variance: Coefficient of variation is {cv:.4f} (< {CV_REGULAR_THRESHOLD})")
        else:
            reasons.append(f"High timing variance: Coefficient of variation is {cv:.4f} (>= {CV_REGULAR_THRESHOLD})")

    # 5. Persistence bonus
    if duration >= MIN_PERSISTENCE_SECONDS:
        score += 10
        reasons.append(f"Observed communication persisted over {duration:.1f}s ({duration / 60.0:.1f} minutes)")
    elif duration > 0:
        reasons.append(f"Communication span: {duration:.1f}s")

    # Classification boundaries (§14)
    if score >= BEACON_CANDIDATE_SCORE_THRESHOLD:
        classification = TemporalClassification.BEACON_CANDIDATE
        analyst_note = (
            "Regular automated communication pattern requiring investigation. "
            "Timing alone does not establish malicious activity (may be telemetry, monitoring, or legitimate polling)."
        )
    elif score >= SUSPICIOUS_SCORE_THRESHOLD:
        classification = TemporalClassification.SUSPICIOUS_TIMING
        analyst_note = (
            "Moderate timing regularity observed, but insufficient evidence to confirm an automated beacon candidate."
        )
    else:
        classification = TemporalClassification.NORMAL
        analyst_note = "Normal or irregular timing with no meaningful evidence of automated beaconing."

    return score, classification, reasons, analyst_note


def analyze_group(
    timestamps: Sequence[float],
    metadata: dict[str, Any],
    session_ids: Sequence[str] | None = None,
) -> TemporalAnalysisResult:
    """Analyze a single communication group defined by endpoint identity (§31)."""
    src_ip = str(metadata.get("src_ip", metadata.get("client_ip", "")))
    dst_ip = str(metadata.get("dst_ip", metadata.get("server_ip", "")))
    dst_port = int(metadata.get("dst_port", metadata.get("server_port", 0)))
    protocol = str(metadata.get("protocol", "TCP"))

    (
        event_count,
        valid_intervals,
        mean_iv,
        std_iv,
        cv,
        jitter,
        duration,
    ) = calculate_temporal_metrics(timestamps)

    score, classification, reasons, analyst_note = score_and_classify_group(
        event_count=event_count,
        mean_interval=mean_iv,
        std_interval=std_iv,
        cv=cv,
        jitter_pct=jitter,
        duration=duration,
    )

    return TemporalAnalysisResult(
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol,
        event_count=event_count,
        session_ids=list(session_ids or []),
        mean_interval=round(mean_iv, 3) if mean_iv is not None else None,
        std_interval=round(std_iv, 3) if std_iv is not None else None,
        cv=round(cv, 4) if cv is not None else None,
        jitter_pct=round(jitter, 2) if jitter is not None else None,
        duration=round(duration, 2),
        behavior_score=score,
        classification=classification.value,
        explanation=reasons,
        analyst_note=analyst_note,
    )


def analyze_temporal_behavior(
    sessions: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    """Group sessions by canonical endpoint identity and evaluate temporal behaviors (§6, §30, §31, §33).

    Canonical grouping key:
        (src_ip, dst_ip, dst_port, protocol)

    Returns:
        {
            "groups": list[dict],
            "session_enrichments": dict[session_id, dict],
            "summary": {
                "analyzed_groups": int,
                "beacon_candidates": int,
                "suspicious_timing": int,
                "insufficient_data": int,
                "normal": int,
            }
        }
    """
    if not sessions:
        return {
            "groups": [],
            "session_enrichments": {},
            "summary": {
                "analyzed_groups": 0,
                "beacon_candidates": 0,
                "suspicious_timing": 0,
                "insufficient_data": 0,
                "normal": 0,
            },
        }

    grouped_sessions: dict[tuple[str, str, int, str], list[dict[str, Any]]] = defaultdict(list)

    for s in sessions:
        src = str(s.get("client_ip") or s.get("src_ip", ""))
        dst = str(s.get("server_ip") or s.get("dst_ip", ""))
        port = int(s.get("server_port") or s.get("dst_port", 0))
        proto = str(s.get("protocol", "TCP"))

        if src and dst:
            grouped_sessions[(src, dst, port, proto)].append(s)

    results: list[TemporalAnalysisResult] = []
    session_enrichments: dict[str, dict[str, Any]] = {}

    beacon_count = 0
    suspicious_count = 0
    insufficient_count = 0
    normal_count = 0

    for (src, dst, port, proto), grp in grouped_sessions.items():
        try:
            # Collect timestamps and session IDs
            timestamps: list[float] = []
            sids: list[str] = []
            for item in grp:
                ts = item.get("first_seen", item.get("timestamp"))
                if ts is not None:
                    try:
                        timestamps.append(float(ts))
                        sids.append(str(item.get("id", "")))
                    except (ValueError, TypeError):
                        continue

            meta = {
                "src_ip": src,
                "dst_ip": dst,
                "dst_port": port,
                "protocol": proto,
            }
            res = analyze_group(timestamps, meta, session_ids=sids)
            results.append(res)

            # Update count summaries
            if res.classification == TemporalClassification.BEACON_CANDIDATE.value:
                beacon_count += 1
            elif res.classification == TemporalClassification.SUSPICIOUS_TIMING.value:
                suspicious_count += 1
            elif res.classification == TemporalClassification.INSUFFICIENT_DATA.value:
                insufficient_count += 1
            else:
                normal_count += 1

            # Enrich individual sessions so each session has access to its group behavior
            for sid in sids:
                if sid:
                    session_enrichments[sid] = {
                        "temporal_classification": res.classification,
                        "temporal_behavior_score": res.behavior_score,
                        "temporal_mean_interval": res.mean_interval,
                        "temporal_jitter_pct": res.jitter_pct,
                        "temporal_cv": res.cv,
                        "temporal_duration": res.duration,
                        "temporal_event_count": res.event_count,
                        "temporal_analyst_note": res.analyst_note,
                    }
        except Exception as err:
            logger.warning("Error analyzing temporal group (%s, %s, %d): %s", src, dst, port, err)

    # Sort results with most notable beacon candidates first
    results.sort(key=lambda r: (r.behavior_score, r.event_count), reverse=True)

    logger.info(
        "Temporal analysis: %d communication groups | %d with sufficient observations | "
        "%d beacon candidates | %d suspicious timing patterns",
        len(grouped_sessions),
        len(grouped_sessions) - insufficient_count,
        beacon_count,
        suspicious_count,
    )

    return {
        "groups": [r.to_dict() for r in results],
        "session_enrichments": session_enrichments,
        "summary": {
            "analyzed_groups": len(grouped_sessions),
            "beacon_candidates": beacon_count,
            "suspicious_timing": suspicious_count,
            "insufficient_data": insufficient_count,
            "normal": normal_count,
        },
    }
