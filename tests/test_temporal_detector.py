"""Unit tests for Temporal Behavioral Beacon and Automated Polling Detector.

Tests cover:
- Test Case 1: Perfect periodic traffic
- Test Case 2: Slightly jittered traffic
- Test Case 3: Highly irregular traffic
- Test Case 4: Insufficient data
- Test Case 5: Zero interval / duplicate timestamps
- Test Case 6: Empty input
- Test Case 7: Legitimate regular polling (60s intervals)
- Test Case 8: Session grouping & enrichment
"""

from __future__ import annotations

import pytest

from pecff.engine.temporal_detector import (
    BEACON_CANDIDATE_SCORE_THRESHOLD,
    CV_REGULAR_THRESHOLD,
    JITTER_REGULAR_THRESHOLD,
    MIN_EVENTS,
    SUSPICIOUS_SCORE_THRESHOLD,
    TemporalClassification,
    analyze_group,
    analyze_temporal_behavior,
    calculate_temporal_metrics,
)


class TestTemporalDetector:
    """Deterministic validation of behavioral beaconing detection."""

    def test_case_1_perfect_periodic_traffic(self):
        """Test Case 1: 0, 10, 20, 30, 40, 50, 60 -> mean=10, std=0, cv=0, BEACON_CANDIDATE."""
        timestamps = [0.0, 10.0, 20.0, 30.0, 40.0, 50.0, 60.0]
        meta = {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.1", "dst_port": 443, "protocol": "TCP"}

        result = analyze_group(timestamps, meta)

        assert result.event_count == 7
        assert result.mean_interval == 10.0
        assert result.std_interval == 0.0
        assert result.cv == 0.0
        assert result.jitter_pct == 0.0
        assert result.classification == TemporalClassification.BEACON_CANDIDATE.value
        assert result.behavior_score >= BEACON_CANDIDATE_SCORE_THRESHOLD
        assert "Highly regular timing" in " ".join(result.explanation)

    def test_case_2_slightly_jittered_traffic(self):
        """Test Case 2: slight jitter around 10s intervals -> low jitter & cv, BEACON_CANDIDATE."""
        # Consecutive intervals: 9.8, 10.4, 9.7, 10.2, 10.1, 9.9, 10.3
        deltas = [9.8, 10.4, 9.7, 10.2, 10.1, 9.9, 10.3]
        timestamps = [0.0]
        for d in deltas:
            timestamps.append(timestamps[-1] + d)

        meta = {"src_ip": "10.0.0.15", "dst_ip": "203.0.113.20", "dst_port": 25, "protocol": "SMTP"}
        result = analyze_group(timestamps, meta)

        assert result.event_count == 8
        assert result.mean_interval is not None and 9.5 < result.mean_interval < 10.5
        assert result.jitter_pct is not None and result.jitter_pct < JITTER_REGULAR_THRESHOLD
        assert result.cv is not None and result.cv < CV_REGULAR_THRESHOLD
        assert result.classification == TemporalClassification.BEACON_CANDIDATE.value
        assert result.behavior_score >= BEACON_CANDIDATE_SCORE_THRESHOLD

    def test_case_3_highly_irregular_traffic(self):
        """Test Case 3: intervals: 2, 37, 8, 91, 4, 52 -> high jitter, NOT BEACON_CANDIDATE."""
        deltas = [2.0, 37.0, 8.0, 91.0, 4.0, 52.0]
        timestamps = [0.0]
        for d in deltas:
            timestamps.append(timestamps[-1] + d)

        meta = {"src_ip": "10.0.0.2", "dst_ip": "192.168.1.5", "dst_port": 587, "protocol": "TCP"}
        result = analyze_group(timestamps, meta)

        assert result.event_count == 7
        assert result.jitter_pct is not None and result.jitter_pct > JITTER_REGULAR_THRESHOLD
        assert result.cv is not None and result.cv > CV_REGULAR_THRESHOLD
        assert result.classification != TemporalClassification.BEACON_CANDIDATE.value
        assert result.classification in (
            TemporalClassification.NORMAL.value,
            TemporalClassification.SUSPICIOUS_TIMING.value,
        )

    def test_case_4_insufficient_data(self):
        """Test Case 4: 0, 10 -> 2 events (< MIN_EVENTS=5) -> INSUFFICIENT_DATA."""
        timestamps = [0.0, 10.0]
        meta = {"src_ip": "10.0.0.3", "dst_ip": "10.0.0.4", "dst_port": 993, "protocol": "IMAP"}
        result = analyze_group(timestamps, meta)

        assert result.event_count == 2
        assert result.classification == TemporalClassification.INSUFFICIENT_DATA.value
        assert result.behavior_score == 0

    def test_case_5_zero_interval_duplicate_timestamps(self):
        """Test Case 5: 0, 10, 10, 20, 30, 40 -> safe handling without crash."""
        timestamps = [0.0, 10.0, 10.0, 20.0, 30.0, 40.0]
        meta = {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.6", "dst_port": 25, "protocol": "SMTP"}
        result = analyze_group(timestamps, meta)

        assert result.event_count == 6
        assert result.mean_interval == 10.0
        assert result.classification == TemporalClassification.BEACON_CANDIDATE.value

    def test_case_6_empty_input(self):
        """Test Case 6: [] -> safe empty handling, no exception."""
        result = analyze_temporal_behavior([])
        assert result["groups"] == []
        assert result["summary"]["analyzed_groups"] == 0
        assert result["summary"]["beacon_candidates"] == 0

        single_res = analyze_group([], {"src_ip": "a", "dst_ip": "b"})
        assert single_res.event_count == 0
        assert single_res.classification == TemporalClassification.INSUFFICIENT_DATA.value

    def test_case_7_legitimate_regular_polling(self):
        """Test Case 7: Legitimate polling every 60s -> flagged as candidate with explainable note."""
        timestamps = [float(i * 60) for i in range(10)]
        meta = {"src_ip": "10.10.10.10", "dst_ip": "172.16.0.1", "dst_port": 443, "protocol": "HTTPS"}
        result = analyze_group(timestamps, meta)

        assert result.event_count == 10
        assert result.mean_interval == 60.0
        assert result.jitter_pct == 0.0
        assert result.classification == TemporalClassification.BEACON_CANDIDATE.value
        # Analyst note must state that timing alone does not establish malicious activity
        assert "Timing alone does not establish malicious activity" in result.analyst_note

    def test_case_8_temporal_behavior_grouping_and_enrichment(self):
        """Test session aggregation and enrichment map across multiple flows."""
        sessions = [
            # Group 1: 6 periodic sessions from 10.0.0.1 -> 1.1.1.1
            {"id": f"s1_{i}", "client_ip": "10.0.0.1", "server_ip": "1.1.1.1", "server_port": 25, "protocol": "SMTP", "first_seen": i * 30.0}
            for i in range(6)
        ] + [
            # Group 2: 2 sessions from 10.0.0.2 -> 2.2.2.2 (insufficient)
            {"id": "s2_0", "client_ip": "10.0.0.2", "server_ip": "2.2.2.2", "server_port": 587, "protocol": "SMTP", "first_seen": 100.0},
            {"id": "s2_1", "client_ip": "10.0.0.2", "server_ip": "2.2.2.2", "server_port": 587, "protocol": "SMTP", "first_seen": 115.0},
        ]

        result = analyze_temporal_behavior(sessions)

        assert result["summary"]["analyzed_groups"] == 2
        assert result["summary"]["beacon_candidates"] == 1
        assert result["summary"]["insufficient_data"] == 1

        # Check session enrichments
        enrichment_s1 = result["session_enrichments"]["s1_0"]
        assert enrichment_s1["temporal_classification"] == "BEACON_CANDIDATE"
        assert enrichment_s1["temporal_mean_interval"] == 30.0

        enrichment_s2 = result["session_enrichments"]["s2_0"]
        assert enrichment_s2["temporal_classification"] == "INSUFFICIENT_DATA"
