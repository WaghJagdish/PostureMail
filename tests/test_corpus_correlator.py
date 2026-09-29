"""Tests for the corpus-level beaconing and timing correlation engine."""

from __future__ import annotations

import pytest


def _make_session(
    sid: str,
    src: str,
    dst: str,
    port: int,
    first_seen: float,
    starttls_state: str = "S4_TLS_READY",
    ja3: str | None = None,
    banner: str | None = None,
) -> dict:
    return {
        "id": sid,
        "client_ip": src,
        "server_ip": dst,
        "server_port": port,
        "first_seen": first_seen,
        "starttls_state": starttls_state,
        "ja3": ja3,
        "server_banner": banner,
    }


class TestBeaconingDetector:
    """CB1 - periodic inter-arrival detection."""

    def _run(self, sessions):
        from pecff.engine.corpus_correlator import _detect_beaconing
        return _detect_beaconing(sessions)

    def test_perfect_beacon_detected(self):
        sessions = [
            _make_session(f"s{i}", "10.0.0.1", "10.0.0.2", 25, float(i * 60))
            for i in range(8)
        ]
        groups, periodic_ids = self._run(sessions)
        assert len(groups) == 1
        assert groups[0].coefficient_of_variation == 0.0
        assert len(periodic_ids) == 8

    def test_jittered_beacon_detected_below_cov_threshold(self):
        import random
        rng = random.Random(42)
        base_period = 300.0
        t = 0.0
        sessions = []
        for i in range(8):
            t += base_period + rng.uniform(-5, 5)
            sessions.append(_make_session(f"s{i}", "10.0.0.1", "10.0.0.2", 587, t))
        groups, periodic_ids = self._run(sessions)
        assert len(groups) == 1
        assert groups[0].coefficient_of_variation < 0.30

    def test_random_timing_not_flagged(self):
        import random
        rng = random.Random(99)
        t = 0.0
        sessions = []
        for i in range(12):
            t += rng.uniform(10, 600)
            sessions.append(_make_session(f"s{i}", "192.168.1.1", "10.0.0.3", 443, t))
        groups, periodic_ids = self._run(sessions)
        assert len(groups) == 0

    def test_fewer_than_min_sessions_skipped(self):
        sessions = [
            _make_session(f"s{i}", "10.0.0.1", "10.0.0.2", 25, float(i * 60))
            for i in range(4)
        ]
        groups, periodic_ids = self._run(sessions)
        assert len(groups) == 0

    def test_multiple_distinct_beacon_groups(self):
        sessions_a = [
            _make_session(f"a{i}", "10.0.0.1", "10.0.0.2", 25, float(i * 60))
            for i in range(6)
        ]
        sessions_b = [
            _make_session(f"b{i}", "10.0.0.3", "10.0.0.4", 587, float(i * 120))
            for i in range(6)
        ]
        groups, periodic_ids = self._run(sessions_a + sessions_b)
        assert len(groups) == 2
        assert len(periodic_ids) == 12

    def test_periodic_ids_are_session_id_strings(self):
        sessions = [
            _make_session(f"sess-{i}", "1.2.3.4", "5.6.7.8", 25, float(i * 60))
            for i in range(7)
        ]
        _, periodic_ids = self._run(sessions)
        expected = {f"sess-{i}" for i in range(7)}
        assert periodic_ids == expected

    def test_beacon_group_fields(self):
        sessions = [
            _make_session(f"s{i}", "172.16.0.1", "172.16.0.2", 993, float(i * 30))
            for i in range(8)
        ]
        groups, _ = self._run(sessions)
        bg = groups[0]
        assert bg.src_ip == "172.16.0.1"
        assert bg.dst_ip == "172.16.0.2"
        assert bg.dst_port == 993
        assert bg.period_estimate_s == pytest.approx(30.0, rel=0.01)

    def test_zero_delta_guard(self):
        sessions = [
            _make_session(f"s{i}", "10.0.0.1", "10.0.0.2", 25, 1000.0)
            for i in range(8)
        ]
        groups, _ = self._run(sessions)
        assert len(groups) == 0


class TestBannerMutationDetector:
    """CB2 - D8 EHLO banner mutation detection."""

    def _run(self, sessions):
        from pecff.engine.corpus_correlator import _detect_banner_mutation
        return _detect_banner_mutation(sessions)

    def test_mutation_detected_above_threshold(self, monkeypatch):
        from pecff.config import settings
        monkeypatch.setattr(settings, "banner_mutation_threshold", 5)
        sessions = [
            _make_session("a", "1.1.1.1", "2.2.2.2", 25, 0.0, banner="ESMTP Postfix v1.0.0"),
            _make_session("b", "1.1.1.2", "2.2.2.2", 25, 1.0, banner="ESMTP Exim v4.96-MALICIOUS"),
        ]
        findings = self._run(sessions)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "D8_BANNER_MUTATION"
        assert findings[0]["evidence"]["levenshtein_distance"] >= 5

    def test_identical_banners_not_flagged(self, monkeypatch):
        from pecff.config import settings
        monkeypatch.setattr(settings, "banner_mutation_threshold", 5)
        sessions = [
            _make_session("a", "1.1.1.1", "2.2.2.2", 25, 0.0, banner="ESMTP Postfix"),
            _make_session("b", "1.1.1.2", "2.2.2.2", 25, 1.0, banner="ESMTP Postfix"),
        ]
        findings = self._run(sessions)
        assert len(findings) == 0

    def test_no_banner_field_skipped(self):
        sessions = [
            _make_session("a", "1.1.1.1", "2.2.2.2", 25, 0.0),
            _make_session("b", "1.1.1.2", "2.2.2.2", 25, 1.0),
        ]
        findings = self._run(sessions)
        assert len(findings) == 0


class TestCorpusCapabilityStripDetector:
    """CB3 - D1 corpus-level STARTTLS strip detection."""

    def _run(self, sessions):
        from pecff.engine.corpus_correlator import _detect_corpus_capability_strip
        return _detect_corpus_capability_strip(sessions)

    def test_strip_detected_when_asymmetric(self):
        sessions = [
            _make_session("clean1", "1.1.1.1", "2.2.2.2", 25, 0.0, starttls_state="S4_TLS_READY"),
            _make_session("clean2", "1.1.1.2", "2.2.2.2", 25, 1.0, starttls_state="S4_TLS_READY"),
            _make_session("absent1", "1.1.1.3", "2.2.2.2", 25, 2.0, starttls_state="S0_TCP_EST"),
        ]
        findings = self._run(sessions)
        assert len(findings) == 1
        f = findings[0]
        assert f["rule_id"] == "D1_CORPUS_CAPABILITY_STRIP"
        assert f["severity"] == "CRITICAL"
        assert f["evidence"]["stripped_count"] == 1
        assert f["evidence"]["clean_count"] == 2

    def test_all_clean_no_finding(self):
        sessions = [
            _make_session(f"s{i}", "1.1.1.1", "2.2.2.2", 25, float(i), starttls_state="S4_TLS_READY")
            for i in range(5)
        ]
        assert self._run(sessions) == []

    def test_all_absent_no_finding(self):
        sessions = [
            _make_session(f"s{i}", "1.1.1.1", "2.2.2.2", 25, float(i), starttls_state="S0_TCP_EST")
            for i in range(5)
        ]
        assert self._run(sessions) == []

    def test_different_ports_are_independent(self):
        sessions = [
            _make_session("a", "1.1.1.1", "2.2.2.2", 25, 0.0, starttls_state="S4_TLS_READY"),
            _make_session("b", "1.1.1.2", "2.2.2.2", 25, 1.0, starttls_state="S0_TCP_EST"),
            _make_session("c", "1.1.1.3", "2.2.2.2", 587, 2.0, starttls_state="S4_TLS_READY"),
        ]
        findings = self._run(sessions)
        assert len(findings) == 1
        assert findings[0]["evidence"]["server_port"] == 25


class TestJA3RarityDetector:
    """CB4 - singleton JA3 fingerprint detection."""

    def _run(self, sessions):
        from pecff.engine.corpus_correlator import _detect_ja3_rarity
        return _detect_ja3_rarity(sessions)

    def test_singleton_ja3_flagged(self):
        dominant = "aabbccdd" * 4
        rare = "deadbeef" * 4
        sessions = (
            [_make_session(f"d{i}", "1.1.1.1", "2.2.2.2", 25, float(i), ja3=dominant)
             for i in range(10)]
            + [_make_session("rare1", "1.1.1.11", "2.2.2.2", 25, 99.0, ja3=rare)]
        )
        findings = self._run(sessions)
        assert any(f["evidence"]["ja3"] == rare for f in findings)

    def test_common_ja3_not_flagged(self):
        common = "aabbccdd" * 4
        sessions = [
            _make_session(f"s{i}", "1.1.1.1", "2.2.2.2", 25, float(i), ja3=common)
            for i in range(15)
        ]
        assert self._run(sessions) == []

    def test_fewer_than_10_sessions_returns_empty(self):
        sessions = [
            _make_session(f"s{i}", "1.1.1.1", "2.2.2.2", 25, float(i), ja3="abc123")
            for i in range(9)
        ]
        assert self._run(sessions) == []

    def test_no_ja3_field_silently_skipped(self):
        sessions = [
            _make_session(f"s{i}", "1.1.1.1", "2.2.2.2", 25, float(i))
            for i in range(15)
        ]
        assert self._run(sessions) == []


class TestAuxiliaryStatComputation:
    """Per-session src_count and distinct SNI statistics."""

    def _run(self, sessions):
        from pecff.engine.corpus_correlator import _compute_src_statistics
        return _compute_src_statistics(sessions)

    def test_src_count_correct(self):
        sessions = [
            _make_session("a", "10.0.0.1", "10.0.0.2", 25, 0.0),
            _make_session("b", "10.0.0.1", "10.0.0.2", 25, 1.0),
            _make_session("c", "10.0.0.3", "10.0.0.2", 25, 2.0),
        ]
        counts, _ = self._run(sessions)
        assert counts["10.0.0.1"] == 2
        assert counts["10.0.0.3"] == 1

    def test_distinct_sni_per_src(self):
        sessions = [
            {**_make_session("a", "10.0.0.1", "2.2.2.2", 25, 0.0), "sni": "mail.example.com"},
            {**_make_session("b", "10.0.0.1", "2.2.2.2", 25, 1.0), "sni": "smtp.example.org"},
            {**_make_session("c", "10.0.0.1", "2.2.2.2", 25, 2.0), "sni": "mail.example.com"},
        ]
        _, distinct = self._run(sessions)
        assert distinct["10.0.0.1"] == 2


class TestRunCorpusCorrelation:
    """Integration tests for the public run_corpus_correlation entry point."""

    def test_is_periodic_stamped_on_beacon_sessions(self):
        from pecff.engine.corpus_correlator import run_corpus_correlation
        sessions = [
            _make_session(f"s{i}", "10.0.0.1", "10.0.0.2", 25, float(i * 60))
            for i in range(8)
        ]
        result = run_corpus_correlation(sessions, [])
        assert all(result.session_is_periodic[f"s{i}"] for i in range(8))

    def test_non_beacon_sessions_not_marked_periodic(self):
        from pecff.engine.corpus_correlator import run_corpus_correlation
        import random
        rng = random.Random(1)
        t = 0.0
        sessions = []
        for i in range(10):
            t += rng.uniform(10, 600)
            sessions.append(_make_session(f"r{i}", "192.168.1.1", "10.0.0.3", 443, t))
        result = run_corpus_correlation(sessions, [])
        assert all(not result.session_is_periodic[f"r{i}"] for i in range(10))

    def test_cb1_finding_emitted_for_beacon_group(self):
        from pecff.engine.corpus_correlator import run_corpus_correlation
        sessions = [
            _make_session(f"s{i}", "10.0.0.1", "10.0.0.2", 25, float(i * 60))
            for i in range(8)
        ]
        result = run_corpus_correlation(sessions, [])
        beacon_findings = [
            f for f in result.new_findings
            if f["rule_id"] == "CB1_BEACONING_PERIODIC_SESSIONS"
        ]
        assert len(beacon_findings) == 1
        assert beacon_findings[0]["severity"] == "HIGH"

    def test_d1_finding_emitted_for_starttls_strip(self):
        from pecff.engine.corpus_correlator import run_corpus_correlation
        sessions = [
            _make_session("clean", "1.1.1.1", "2.2.2.2", 25, 0.0, starttls_state="S4_TLS_READY"),
            _make_session("absent", "1.1.1.2", "2.2.2.2", 25, 1.0, starttls_state="S0_TCP_EST"),
        ]
        result = run_corpus_correlation(sessions, [])
        strip_findings = [
            f for f in result.new_findings
            if f["rule_id"] == "D1_CORPUS_CAPABILITY_STRIP"
        ]
        assert len(strip_findings) == 1

    def test_src_count_populated_for_all_sessions(self):
        from pecff.engine.corpus_correlator import run_corpus_correlation
        sessions = [
            _make_session(f"s{i}", "10.0.0.1", "10.0.0.2", 25, float(i * 60))
            for i in range(6)
        ]
        result = run_corpus_correlation(sessions, [])
        for i in range(6):
            assert result.session_src_count[f"s{i}"] == 6

    def test_empty_sessions_does_not_raise(self):
        from pecff.engine.corpus_correlator import run_corpus_correlation
        result = run_corpus_correlation([], [])
        assert result.beacon_groups == []
        assert result.new_findings == []
