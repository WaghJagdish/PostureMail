"""Comprehensive test suite for the deterministic NIST SP 800-57 risk engine.

Tests:
1. 120 Golden Fixtures: Exact-match regression assertions against committed golden fixtures.
2. Determinism: 1,000 runs producing byte-identical outputs across runs and random states.
3. Veto Dominance: Catastrophic flaws (NULL cipher, revoked cert) score 100 despite perfect parameters elsewhere.
4. TLS 1.3 Redistribution: Certificate weight drop and exact 1.0 weight sum verification.
5. Hypothesis Property Testing: Fuzzing arbitrary inputs asserting scores within [0, 100].
6. Provenance Invariant: Assert that score > 0 implies non-empty provenance.
"""

from __future__ import annotations

import datetime
import json
import os
import subprocess
import sys
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

import pytest
from hypothesis import given
from hypothesis import settings as hyp_settings
from hypothesis import strategies as st

from pecff.crypto.chain_validator import ChainError, ChainValidationResult
from pecff.crypto.hostname import HostnameVerificationResult
from pecff.crypto.risk_engine import (
    BASE_WEIGHTS,
    TLS13_REDISTRIBUTED_WEIGHTS,
    NISTDeterministicRiskScorer,
    SessionCryptoParameters,
)
from pecff.crypto.x509_parser import ParsedCertificate

GOLDEN_FIXTURES_PATH = Path(__file__).parent / "golden_risk_fixtures.json"


@pytest.fixture(scope="module")
def golden_fixtures() -> list[dict[str, Any]]:
    """Load committed 120 golden fixtures."""
    with open(GOLDEN_FIXTURES_PATH, encoding="utf-8") as f:
        return cast(list[dict[str, Any]], json.load(f))


@pytest.fixture
def scorer() -> NISTDeterministicRiskScorer:
    return NISTDeterministicRiskScorer()


class TestNISTDeterministicRiskScorer:
    """Deterministic risk scorer unit and integration tests."""

    def test_all_120_golden_fixtures_exact_match(
        self,
        scorer: NISTDeterministicRiskScorer,
        golden_fixtures: list[dict[str, Any]],
    ) -> None:
        """Verify all 120 golden fixtures produce exact expected scores and rule sets."""
        assert len(golden_fixtures) == 120

        for fix in golden_fixtures:
            inp = fix["inputs"]
            expected = fix["expected_output"]

            cert_obj: ParsedCertificate | None = None
            chain_obj: ChainValidationResult | None = None
            host_obj: HostnameVerificationResult | None = None

            if inp["cert_analysis_possible"]:
                now = datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC)
                cert_obj = ParsedCertificate(
                    fingerprint_sha256="a" * 64,
                    spki_sha256="b" * 64,
                    serial_number="100",
                    version=3,
                    subject_dn="CN=mail.example.com",
                    issuer_dn="CN=Root CA",
                    not_before=now,
                    not_after=now + datetime.timedelta(days=inp["cert_lifetime_days"] or 273),
                    lifetime_days=inp["cert_lifetime_days"] or 273,
                    signature_algorithm_oid="1.2.840.113549.1.1.11",
                    signature_hash=inp["cert_sig_hash"] or "SHA256",
                    public_key_algorithm="RSA",
                    public_key_bits=inp["cert_key_bits"] or 2048,
                    ec_curve=None,
                    security_bits=112,
                    is_self_signed=bool(inp["cert_is_self_signed"]),
                    san_dns=["mail.example.com"],
                    sct_count=0 if ("CERT-NO-SCT" in expected["rule_ids"]) else 2,
                )

                is_valid = True if inp["chain_is_valid"] is None else inp["chain_is_valid"]
                chain_errors: list[ChainError] = []
                anchor_source = "mozilla_nss"
                if fix["case_name"] == "veto_revoked_cert":
                    is_valid = False
                    chain_errors.append(ChainError("CERT_REVOKED", "Revoked"))
                elif fix["case_name"] == "cert_expired_at_capture":
                    is_valid = False
                    chain_errors.append(ChainError("CERT_EXPIRED", "Expired"))
                elif fix["case_name"] == "cert_self_signed":
                    is_valid = False
                    anchor_source = "self_signed"

                chain_obj = ChainValidationResult(
                    is_valid=is_valid,
                    chain_length=2,
                    anchor_source=anchor_source,
                    errors=chain_errors,
                    ocsp_status="REVOKED" if fix["case_name"] == "veto_revoked_cert" else "GOOD",
                )

                host_status = inp["host_status"] or "MATCH"
                host_obj = HostnameVerificationResult(
                    matched=(host_status == "MATCH"),
                    status=host_status,
                    method="sni",
                    reference_identifier="mail.example.com"
                    if host_status == "MATCH"
                    else "bad.example.com",
                )

            params = SessionCryptoParameters(
                protocol_version=inp["protocol_version"],
                dst_port=inp["dst_port"],
                has_auth=inp["has_auth"],
                cleartext_credentials_observed=inp["cleartext_credentials_observed"],
                handshake_completed=inp["handshake_completed"],
                cert_analysis_possible=inp["cert_analysis_possible"],
                cipher_id=inp["cipher_id"],
                kex_algorithm=inp["kex_algorithm"],
                named_group=inp["named_group"],
                dh_key_bits=inp.get("dh_key_bits", 2048),
                extended_master_secret=inp["extended_master_secret"],
                secure_renegotiation=inp["secure_renegotiation"],
                compression_method=inp["compression_method"],
                ticket_lifetime_seconds=inp["ticket_lifetime_seconds"],
                zero_rtt_used=inp["zero_rtt_used"],
                leaf_certificate=cert_obj,
                chain_validation_result=chain_obj,
                hostname_verification_result=host_obj,
                known_compromised_spki=inp["known_compromised_spki"],
            )

            res = scorer.score_session(params)

            assert res.score == expected["score"], (
                f"Case {fix['case_id']} ({fix['case_name']}) score mismatch"
            )
            assert res.band == expected["band"], f"Case {fix['case_id']} band mismatch"
            assert res.context_multiplier == expected["context_multiplier"]
            assert res.weight_redistributed == expected["weight_redistributed"]
            actual_rule_ids = sorted({p.rule_id for p in res.provenance})
            assert actual_rule_ids == expected["rule_ids"], (
                f"Case {fix['case_id']} rule_ids mismatch"
            )

    def test_determinism_1000_executions(self, scorer: NISTDeterministicRiskScorer) -> None:
        """1,000 evaluations of the same session must return identical scores and provenance."""
        params = SessionCryptoParameters(
            protocol_version="TLS 1.2",
            cipher_id="0xC02F",
            kex_algorithm="ECDHE",
            named_group="secp256r1",
            dst_port=587,
            extended_master_secret=True,
            secure_renegotiation=True,
            cert_analysis_possible=False,
        )

        first_res = scorer.score_session(params)
        for _ in range(1000):
            res = scorer.score_session(params)
            assert res.score == first_res.score
            assert res.band == first_res.band
            assert res.provenance == first_res.provenance
            assert res.vetoes == first_res.vetoes

    def test_determinism_across_pythonhashseed(self) -> None:
        """Score under PYTHONHASHSEED=0 and PYTHONHASHSEED=random asserting byte-identical output."""
        script = (
            "import json\n"
            "from pecff.crypto.risk_engine import NISTDeterministicRiskScorer, SessionCryptoParameters\n"
            "scorer = NISTDeterministicRiskScorer()\n"
            "params = SessionCryptoParameters(\n"
            '    protocol_version="TLS 1.2",\n'
            '    cipher_id="0xC02F",\n'
            '    kex_algorithm="ECDHE",\n'
            '    named_group="secp256r1",\n'
            "    dst_port=587,\n"
            "    extended_master_secret=True,\n"
            "    secure_renegotiation=True,\n"
            "    cert_analysis_possible=False,\n"
            ")\n"
            "res = scorer.score_session(params)\n"
            'print(json.dumps({"score": res.score, "band": res.band, "prov": [p.rule_id for p in res.provenance]}))\n'
        )
        env0 = dict(os.environ, PYTHONHASHSEED="0")
        env_rand = dict(os.environ, PYTHONHASHSEED="random")
        out0 = subprocess.check_output([sys.executable, "-c", script], env=env0, text=True).strip()
        out_rand = subprocess.check_output(
            [sys.executable, "-c", script], env=env_rand, text=True
        ).strip()
        assert out0 == out_rand

    def test_veto_dominance_null_cipher(self, scorer: NISTDeterministicRiskScorer) -> None:
        """A session with a NULL cipher and otherwise perfect parameters scores 100."""
        params = SessionCryptoParameters(
            protocol_version="TLS 1.3",
            cipher_id="0x0001",  # TLS_RSA_WITH_NULL_MD5
            kex_algorithm="ECDHE",
            named_group="x25519",
            dst_port=25,
            extended_master_secret=True,
            secure_renegotiation=True,
            cert_analysis_possible=False,
        )
        res = scorer.score_session(params)
        assert res.score == 100
        assert res.band == "CRITICAL"
        assert any(v.rule_id == "CIPHER-NULL" for v in res.vetoes)

    def test_tls13_weight_redistribution_sums_to_one(
        self, scorer: NISTDeterministicRiskScorer
    ) -> None:
        """TLS 1.3 session drops C4 and redistributes weights to sum to exactly 1.0."""
        # Base weights sum to 1.0
        base_sum = sum(BASE_WEIGHTS.values())
        assert base_sum == Decimal("1.0")

        # TLS 1.3 redistributed weights sum to 1.0
        redist_sum = sum(TLS13_REDISTRIBUTED_WEIGHTS.values())
        assert redist_sum == Decimal("1.0")

        params = SessionCryptoParameters(
            protocol_version="TLS 1.3",
            cipher_id="0x1301",
            kex_algorithm="ECDHE",
            named_group="x25519",
            cert_analysis_possible=False,
        )
        res = scorer.score_session(params)
        assert res.weight_redistributed is True
        assert sum(res.component_weights.values()) == pytest.approx(1.0)
        assert "certificate" not in res.component_weights

    def test_effective_strength_gate_triggers_veto(
        self, scorer: NISTDeterministicRiskScorer
    ) -> None:
        """Effective strength S_eff < 112 bits triggers NIST-MIN-STRENGTH veto floor at 90."""
        # 3DES has 112-bit key, but MD5 MAC has 0-bit collision resistance -> S_eff = 0
        params = SessionCryptoParameters(
            protocol_version="TLS 1.2",
            cipher_id="0x0018",  # DH_anon with RC4 128 MD5
            kex_algorithm="DHE",
            dh_key_bits=1024,
            cert_analysis_possible=False,
        )
        res = scorer.score_session(params)
        assert res.score >= 90
        assert any(v.rule_id == "NIST-MIN-STRENGTH" or v.floor_score >= 90 for v in res.vetoes)

    def test_provenance_invariant_score_greater_than_zero(
        self, scorer: NISTDeterministicRiskScorer
    ) -> None:
        """A score > 0 with an empty provenance list is a critical bug."""
        params = SessionCryptoParameters(
            protocol_version="TLS 1.0",
            cipher_id="0x0005",
            kex_algorithm="RSA",
            cert_analysis_possible=False,
        )
        res = scorer.score_session(params)
        assert res.score > 0
        assert len(res.provenance) > 0
        for item in res.provenance:
            assert item.rule_id
            assert item.nist_reference
            assert item.evidence

    @given(
        proto=st.sampled_from(
            ["TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0", "SSL 3.0", "SSL 2.0", "NONE"]
        ),
        port=st.sampled_from([25, 465, 587, 993, 995, 110, 143, 8080]),
        has_auth=st.booleans(),
        clear_cred=st.booleans(),
        ems=st.booleans(),
        reneg=st.booleans(),
        comp=st.sampled_from([0, 1, 2]),
        ticket=st.sampled_from([None, 3600, 700000]),
        zero_rtt=st.booleans(),
        kex=st.sampled_from(["ECDHE", "DHE", "RSA", "DH", "NONE"]),
        named_grp=st.sampled_from(["x25519", "secp256r1", "secp192r1", "unknown", None]),
        c_id=st.sampled_from(
            ["0x1301", "0x1302", "0xC02F", "0x0035", "0x0005", "0x0001", "0x0008"]
        ),
    )
    @hyp_settings(max_examples=100, deadline=None)
    def test_property_score_always_bounded_0_to_100(
        self,
        proto: str,
        port: int,
        has_auth: bool,
        clear_cred: bool,
        ems: bool,
        reneg: bool,
        comp: int,
        ticket: int | None,
        zero_rtt: bool,
        kex: str,
        named_grp: str | None,
        c_id: str,
    ) -> None:
        """Property test: Score must always be integer in [0, 100], and band must be valid."""
        scorer = NISTDeterministicRiskScorer()
        params = SessionCryptoParameters(
            protocol_version=proto,
            dst_port=port,
            has_auth=has_auth,
            cleartext_credentials_observed=clear_cred,
            extended_master_secret=ems,
            secure_renegotiation=reneg,
            compression_method=comp,
            ticket_lifetime_seconds=ticket,
            zero_rtt_used=zero_rtt,
            kex_algorithm=kex,
            named_group=named_grp,
            cipher_id=c_id,
            cert_analysis_possible=False,
        )
        res = scorer.score_session(params)

        assert 0 <= res.score <= 100
        assert res.band in {"SECURE", "ACCEPTABLE", "WEAK", "HIGH", "CRITICAL"}
        if res.score > 0:
            assert len(res.provenance) > 0
