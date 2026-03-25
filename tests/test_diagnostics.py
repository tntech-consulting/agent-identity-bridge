"""Tests for Sprint 12 — Diagnostics & Federation Trust Scoring."""

import time
import pytest
from aib.diagnostics import (
    DiagnosticRunner, DiagnosticResult, DiagnosticLevel, Component,
    diagnose_error,
    FederationTrustScorer, TrustScore, TrustMetrics,
)
from aib.security import URLValidationError
from aib.lifecycle import CapabilityEscalationError
from aib.renewal import PassportRevokedError
from aib.webhooks import WebhookDeniedError


# ═══════════════════════════════════════════════════════════════════
# 1. DIAGNOSTIC RUNNER
# ═══════════════════════════════════════════════════════════════════

class TestDiagnosticRunner:

    def test_register_and_check_ok(self):
        diag = DiagnosticRunner()
        diag.register("passport", lambda: True, description="Passport store OK")
        result = diag.check_one("passport")
        assert result.level == DiagnosticLevel.OK

    def test_check_returns_false(self):
        diag = DiagnosticRunner()
        diag.register("gateway", lambda: False, suggestion_on_fail="Check gateway config")
        result = diag.check_one("gateway")
        assert result.level == DiagnosticLevel.ERROR
        assert "gateway" in result.message

    def test_check_exception(self):
        diag = DiagnosticRunner()
        diag.register("translator", lambda: 1/0, suggestion_on_fail="Fix division")
        result = diag.check_one("translator")
        assert result.level == DiagnosticLevel.ERROR
        assert "ZeroDivisionError" in result.message
        assert result.suggestion == "Fix division"

    def test_check_unregistered(self):
        diag = DiagnosticRunner()
        result = diag.check_one("unknown")
        assert result.level == DiagnosticLevel.WARN

    def test_run_all(self):
        diag = DiagnosticRunner()
        diag.register("a", lambda: True)
        diag.register("b", lambda: True)
        diag.register("c", lambda: False)
        results = diag.run_all()
        assert len(results) == 3

    def test_summary_healthy(self):
        diag = DiagnosticRunner()
        diag.register("a", lambda: True)
        diag.register("b", lambda: True)
        s = diag.summary()
        assert s["status"] == "healthy"
        assert s["ok"] == 2
        assert s["error"] == 0

    def test_summary_degraded(self):
        diag = DiagnosticRunner()
        diag.register("a", lambda: True)
        diag.register("b", lambda: False)
        s = diag.summary()
        assert s["status"] == "degraded"
        assert len(s["errors"]) == 1

    def test_latency_measured(self):
        diag = DiagnosticRunner()
        diag.register("slow", lambda: time.sleep(0.05) or True)
        result = diag.check_one("slow")
        assert result.latency_ms >= 40

    def test_registered_components(self):
        diag = DiagnosticRunner()
        diag.register("a", lambda: True)
        diag.register("b", lambda: True)
        assert set(diag.registered_components) == {"a", "b"}


# ═══════════════════════════════════════════════════════════════════
# 2. ERROR DIAGNOSIS
# ═══════════════════════════════════════════════════════════════════

class TestDiagnoseError:

    def test_url_validation_error(self):
        err = URLValidationError("Bad URL: ftp://evil.com")
        result = diagnose_error(err)
        assert result.component == "gateway"
        assert "GATEWAY" in result.message
        assert "SSRF" in result.suggestion

    def test_capability_escalation(self):
        err = CapabilityEscalationError("admin not in parent")
        result = diagnose_error(err)
        assert result.component == "lifecycle"

    def test_passport_revoked(self):
        err = PassportRevokedError("Passport p1 is revoked")
        result = diagnose_error(err)
        assert result.component == "passport"
        assert "revoked" in result.suggestion.lower()

    def test_webhook_denied(self):
        err = WebhookDeniedError("Blocked by policy", webhook_id="wh_123")
        result = diagnose_error(err)
        assert result.component == "webhooks"

    def test_unknown_error(self):
        err = RuntimeError("Something unexpected")
        result = diagnose_error(err)
        assert result.component == "unknown"
        assert result.level == DiagnosticLevel.ERROR

    def test_result_has_timestamp(self):
        err = ValueError("test")
        result = diagnose_error(err)
        assert result.timestamp != ""

    def test_result_to_dict(self):
        err = URLValidationError("test")
        result = diagnose_error(err)
        d = result.to_dict()
        assert "component" in d
        assert "suggestion" in d
        assert "message" in d


# ═══════════════════════════════════════════════════════════════════
# 3. TRUST SCORING
# ═══════════════════════════════════════════════════════════════════

class TestTrustScoring:

    @pytest.fixture
    def scorer(self):
        return FederationTrustScorer()

    def test_unknown_issuer_score_zero(self, scorer):
        score = scorer.compute_score("urn:aib:org:unknown")
        assert score.score == 0
        assert score.grade == "F"

    def test_perfect_partner(self, scorer):
        issuer = "urn:aib:org:perfect"
        # Simulate 30+ days of perfect transactions
        scorer._metrics[issuer] = TrustMetrics(
            issuer=issuer,
            total_transactions=1000,
            successful_transactions=1000,
            failed_transactions=0,
            revocations_received=0,
            avg_response_ms=25.0,
            first_seen=(datetime.now(timezone.utc) - timedelta(days=90)).isoformat(),
            jwks_fetch_failures=0,
        )
        score = scorer.compute_score(issuer)
        assert score.score >= 80
        assert score.grade == "A"

    def test_terrible_partner(self, scorer):
        issuer = "urn:aib:org:terrible"
        scorer._metrics[issuer] = TrustMetrics(
            issuer=issuer,
            total_transactions=100,
            successful_transactions=20,
            failed_transactions=80,
            revocations_received=50,
            avg_response_ms=5000.0,
            first_seen=datetime.now(timezone.utc).isoformat(),
            jwks_fetch_failures=10,
        )
        score = scorer.compute_score(issuer)
        assert score.score < 30
        assert score.grade in ("D", "F")

    def test_record_transaction(self, scorer):
        scorer.record_transaction("org-a", success=True, latency_ms=50)
        scorer.record_transaction("org-a", success=True, latency_ms=60)
        scorer.record_transaction("org-a", success=False, latency_ms=5000)
        m = scorer.get_metrics("org-a")
        assert m["total_transactions"] == 3
        assert m["successful_transactions"] == 2

    def test_record_revocation(self, scorer):
        scorer.record_revocation("org-a")
        scorer.record_revocation("org-a")
        m = scorer.get_metrics("org-a")
        assert m["revocations_received"] == 2

    def test_record_jwks_failure(self, scorer):
        scorer.record_jwks_failure("org-a")
        m = scorer.get_metrics("org-a")
        assert m["jwks_fetch_failures"] == 1

    def test_score_factors(self, scorer):
        scorer.record_transaction("org-a", True, 50)
        score = scorer.compute_score("org-a")
        assert "success_rate" in score.factors
        assert "age" in score.factors
        assert "revocation_rate" in score.factors
        assert "response_time" in score.factors
        assert "jwks_reliability" in score.factors

    def test_score_capped_0_100(self, scorer):
        scorer.record_transaction("org-a", True, 10)
        score = scorer.compute_score("org-a")
        assert 0 <= score.score <= 100

    def test_grade_mapping(self, scorer):
        assert scorer._grade(90) == "A"
        assert scorer._grade(70) == "B"
        assert scorer._grade(50) == "C"
        assert scorer._grade(30) == "D"
        assert scorer._grade(10) == "F"

    def test_should_trust_with_threshold(self):
        scorer = FederationTrustScorer(min_score_to_trust=50)
        # New issuer with no data = score 0
        trusted, score = scorer.should_trust("urn:aib:org:new")
        assert trusted is False

    def test_should_trust_good_partner(self):
        scorer = FederationTrustScorer(min_score_to_trust=50)
        scorer._metrics["org-good"] = TrustMetrics(
            issuer="org-good",
            total_transactions=500,
            successful_transactions=495,
            avg_response_ms=30,
            first_seen=(datetime.now(timezone.utc) - timedelta(days=60)).isoformat(),
        )
        trusted, score = scorer.should_trust("org-good")
        assert trusted is True

    def test_list_scores(self, scorer):
        scorer.record_transaction("org-a", True, 50)
        scorer.record_transaction("org-b", True, 100)
        scores = scorer.list_scores()
        assert len(scores) == 2

    def test_list_by_grade(self, scorer):
        scorer._metrics["org-a"] = TrustMetrics(
            issuer="org-a", total_transactions=100,
            successful_transactions=100, avg_response_ms=20,
            first_seen=(datetime.now(timezone.utc) - timedelta(days=90)).isoformat(),
        )
        a_list = scorer.list_by_grade("A")
        assert len(a_list) >= 1

    def test_issuer_count(self, scorer):
        scorer.record_transaction("a", True, 10)
        scorer.record_transaction("b", True, 20)
        assert scorer.issuer_count == 2

    def test_crl_size(self, scorer):
        scorer.set_crl_size("org-a", 42)
        m = scorer.get_metrics("org-a")
        assert m["crl_size"] == 42


# ═══════════════════════════════════════════════════════════════════
# 4. END-TO-END
# ═══════════════════════════════════════════════════════════════════

class TestEndToEnd:

    def test_diagnostics_plus_trust(self):
        """Full scenario: check components then evaluate federation trust."""
        # Diagnostics
        diag = DiagnosticRunner()
        diag.register("passport", lambda: True)
        diag.register("translator", lambda: True)
        diag.register("federation", lambda: True)
        s = diag.summary()
        assert s["status"] == "healthy"

        # Trust scoring
        scorer = FederationTrustScorer(min_score_to_trust=40)
        for _ in range(50):
            scorer.record_transaction("urn:aib:org:partner", True, 45)
        scorer.record_transaction("urn:aib:org:partner", False, 3000)

        trusted, score = scorer.should_trust("urn:aib:org:partner")
        assert trusted is True
        assert score.grade in ("A", "B", "C")
        assert score.factors["success_rate"]["value"] > 0.9

    def test_error_diagnosis_in_context(self):
        """Simulate error in translation → diagnose → report."""
        try:
            raise URLValidationError("Blocked: resolves to 10.0.0.1")
        except Exception as e:
            result = diagnose_error(e)
            assert result.component == "gateway"
            assert result.level == "error"
            assert "10.0.0.1" in result.detail


from datetime import datetime, timezone, timedelta
