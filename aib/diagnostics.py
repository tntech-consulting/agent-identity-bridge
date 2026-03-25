"""
AIB — Sprint 12: Diagnostics & Federation Trust Scoring.

Two features:

1. Component diagnostics — when something fails, tell the user WHICH
   AIB component is responsible, not just a Python traceback.
2. Federation trust scoring — score 0-100 per federated org based on
   transaction history, revocation rate, response time, and age.
"""

import time
import threading
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, Any, Callable
from enum import Enum


# ═══════════════════════════════════════════════════════════════════
# 1. COMPONENT DIAGNOSTICS
# ═══════════════════════════════════════════════════════════════════

class Component(str, Enum):
    PASSPORT = "passport"
    TRANSLATOR = "translator"
    GATEWAY = "gateway"
    LIFECYCLE = "lifecycle"
    RECEIPTS = "receipts"
    MERKLE = "merkle"
    OIDC = "oidc"
    GDPR = "gdpr"
    RATE_LIMITER = "rate_limiter"
    SCHEMA_VALIDATOR = "schema_validator"
    FEDERATION = "federation"
    WEBHOOKS = "webhooks"
    RENEWAL = "renewal"
    CRYPTO = "crypto"
    DISCOVERY = "discovery"
    CIRCUIT_BREAKER = "circuit_breaker"


class DiagnosticLevel(str, Enum):
    OK = "ok"
    WARN = "warn"
    ERROR = "error"
    FATAL = "fatal"


@dataclass
class DiagnosticResult:
    """Result of a single component check."""
    component: str
    level: str
    message: str
    latency_ms: float = 0.0
    detail: str = ""
    suggestion: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "component": self.component,
            "level": self.level,
            "message": self.message,
            "latency_ms": self.latency_ms,
            "detail": self.detail,
            "suggestion": self.suggestion,
            "timestamp": self.timestamp,
        }


class DiagnosticRunner:
    """
    Runs health checks on all AIB components and reports which
    brick is broken when something fails.

    Usage:
        diag = DiagnosticRunner()

        # Register component checks
        diag.register("passport", lambda: passport_svc.list_passports() is not None)
        diag.register("translator", lambda: translator.translate(...) is not None)

        # Run all checks
        results = diag.run_all()
        for r in results:
            print(f"{r.component}: {r.level} — {r.message}")

        # Quick status
        print(diag.summary())  # "12/14 OK, 1 WARN, 1 ERROR"
    """

    def __init__(self):
        self._checks: dict[str, dict] = {}

    def register(
        self,
        component: str,
        check_fn: Callable[[], bool],
        description: str = "",
        suggestion_on_fail: str = "",
    ):
        """Register a health check for a component."""
        self._checks[component] = {
            "fn": check_fn,
            "description": description,
            "suggestion": suggestion_on_fail,
        }

    def check_one(self, component: str) -> DiagnosticResult:
        """Run a single component check."""
        check = self._checks.get(component)
        if not check:
            return DiagnosticResult(
                component=component,
                level=DiagnosticLevel.WARN,
                message=f"No check registered for {component}",
                timestamp=datetime.now(timezone.utc).isoformat(),
            )

        start = time.time()
        try:
            result = check["fn"]()
            latency = (time.time() - start) * 1000

            if result:
                return DiagnosticResult(
                    component=component,
                    level=DiagnosticLevel.OK,
                    message=check.get("description", f"{component} is healthy"),
                    latency_ms=round(latency, 2),
                    timestamp=datetime.now(timezone.utc).isoformat(),
                )
            else:
                return DiagnosticResult(
                    component=component,
                    level=DiagnosticLevel.ERROR,
                    message=f"{component} check returned False",
                    latency_ms=round(latency, 2),
                    suggestion=check.get("suggestion", ""),
                    timestamp=datetime.now(timezone.utc).isoformat(),
                )
        except Exception as e:
            latency = (time.time() - start) * 1000
            return DiagnosticResult(
                component=component,
                level=DiagnosticLevel.ERROR,
                message=f"{component} check failed: {type(e).__name__}",
                latency_ms=round(latency, 2),
                detail=str(e),
                suggestion=check.get("suggestion", f"Check {component} configuration"),
                timestamp=datetime.now(timezone.utc).isoformat(),
            )

    def run_all(self) -> list[DiagnosticResult]:
        """Run all registered checks."""
        return [self.check_one(comp) for comp in self._checks]

    def summary(self) -> dict:
        """Run all checks and return a summary."""
        results = self.run_all()
        by_level = {}
        for r in results:
            by_level[r.level] = by_level.get(r.level, 0) + 1

        total = len(results)
        ok = by_level.get(DiagnosticLevel.OK, 0)
        errors = [r for r in results if r.level in (DiagnosticLevel.ERROR, DiagnosticLevel.FATAL)]

        return {
            "status": "healthy" if ok == total else "degraded" if errors else "warning",
            "total_components": total,
            "ok": ok,
            "warn": by_level.get(DiagnosticLevel.WARN, 0),
            "error": by_level.get(DiagnosticLevel.ERROR, 0),
            "fatal": by_level.get(DiagnosticLevel.FATAL, 0),
            "errors": [e.to_dict() for e in errors],
            "all_results": [r.to_dict() for r in results],
        }

    @property
    def registered_components(self) -> list[str]:
        return list(self._checks.keys())


def diagnose_error(error: Exception, context: dict = None) -> DiagnosticResult:
    """
    Given an exception, identify which AIB component is responsible.

    Maps exception types to components for clear error reporting.
    """
    context = context or {}
    error_type = type(error).__name__
    error_module = type(error).__module__ or ""

    # Map exception types to components
    component_map = {
        "URLValidationError": ("gateway", "Check target URL format and SSRF rules"),
        "InputValidationError": ("gateway", "Validate input data format"),
        "SchemaValidationError": ("schema_validator", "Check document against JSON Schema"),
        "DNSRebindingError": ("gateway", "Target host DNS is inconsistent"),
        "AudienceError": ("passport", "Passport audience doesn't match this service"),
        "MaxChildrenExceededError": ("lifecycle", "Reduce delegation count or increase limit"),
        "DelegationError": ("lifecycle", "Check delegation rules and parent passport"),
        "CapabilityEscalationError": ("lifecycle", "Cannot add capabilities beyond parent scope"),
        "TierViolationError": ("lifecycle", "Check tier delegation rules"),
        "MaxDepthExceededError": ("lifecycle", "Delegation chain too deep"),
        "MigrationError": ("migration", "Check protocol migration parameters"),
        "ProtocolAlreadyExistsError": ("migration", "Protocol already added to this passport"),
        "ProtocolNotFoundError": ("migration", "Protocol not found in passport bindings"),
        "RenewalError": ("renewal", "Check renewal parameters"),
        "PassportNotFoundError": ("passport", "Verify passport_id exists"),
        "PassportRevokedError": ("passport", "Passport was revoked — create a new one"),
        "PIIViolationError": ("gdpr", "Input contains PII that must be encrypted"),
        "ShredError": ("gdpr", "Crypto-shredding failed — check key store"),
        "SignatureTimeoutError": ("crypto", "Multi-sig request expired — start a new one"),
        "CircuitBreakerError": ("circuit_breaker", "Target service is down — circuit open"),
        "WebhookDeniedError": ("webhooks", "External policy check denied the request"),
        "OutputValidationError": ("translator", "Translated output failed validation"),
        "IssuerValidationError": ("federation", "Passport issuer not trusted"),
        "SignedDocumentError": ("federation", "Discovery document signature invalid"),
        "OIDCDevGuardError": ("oidc", "OIDC dev mode not allowed in production"),
    }

    component = "unknown"
    suggestion = f"Check error: {error_type}"

    if error_type in component_map:
        component, suggestion = component_map[error_type]
    elif "translator" in error_module:
        component = "translator"
        suggestion = "Check source format and translation path"
    elif "passport" in error_module:
        component = "passport"
    elif "gateway" in error_module:
        component = "gateway"
    elif "lifecycle" in error_module:
        component = "lifecycle"

    return DiagnosticResult(
        component=component,
        level=DiagnosticLevel.ERROR,
        message=f"[{component.upper()}] {error_type}: {str(error)}",
        detail=traceback.format_exception_only(type(error), error)[-1].strip(),
        suggestion=suggestion,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


# ═══════════════════════════════════════════════════════════════════
# 2. FEDERATION TRUST SCORING
# ═══════════════════════════════════════════════════════════════════

@dataclass
class TrustMetrics:
    """Raw metrics for computing a trust score."""
    issuer: str
    total_transactions: int = 0
    successful_transactions: int = 0
    failed_transactions: int = 0
    revocations_received: int = 0       # Passports from this org revoked
    avg_response_ms: float = 0.0
    first_seen: str = ""
    last_seen: str = ""
    jwks_fetch_failures: int = 0
    crl_size: int = 0                   # How many revoked passports they have

    def success_rate(self) -> float:
        if self.total_transactions == 0:
            return 0.0
        return self.successful_transactions / self.total_transactions

    def age_days(self) -> int:
        if not self.first_seen:
            return 0
        first = datetime.fromisoformat(self.first_seen)
        return max(0, (datetime.now(timezone.utc) - first).days)

    def to_dict(self) -> dict:
        return {
            "issuer": self.issuer,
            "total_transactions": self.total_transactions,
            "successful_transactions": self.successful_transactions,
            "failed_transactions": self.failed_transactions,
            "success_rate": round(self.success_rate(), 4),
            "revocations_received": self.revocations_received,
            "avg_response_ms": round(self.avg_response_ms, 2),
            "age_days": self.age_days(),
            "jwks_fetch_failures": self.jwks_fetch_failures,
            "crl_size": self.crl_size,
        }


@dataclass
class TrustScore:
    """Computed trust score for a federated issuer."""
    issuer: str
    score: int                   # 0-100
    grade: str                   # A, B, C, D, F
    factors: dict = field(default_factory=dict)
    computed_at: str = ""

    def to_dict(self) -> dict:
        return {
            "issuer": self.issuer,
            "score": self.score,
            "grade": self.grade,
            "factors": self.factors,
            "computed_at": self.computed_at,
        }


class FederationTrustScorer:
    """
    Computes trust scores (0-100) for federated organizations.

    Scoring factors (weighted):
    - Transaction success rate (30%) — what % of transactions succeed
    - Federation age (20%) — how long we've been federated
    - Revocation rate (20%) — how many of their passports are revoked
    - Response time (15%) — avg latency of their endpoints
    - JWKS reliability (15%) — how often their JWKS fetch fails

    Grades: A (80-100), B (60-79), C (40-59), D (20-39), F (0-19)

    Usage:
        scorer = FederationTrustScorer()

        # Record transactions
        scorer.record_transaction("urn:aib:org:partner", success=True, latency_ms=45)
        scorer.record_transaction("urn:aib:org:partner", success=True, latency_ms=52)
        scorer.record_transaction("urn:aib:org:partner", success=False, latency_ms=5000)

        # Record a revocation from that org
        scorer.record_revocation("urn:aib:org:partner")

        # Compute score
        score = scorer.compute_score("urn:aib:org:partner")
        print(f"{score.issuer}: {score.score}/100 ({score.grade})")

        # Use in federation decisions
        if score.score < 50:
            reject_passport()
    """

    # Weight of each factor in the score
    WEIGHTS = {
        "success_rate": 0.30,
        "age": 0.20,
        "revocation_rate": 0.20,
        "response_time": 0.15,
        "jwks_reliability": 0.15,
    }

    def __init__(self, min_score_to_trust: int = 0):
        self._metrics: dict[str, TrustMetrics] = {}
        self._lock = threading.Lock()
        self.min_score_to_trust = min_score_to_trust

    def _get_or_create(self, issuer: str) -> TrustMetrics:
        if issuer not in self._metrics:
            self._metrics[issuer] = TrustMetrics(
                issuer=issuer,
                first_seen=datetime.now(timezone.utc).isoformat(),
            )
        return self._metrics[issuer]

    # ── Recording ─────────────────────────────────────────────────

    def record_transaction(self, issuer: str, success: bool, latency_ms: float = 0.0):
        with self._lock:
            m = self._get_or_create(issuer)
            m.total_transactions += 1
            if success:
                m.successful_transactions += 1
            else:
                m.failed_transactions += 1
            # Running average of latency
            if m.avg_response_ms == 0:
                m.avg_response_ms = latency_ms
            else:
                m.avg_response_ms = (m.avg_response_ms * 0.9) + (latency_ms * 0.1)
            m.last_seen = datetime.now(timezone.utc).isoformat()

    def record_revocation(self, issuer: str):
        with self._lock:
            m = self._get_or_create(issuer)
            m.revocations_received += 1

    def record_jwks_failure(self, issuer: str):
        with self._lock:
            m = self._get_or_create(issuer)
            m.jwks_fetch_failures += 1

    def set_crl_size(self, issuer: str, size: int):
        with self._lock:
            m = self._get_or_create(issuer)
            m.crl_size = size

    # ── Scoring ───────────────────────────────────────────────────

    def compute_score(self, issuer: str) -> TrustScore:
        with self._lock:
            m = self._metrics.get(issuer)

        if not m:
            return TrustScore(
                issuer=issuer, score=0, grade="F",
                factors={"reason": "No data — issuer never seen"},
                computed_at=datetime.now(timezone.utc).isoformat(),
            )

        factors = {}

        # 1. Success rate (30%) — 100% = full score, 0% = zero
        sr = m.success_rate()
        factors["success_rate"] = {
            "value": round(sr, 4),
            "score": round(sr * 100),
            "weight": self.WEIGHTS["success_rate"],
        }

        # 2. Age (20%) — 0 days = 0, 30+ days = 100
        age = m.age_days()
        age_score = min(100, (age / 30) * 100)
        factors["age"] = {
            "value": age,
            "score": round(age_score),
            "weight": self.WEIGHTS["age"],
        }

        # 3. Revocation rate (20%) — 0 revocations per 100 tx = 100, 10+ = 0
        if m.total_transactions > 0:
            rev_rate = m.revocations_received / max(m.total_transactions, 1)
            rev_score = max(0, 100 - (rev_rate * 1000))
        else:
            rev_score = 50  # No data = neutral
        factors["revocation_rate"] = {
            "value": m.revocations_received,
            "score": round(rev_score),
            "weight": self.WEIGHTS["revocation_rate"],
        }

        # 4. Response time (15%) — <50ms = 100, >2000ms = 0
        if m.avg_response_ms > 0:
            rt_score = max(0, 100 - ((m.avg_response_ms - 50) / 20))
            rt_score = min(100, rt_score)
        else:
            rt_score = 50
        factors["response_time"] = {
            "value": round(m.avg_response_ms, 2),
            "score": round(rt_score),
            "weight": self.WEIGHTS["response_time"],
        }

        # 5. JWKS reliability (15%) — 0 failures = 100, 5+ = 0
        jwks_score = max(0, 100 - (m.jwks_fetch_failures * 20))
        factors["jwks_reliability"] = {
            "value": m.jwks_fetch_failures,
            "score": round(jwks_score),
            "weight": self.WEIGHTS["jwks_reliability"],
        }

        # Weighted total
        total = sum(
            factors[k]["score"] * factors[k]["weight"]
            for k in self.WEIGHTS
        )
        score = round(total)
        score = max(0, min(100, score))

        grade = self._grade(score)

        return TrustScore(
            issuer=issuer,
            score=score,
            grade=grade,
            factors=factors,
            computed_at=datetime.now(timezone.utc).isoformat(),
        )

    def should_trust(self, issuer: str) -> tuple[bool, TrustScore]:
        """Check if an issuer meets the minimum trust threshold."""
        score = self.compute_score(issuer)
        return score.score >= self.min_score_to_trust, score

    def _grade(self, score: int) -> str:
        if score >= 80: return "A"
        if score >= 60: return "B"
        if score >= 40: return "C"
        if score >= 20: return "D"
        return "F"

    # ── Query ─────────────────────────────────────────────────────

    def get_metrics(self, issuer: str) -> Optional[dict]:
        with self._lock:
            m = self._metrics.get(issuer)
            return m.to_dict() if m else None

    def list_scores(self) -> list[dict]:
        with self._lock:
            issuers = list(self._metrics.keys())
        return [self.compute_score(i).to_dict() for i in issuers]

    def list_by_grade(self, grade: str) -> list[dict]:
        return [s for s in self.list_scores() if s["grade"] == grade]

    @property
    def issuer_count(self) -> int:
        with self._lock:
            return len(self._metrics)
