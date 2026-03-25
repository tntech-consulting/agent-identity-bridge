"""Tests for Security Hardening Sprint 1 — 5 quick wins."""

import pytest
from aib.hardening_sprint1 import (
    # OPT-ID-01: Audience
    inject_audience, verify_audience, AudienceError,
    # OPT-OIDC-03: Clock skew
    get_jwt_decode_options, DEFAULT_CLOCK_SKEW_SECONDS,
    # OPT-NET-04: Double DNS
    double_dns_check, DNSRebindingError, _is_private,
    # OPT-ID-03: Max children
    ChildrenLimiter, MaxChildrenExceededError, DEFAULT_MAX_CHILDREN,
    # OPT-OPS-04: Error codes
    ErrorCodes, AIBError, make_error,
)


# ═══════════════════════════════════════════════════════════════════
# 1. AUDIENCE CLAIM
# ═══════════════════════════════════════════════════════════════════

class TestAudienceClaim:

    def test_inject_single_audience(self):
        payload = {"passport_id": "urn:aib:agent:acme:bot"}
        result = inject_audience(payload, ["partner.com"])
        assert result["aud"] == "partner.com"  # Single → string

    def test_inject_multiple_audiences(self):
        payload = {"passport_id": "urn:aib:agent:acme:bot"}
        result = inject_audience(payload, ["partner.com", "other.com"])
        assert result["aud"] == ["partner.com", "other.com"]  # Multiple → list

    def test_inject_empty_audiences(self):
        payload = {"passport_id": "urn:aib:agent:acme:bot"}
        result = inject_audience(payload, [])
        assert "aud" not in result

    def test_verify_no_aud_backward_compatible(self):
        valid, reason = verify_audience({"passport_id": "test"}, "partner.com")
        assert valid is True
        assert "backward compatible" in reason.lower()

    def test_verify_aud_matches(self):
        valid, _ = verify_audience({"aud": "partner.com"}, "partner.com")
        assert valid is True

    def test_verify_aud_list_matches(self):
        valid, _ = verify_audience({"aud": ["a.com", "b.com"]}, "b.com")
        assert valid is True

    def test_verify_aud_mismatch(self):
        valid, reason = verify_audience({"aud": "partner.com"}, "attacker.com")
        assert valid is False
        assert "mismatch" in reason.lower()

    def test_verify_aud_no_expected(self):
        """If verifier doesn't specify expected audience, pass."""
        valid, _ = verify_audience({"aud": "partner.com"}, None)
        assert valid is True

    def test_verify_aud_invalid_type(self):
        valid, reason = verify_audience({"aud": 12345}, "partner.com")
        assert valid is False
        assert "invalid" in reason.lower()


# ═══════════════════════════════════════════════════════════════════
# 2. CLOCK SKEW TOLERANCE
# ═══════════════════════════════════════════════════════════════════

class TestClockSkew:

    def test_default_leeway(self):
        assert DEFAULT_CLOCK_SKEW_SECONDS == 30

    def test_options_structure(self):
        opts = get_jwt_decode_options(leeway_seconds=60)
        assert opts["verify_exp"] is True
        assert opts["verify_iat"] is True
        assert opts["verify_nbf"] is True

    def test_options_with_required_claims(self):
        opts = get_jwt_decode_options(
            leeway_seconds=30,
            require_claims=["exp", "iat", "passport_id"],
        )
        assert opts["require"] == ["exp", "iat", "passport_id"]

    def test_options_without_required_claims(self):
        opts = get_jwt_decode_options(leeway_seconds=30)
        assert "require" not in opts


# ═══════════════════════════════════════════════════════════════════
# 3. DOUBLE DNS RESOLUTION
# ═══════════════════════════════════════════════════════════════════

class TestDoubleDNS:

    def test_is_private_loopback(self):
        assert _is_private("127.0.0.1") is True

    def test_is_private_10(self):
        assert _is_private("10.0.0.1") is True

    def test_is_private_192(self):
        assert _is_private("192.168.1.1") is True

    def test_is_private_link_local(self):
        assert _is_private("169.254.169.254") is True

    def test_is_private_public(self):
        assert _is_private("8.8.8.8") is False

    def test_is_private_invalid(self):
        assert _is_private("not-an-ip") is True  # Can't parse → unsafe

    def test_double_dns_nonexistent(self):
        safe, reason = double_dns_check("this-domain-definitely-does-not-exist-xyz123.com")
        assert safe is False
        assert "cannot resolve" in reason.lower()

    def test_double_dns_localhost(self):
        safe, reason = double_dns_check("localhost")
        assert safe is False
        assert "private" in reason.lower()


# ═══════════════════════════════════════════════════════════════════
# 4. MAX CHILDREN PER TIER
# ═══════════════════════════════════════════════════════════════════

class TestMaxChildren:

    @pytest.fixture
    def limiter(self):
        return ChildrenLimiter(limits={"permanent": 3, "session": 2, "ephemeral": 0})

    def test_default_limits(self):
        assert DEFAULT_MAX_CHILDREN["permanent"] == 100
        assert DEFAULT_MAX_CHILDREN["session"] == 10
        assert DEFAULT_MAX_CHILDREN["ephemeral"] == 0

    def test_first_child_allowed(self, limiter):
        allowed, _ = limiter.check_can_delegate("parent-1", "permanent")
        assert allowed is True

    def test_under_limit(self, limiter):
        limiter.record_child("parent-1")
        limiter.record_child("parent-1")
        allowed, reason = limiter.check_can_delegate("parent-1", "permanent")
        assert allowed is True
        assert "2/3" in reason

    def test_at_limit_blocked(self, limiter):
        for _ in range(3):
            limiter.record_child("parent-1")
        with pytest.raises(MaxChildrenExceededError, match="max children"):
            limiter.check_can_delegate("parent-1", "permanent")

    def test_ephemeral_cannot_delegate(self, limiter):
        with pytest.raises(MaxChildrenExceededError, match="cannot delegate"):
            limiter.check_can_delegate("eph-1", "ephemeral")

    def test_different_parents_independent(self, limiter):
        for _ in range(3):
            limiter.record_child("parent-1")
        # parent-1 blocked, parent-2 free
        with pytest.raises(MaxChildrenExceededError):
            limiter.check_can_delegate("parent-1", "permanent")
        allowed, _ = limiter.check_can_delegate("parent-2", "permanent")
        assert allowed is True

    def test_remove_child_frees_slot(self, limiter):
        for _ in range(3):
            limiter.record_child("parent-1")
        with pytest.raises(MaxChildrenExceededError):
            limiter.check_can_delegate("parent-1", "permanent")

        limiter.remove_child("parent-1")
        allowed, _ = limiter.check_can_delegate("parent-1", "permanent")
        assert allowed is True

    def test_get_count(self, limiter):
        assert limiter.get_count("parent-1") == 0
        limiter.record_child("parent-1")
        assert limiter.get_count("parent-1") == 1

    def test_get_usage(self, limiter):
        limiter.record_child("parent-1")
        usage = limiter.get_usage("parent-1", "permanent")
        assert usage["children"] == 1
        assert usage["limit"] == 3
        assert usage["remaining"] == 2
        assert usage["can_delegate"] is True

    def test_session_limit(self, limiter):
        limiter.record_child("sess-1")
        limiter.record_child("sess-1")
        with pytest.raises(MaxChildrenExceededError):
            limiter.check_can_delegate("sess-1", "session")


# ═══════════════════════════════════════════════════════════════════
# 5. STANDARDIZED ERROR CODES
# ═══════════════════════════════════════════════════════════════════

class TestErrorCodes:

    def test_error_code_format(self):
        assert ErrorCodes.PASSPORT_NOT_FOUND.code == "AIB-001"
        assert ErrorCodes.RATE_LIMITED.code == "AIB-303"
        assert ErrorCodes.INTERNAL_ERROR.code == "AIB-901"

    def test_http_status(self):
        assert ErrorCodes.PASSPORT_NOT_FOUND.http_status == 404
        assert ErrorCodes.PASSPORT_EXPIRED.http_status == 401
        assert ErrorCodes.RATE_LIMITED.http_status == 429
        assert ErrorCodes.INTERNAL_ERROR.http_status == 500

    def test_to_response_no_detail(self):
        resp = ErrorCodes.PASSPORT_NOT_FOUND.to_response()
        assert "error" in resp
        assert resp["error"]["code"] == "AIB-001"
        assert resp["error"]["message"] == "Passport not found"
        assert "detail" not in resp["error"]  # Detail NEVER in response

    def test_to_log_includes_detail(self):
        err = make_error(ErrorCodes.PASSPORT_NOT_FOUND, detail="Checked PostgreSQL table 'passports'")
        log = err.to_log()
        assert log["error_code"] == "AIB-001"
        assert "PostgreSQL" in log["detail"]

    def test_make_error(self):
        err = make_error(
            ErrorCodes.SSRF_BLOCKED,
            detail="Resolved to 169.254.169.254"
        )
        assert err.code == "AIB-301"
        assert err.http_status == 403
        assert err.detail == "Resolved to 169.254.169.254"
        # Response is generic
        assert "169.254" not in str(err.to_response())

    def test_all_categories_covered(self):
        """Verify all error categories have at least one code."""
        codes = [
            v for k, v in vars(ErrorCodes).items()
            if isinstance(v, AIBError)
        ]
        categories = set(c.code.split("-")[1][0] for c in codes)
        assert "0" in categories  # Auth
        assert "1" in categories  # Authorization
        assert "2" in categories  # Translation
        assert "3" in categories  # Gateway
        assert "4" in categories  # Audit
        assert "5" in categories  # Federation
        assert "9" in categories  # Internal

    def test_error_message_is_generic(self):
        """Verify error messages don't contain technical details."""
        for k, v in vars(ErrorCodes).items():
            if isinstance(v, AIBError):
                assert "PostgreSQL" not in v.message
                assert "Redis" not in v.message
                assert "traceback" not in v.message.lower()
                assert "stack" not in v.message.lower()

    def test_gateway_errors(self):
        assert ErrorCodes.SSRF_BLOCKED.http_status == 403
        assert ErrorCodes.DNS_REBINDING.http_status == 403
        assert ErrorCodes.GATEWAY_TIMEOUT.http_status == 504
        assert ErrorCodes.GATEWAY_ERROR.http_status == 502

    def test_gdpr_shredded_uses_410(self):
        """HTTP 410 Gone is correct for crypto-shredded data."""
        assert ErrorCodes.GDPR_SHREDDED.http_status == 410
