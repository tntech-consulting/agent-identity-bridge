"""Tests for rate limiting — sliding window, tier limits, blocking, headers."""

import time
import threading
import pytest
from aib.rate_limiter import (
    MemoryRateLimiter, RateLimitResult, RateLimitTier,
    DEFAULT_LIMITS, DEFAULT_WINDOW,
)


@pytest.fixture
def limiter():
    return MemoryRateLimiter(window_seconds=1)


@pytest.fixture
def tight_limiter():
    """Limiter with very low limits for testing."""
    return MemoryRateLimiter(
        limits={"permanent": 3, "session": 2, "ephemeral": 1},
        window_seconds=1,
    )


# ═══════════════════════════════════════════════════════════════════
# Basic functionality
# ═══════════════════════════════════════════════════════════════════

class TestBasicRateLimiting:

    def test_first_request_allowed(self, limiter):
        result = limiter.check("agent-1", tier="permanent")
        assert result.allowed is True

    def test_returns_rate_limit_result(self, limiter):
        result = limiter.check("agent-1", tier="permanent")
        assert isinstance(result, RateLimitResult)
        assert result.limit == DEFAULT_LIMITS[RateLimitTier.PERMANENT]
        assert result.remaining >= 0
        assert result.tier == "permanent"
        assert result.key == "agent-1"

    def test_remaining_decreases(self, tight_limiter):
        r1 = tight_limiter.check("agent-1", tier="permanent")
        assert r1.remaining == 2  # 3 limit, 1 used

        r2 = tight_limiter.check("agent-1", tier="permanent")
        assert r2.remaining == 1

        r3 = tight_limiter.check("agent-1", tier="permanent")
        assert r3.remaining == 0

    def test_blocked_after_limit(self, tight_limiter):
        for _ in range(3):
            result = tight_limiter.check("agent-1", tier="permanent")
            assert result.allowed is True

        result = tight_limiter.check("agent-1", tier="permanent")
        assert result.allowed is False
        assert result.remaining == 0
        assert result.retry_after > 0

    def test_different_keys_independent(self, tight_limiter):
        for _ in range(3):
            tight_limiter.check("agent-1", tier="permanent")

        # Agent-1 blocked
        assert tight_limiter.check("agent-1", tier="permanent").allowed is False

        # Agent-2 still free
        assert tight_limiter.check("agent-2", tier="permanent").allowed is True


# ═══════════════════════════════════════════════════════════════════
# Tier-based limits
# ═══════════════════════════════════════════════════════════════════

class TestTierLimits:

    def test_permanent_higher_than_session(self, tight_limiter):
        # Permanent allows 3
        for _ in range(3):
            assert tight_limiter.check("perm", tier="permanent").allowed is True
        assert tight_limiter.check("perm", tier="permanent").allowed is False

        # Session allows only 2
        for _ in range(2):
            assert tight_limiter.check("sess", tier="session").allowed is True
        assert tight_limiter.check("sess", tier="session").allowed is False

    def test_ephemeral_most_restricted(self, tight_limiter):
        assert tight_limiter.check("eph", tier="ephemeral").allowed is True
        assert tight_limiter.check("eph", tier="ephemeral").allowed is False

    def test_system_unlimited(self, limiter):
        for _ in range(10000):
            result = limiter.check("sys", tier="system")
            assert result.allowed is True

    def test_default_limits(self):
        assert DEFAULT_LIMITS[RateLimitTier.PERMANENT] == 1000
        assert DEFAULT_LIMITS[RateLimitTier.SESSION] == 100
        assert DEFAULT_LIMITS[RateLimitTier.EPHEMERAL] == 10
        assert DEFAULT_LIMITS[RateLimitTier.SYSTEM] == 0


# ═══════════════════════════════════════════════════════════════════
# Sliding window
# ═══════════════════════════════════════════════════════════════════

class TestSlidingWindow:

    def test_window_expires(self):
        limiter = MemoryRateLimiter(
            limits={"permanent": 2},
            window_seconds=1,
        )

        limiter.check("agent", tier="permanent")
        limiter.check("agent", tier="permanent")
        assert limiter.check("agent", tier="permanent").allowed is False

        # Wait for window to expire
        time.sleep(1.1)

        assert limiter.check("agent", tier="permanent").allowed is True

    def test_sliding_not_fixed(self):
        """Verify it's a sliding window, not a fixed window."""
        limiter = MemoryRateLimiter(
            limits={"permanent": 3},
            window_seconds=1,
        )

        # T=0: request 1
        limiter.check("agent", tier="permanent")
        time.sleep(0.4)

        # T=0.4: request 2
        limiter.check("agent", tier="permanent")
        time.sleep(0.4)

        # T=0.8: request 3
        limiter.check("agent", tier="permanent")

        # T=0.8: should be blocked (3 requests in last 1s)
        assert limiter.check("agent", tier="permanent").allowed is False

        # T=1.1: request 1 has expired, window slides
        time.sleep(0.3)
        assert limiter.check("agent", tier="permanent").allowed is True


# ═══════════════════════════════════════════════════════════════════
# HTTP Headers
# ═══════════════════════════════════════════════════════════════════

class TestHeaders:

    def test_allowed_headers(self, tight_limiter):
        result = tight_limiter.check("agent", tier="permanent")
        headers = result.to_headers()
        assert "X-RateLimit-Limit" in headers
        assert "X-RateLimit-Remaining" in headers
        assert "X-RateLimit-Reset" in headers
        assert headers["X-RateLimit-Limit"] == "3"
        assert "Retry-After" not in headers  # Not blocked

    def test_blocked_headers(self, tight_limiter):
        for _ in range(3):
            tight_limiter.check("agent", tier="permanent")

        result = tight_limiter.check("agent", tier="permanent")
        headers = result.to_headers()
        assert "Retry-After" in headers
        assert int(headers["Retry-After"]) > 0
        assert headers["X-RateLimit-Remaining"] == "0"

    def test_to_dict(self, tight_limiter):
        result = tight_limiter.check("agent", tier="permanent")
        d = result.to_dict()
        assert d["allowed"] is True
        assert d["tier"] == "permanent"
        assert d["key"] == "agent"
        assert "limit" in d
        assert "remaining" in d


# ═══════════════════════════════════════════════════════════════════
# Reset & Cleanup
# ═══════════════════════════════════════════════════════════════════

class TestResetAndCleanup:

    def test_reset_key(self, tight_limiter):
        for _ in range(3):
            tight_limiter.check("agent", tier="permanent")
        assert tight_limiter.check("agent", tier="permanent").allowed is False

        tight_limiter.reset("agent")
        assert tight_limiter.check("agent", tier="permanent").allowed is True

    def test_reset_all(self, tight_limiter):
        tight_limiter.check("agent-1", tier="permanent")
        tight_limiter.check("agent-2", tier="permanent")
        tight_limiter.reset_all()
        assert len(tight_limiter.get_all_keys()) == 0

    def test_cleanup(self):
        limiter = MemoryRateLimiter(
            limits={"permanent": 5},
            window_seconds=1,
        )
        limiter.check("agent-1", tier="permanent")
        limiter.check("agent-2", tier="permanent")
        assert len(limiter.get_all_keys()) == 2

        time.sleep(1.1)
        limiter.cleanup()
        assert len(limiter.get_all_keys()) == 0

    def test_get_usage_without_consuming(self, tight_limiter):
        tight_limiter.check("agent", tier="permanent")
        usage = tight_limiter.get_usage("agent", tier="permanent")
        assert usage.remaining == 2  # Only 1 real request, not 2

        # Check again - still 2 remaining (get_usage doesn't consume)
        usage2 = tight_limiter.get_usage("agent", tier="permanent")
        assert usage2.remaining == 2


# ═══════════════════════════════════════════════════════════════════
# Stats
# ═══════════════════════════════════════════════════════════════════

class TestStats:

    def test_stats(self, tight_limiter):
        tight_limiter.check("agent-1", tier="permanent")
        tight_limiter.check("agent-1", tier="permanent")
        tight_limiter.check("agent-2", tier="session")

        s = tight_limiter.stats
        assert s["active_keys"] == 2
        assert s["total_requests_in_window"] == 3
        assert "limits" in s
        assert s["limits"]["permanent"] == 3


# ═══════════════════════════════════════════════════════════════════
# Thread Safety
# ═══════════════════════════════════════════════════════════════════

class TestConcurrency:

    def test_thread_safe(self):
        limiter = MemoryRateLimiter(
            limits={"permanent": 100},
            window_seconds=2,
        )

        results = []

        def hammer():
            for _ in range(50):
                r = limiter.check("shared-agent", tier="permanent")
                results.append(r.allowed)

        threads = [threading.Thread(target=hammer) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # 200 total requests, limit is 100
        allowed = sum(1 for r in results if r)
        blocked = sum(1 for r in results if not r)
        assert allowed == 100
        assert blocked == 100

    def test_no_race_condition_on_reset(self):
        limiter = MemoryRateLimiter(
            limits={"permanent": 10},
            window_seconds=2,
        )

        def check_loop():
            for _ in range(20):
                limiter.check("agent", tier="permanent")

        def reset_loop():
            for _ in range(5):
                time.sleep(0.01)
                limiter.reset("agent")

        t1 = threading.Thread(target=check_loop)
        t2 = threading.Thread(target=reset_loop)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        # No crash = pass


# ═══════════════════════════════════════════════════════════════════
# Custom Limits
# ═══════════════════════════════════════════════════════════════════

class TestCustomLimits:

    def test_custom_limits(self):
        limiter = MemoryRateLimiter(
            limits={"permanent": 5, "session": 3, "ephemeral": 1},
            window_seconds=1,
        )
        for _ in range(5):
            assert limiter.check("p", tier="permanent").allowed is True
        assert limiter.check("p", tier="permanent").allowed is False

        for _ in range(3):
            assert limiter.check("s", tier="session").allowed is True
        assert limiter.check("s", tier="session").allowed is False

    def test_custom_window(self):
        limiter = MemoryRateLimiter(
            limits={"permanent": 2},
            window_seconds=2,
        )
        limiter.check("a", tier="permanent")
        limiter.check("a", tier="permanent")
        assert limiter.check("a", tier="permanent").allowed is False

        time.sleep(2.1)
        assert limiter.check("a", tier="permanent").allowed is True
