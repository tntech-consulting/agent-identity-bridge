"""
AIB — Rate Limiting.

Sliding window rate limiter per passport_id.

Limits are configurable per passport tier:
  - permanent: 1000 req/min (production agents, high throughput)
  - session:    100 req/min (workflow scoped, moderate)
  - ephemeral:   10 req/min (sub-agents, minimal)

Two backends:
  - MemoryRateLimiter: in-process dict, for Tier 1 (single instance)
  - RedisRateLimiter:  Redis INCR+EXPIRE, for Tier 2+ (multi-instance)
    (interface defined here, Redis implementation is a drop-in)

The limiter returns a RateLimitResult with:
  - allowed: bool
  - remaining: how many requests left in the window
  - reset_at: when the window resets
  - retry_after: seconds to wait if blocked

Integration:
  Put rate_limiter.check() BEFORE passport verification in the gateway.
  Reject with HTTP 429 + Retry-After header if blocked.

References: OPT-NET-01 in Security Audit document.
"""

import time
import threading
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional
from enum import Enum


# ── Rate limit tiers ──────────────────────────────────────────────

class RateLimitTier(str, Enum):
    PERMANENT = "permanent"
    SESSION = "session"
    EPHEMERAL = "ephemeral"
    SYSTEM = "system"              # Internal system calls (no limit)


# Default limits: requests per window
DEFAULT_LIMITS = {
    RateLimitTier.PERMANENT: 1000,
    RateLimitTier.SESSION: 100,
    RateLimitTier.EPHEMERAL: 10,
    RateLimitTier.SYSTEM: 0,       # 0 = unlimited
}

# Default window: seconds
DEFAULT_WINDOW = 60  # 1 minute


# ── Result ────────────────────────────────────────────────────────

@dataclass
class RateLimitResult:
    """Result of a rate limit check."""
    allowed: bool
    limit: int                     # Max requests in window
    remaining: int                 # Requests remaining
    window_seconds: int            # Window size
    reset_at: float                # Unix timestamp when window resets
    retry_after: float = 0.0       # Seconds to wait (0 if allowed)
    tier: str = ""
    key: str = ""

    def to_headers(self) -> dict:
        """Generate standard rate limit headers for HTTP response."""
        headers = {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(max(0, self.remaining)),
            "X-RateLimit-Reset": str(int(self.reset_at)),
        }
        if not self.allowed:
            headers["Retry-After"] = str(int(self.retry_after) + 1)
        return headers

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "limit": self.limit,
            "remaining": self.remaining,
            "window_seconds": self.window_seconds,
            "reset_at": self.reset_at,
            "retry_after": self.retry_after,
            "tier": self.tier,
            "key": self.key,
        }


# ── Sliding Window Entry ─────────────────────────────────────────

@dataclass
class _WindowEntry:
    """Internal: tracks requests in a sliding window."""
    timestamps: list  # List of request timestamps within the window
    window_start: float


# ── Memory Rate Limiter (Tier 1) ──────────────────────────────────

class MemoryRateLimiter:
    """
    In-memory sliding window rate limiter.

    Thread-safe. Suitable for single-instance deployments.

    Usage:
        limiter = MemoryRateLimiter()

        result = limiter.check("urn:aib:agent:acme:bot", tier="permanent")
        if not result.allowed:
            return HTTP 429, headers=result.to_headers()
    """

    def __init__(
        self,
        limits: Optional[dict] = None,
        window_seconds: int = DEFAULT_WINDOW,
    ):
        self._limits = {}
        for tier in RateLimitTier:
            if limits and tier.value in limits:
                self._limits[tier] = limits[tier.value]
            elif limits and tier in limits:
                self._limits[tier] = limits[tier]
            else:
                self._limits[tier] = DEFAULT_LIMITS[tier]

        self._window = window_seconds
        self._entries: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def check(
        self,
        key: str,
        tier: str = "permanent",
    ) -> RateLimitResult:
        """
        Check if a request is allowed under the rate limit.

        Args:
            key: Rate limit key (typically passport_id)
            tier: Passport tier (permanent, session, ephemeral, system)

        Returns:
            RateLimitResult with allowed status and headers
        """
        tier_enum = RateLimitTier(tier) if isinstance(tier, str) else tier
        limit = self._limits.get(tier_enum, DEFAULT_LIMITS.get(tier_enum, 1000))

        # System tier = unlimited
        if limit == 0:
            return RateLimitResult(
                allowed=True, limit=0, remaining=0,
                window_seconds=self._window,
                reset_at=time.time() + self._window,
                tier=tier, key=key,
            )

        now = time.time()
        window_start = now - self._window

        with self._lock:
            # Prune old entries outside the window
            timestamps = self._entries[key]
            self._entries[key] = [t for t in timestamps if t > window_start]
            timestamps = self._entries[key]

            current_count = len(timestamps)

            if current_count >= limit:
                # BLOCKED
                oldest_in_window = timestamps[0] if timestamps else now
                reset_at = oldest_in_window + self._window
                retry_after = reset_at - now

                return RateLimitResult(
                    allowed=False,
                    limit=limit,
                    remaining=0,
                    window_seconds=self._window,
                    reset_at=reset_at,
                    retry_after=max(0, retry_after),
                    tier=tier,
                    key=key,
                )

            # ALLOWED — record this request
            timestamps.append(now)

            return RateLimitResult(
                allowed=True,
                limit=limit,
                remaining=limit - len(timestamps),
                window_seconds=self._window,
                reset_at=now + self._window,
                tier=tier,
                key=key,
            )

    def reset(self, key: str):
        """Reset the rate limit for a specific key."""
        with self._lock:
            self._entries.pop(key, None)

    def reset_all(self):
        """Reset all rate limits."""
        with self._lock:
            self._entries.clear()

    def get_usage(self, key: str, tier: str = "permanent") -> RateLimitResult:
        """Check current usage without consuming a request."""
        tier_enum = RateLimitTier(tier) if isinstance(tier, str) else tier
        limit = self._limits.get(tier_enum, DEFAULT_LIMITS.get(tier_enum, 1000))

        now = time.time()
        window_start = now - self._window

        with self._lock:
            timestamps = [t for t in self._entries.get(key, []) if t > window_start]
            current_count = len(timestamps)

        return RateLimitResult(
            allowed=current_count < limit,
            limit=limit,
            remaining=max(0, limit - current_count),
            window_seconds=self._window,
            reset_at=now + self._window,
            tier=tier,
            key=key,
        )

    def get_all_keys(self) -> list[str]:
        """List all tracked keys."""
        with self._lock:
            return list(self._entries.keys())

    def cleanup(self):
        """Remove expired entries to free memory."""
        now = time.time()
        window_start = now - self._window
        with self._lock:
            empty_keys = []
            for key, timestamps in self._entries.items():
                self._entries[key] = [t for t in timestamps if t > window_start]
                if not self._entries[key]:
                    empty_keys.append(key)
            for key in empty_keys:
                del self._entries[key]

    @property
    def stats(self) -> dict:
        """Rate limiter statistics."""
        now = time.time()
        window_start = now - self._window
        with self._lock:
            active_keys = sum(
                1 for timestamps in self._entries.values()
                if any(t > window_start for t in timestamps)
            )
            total_requests = sum(
                sum(1 for t in timestamps if t > window_start)
                for timestamps in self._entries.values()
            )
        return {
            "active_keys": active_keys,
            "total_requests_in_window": total_requests,
            "window_seconds": self._window,
            "limits": {tier.value: limit for tier, limit in self._limits.items()},
        }


# ── Redis Rate Limiter Interface (Tier 2+) ────────────────────────

class RedisRateLimiterInterface:
    """
    Interface for Redis-based rate limiting.

    This is the contract for production deployments. The actual
    implementation uses Redis INCR + EXPIRE for atomic, distributed
    rate limiting across multiple gateway instances.

    Implementation sketch (not included — depends on redis-py):

        def check(self, key, tier):
            redis_key = f"aib:ratelimit:{key}:{window_id}"
            count = redis.incr(redis_key)
            if count == 1:
                redis.expire(redis_key, self._window)
            if count > limit:
                ttl = redis.ttl(redis_key)
                return RateLimitResult(allowed=False, retry_after=ttl, ...)
            return RateLimitResult(allowed=True, remaining=limit-count, ...)

    Drop-in replacement for MemoryRateLimiter. Same check() signature.
    """

    def check(self, key: str, tier: str = "permanent") -> RateLimitResult:
        raise NotImplementedError("Use MemoryRateLimiter or implement with redis-py")

    def reset(self, key: str):
        raise NotImplementedError

    def get_usage(self, key: str, tier: str = "permanent") -> RateLimitResult:
        raise NotImplementedError
