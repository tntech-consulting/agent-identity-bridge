"""
AIB — Security Hardening Sprint 3: Performance & Compliance.

Five optimizations:

1. OPT-AUDIT-05: Async receipt pipeline (receipts don't block the gateway)
2. OPT-AUDIT-02: Incremental Merkle Tree (O(log N) add instead of O(N) rebuild)
3. OPT-OIDC-04: JWKS warm cache (pre-fetch at boot, background refresh)
4. OPT-OIDC-02: Token replay protection (jti tracking with TTL)
5. OPT-GDPR-04: PII access audit (every encrypt/decrypt/shred generates a receipt)

None modifies existing modules. All are opt-in wrappers.
"""

import hashlib
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Any, Callable


# ═══════════════════════════════════════════════════════════════════
# 1. OPT-AUDIT-05 — ASYNC RECEIPT PIPELINE
# ═══════════════════════════════════════════════════════════════════

@dataclass
class ReceiptEvent:
    """
    Lightweight event published by the gateway BEFORE returning to the caller.

    The timestamp is set NOW (when the action happens), not when the
    receipt is persisted. This guarantees accurate timing even with
    async processing.
    """
    event_id: str
    passport_id: str
    action: str
    protocol: str
    target_url: str
    timestamp: str
    timestamp_unix: float
    status: str
    latency_ms: float
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "passport_id": self.passport_id,
            "action": self.action,
            "protocol": self.protocol,
            "target_url": self.target_url,
            "timestamp": self.timestamp,
            "timestamp_unix": self.timestamp_unix,
            "status": self.status,
            "latency_ms": self.latency_ms,
            "metadata": self.metadata,
        }


class AsyncReceiptPipeline:
    """
    Decouples receipt creation from the gateway request lifecycle.

    Flow:
    1. Gateway handles request (validate → proxy → response)
    2. Gateway publishes a ReceiptEvent to the pipeline (< 0.1ms)
    3. Gateway returns response to caller immediately
    4. Background worker consumes events and creates Action Receipts

    The caller NEVER waits for receipt persistence.

    For Tier 1 (single instance): uses an in-memory deque + worker thread.
    For Tier 2+ (multi-instance): replace with Kafka/Redis Streams.

    Usage:
        pipeline = AsyncReceiptPipeline(handler=my_receipt_creator)
        pipeline.start()

        # In gateway request handler:
        event = pipeline.publish(
            passport_id="urn:aib:agent:acme:bot",
            action="proxy", protocol="a2a",
            target_url="https://partner.com/agent",
            status="success", latency_ms=1.3,
        )
        # Returns immediately — receipt created in background

        pipeline.stop()
    """

    def __init__(
        self,
        handler: Optional[Callable[[ReceiptEvent], None]] = None,
        max_queue_size: int = 10000,
        flush_interval: float = 0.1,
    ):
        self._queue: deque[ReceiptEvent] = deque(maxlen=max_queue_size)
        self._handler = handler or self._default_handler
        self._flush_interval = flush_interval
        self._running = False
        self._worker: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._processed: int = 0
        self._dropped: int = 0
        self._events_log: list[ReceiptEvent] = []  # For testing

    def publish(
        self,
        passport_id: str,
        action: str,
        protocol: str = "",
        target_url: str = "",
        status: str = "success",
        latency_ms: float = 0.0,
        metadata: Optional[dict] = None,
    ) -> ReceiptEvent:
        """
        Publish a receipt event. Returns immediately.

        The event is queued for async processing.
        Timestamp is set NOW, not when processed.
        """
        now = datetime.now(timezone.utc)
        event = ReceiptEvent(
            event_id=f"evt_{uuid.uuid4().hex[:12]}",
            passport_id=passport_id,
            action=action,
            protocol=protocol,
            target_url=target_url,
            timestamp=now.isoformat(),
            timestamp_unix=now.timestamp(),
            status=status,
            latency_ms=latency_ms,
            metadata=metadata or {},
        )

        with self._lock:
            if len(self._queue) >= self._queue.maxlen:
                self._dropped += 1
            self._queue.append(event)

        return event

    def start(self):
        """Start the background worker."""
        if self._running:
            return
        self._running = True
        self._worker = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker.start()

    def stop(self, timeout: float = 2.0):
        """Stop the worker and flush remaining events."""
        self._running = False
        if self._worker:
            self._worker.join(timeout=timeout)
        self._flush()

    def _worker_loop(self):
        while self._running:
            self._flush()
            time.sleep(self._flush_interval)
        self._flush()  # Final flush

    def _flush(self):
        """Process all queued events."""
        while True:
            with self._lock:
                if not self._queue:
                    break
                event = self._queue.popleft()
            try:
                self._handler(event)
                self._processed += 1
                self._events_log.append(event)
            except Exception:
                pass  # Handler errors don't crash the pipeline

    def _default_handler(self, event: ReceiptEvent):
        """Default handler — just stores the event."""
        pass

    @property
    def pending(self) -> int:
        with self._lock:
            return len(self._queue)

    @property
    def processed(self) -> int:
        return self._processed

    @property
    def dropped(self) -> int:
        return self._dropped

    @property
    def stats(self) -> dict:
        return {
            "pending": self.pending,
            "processed": self._processed,
            "dropped": self._dropped,
            "running": self._running,
        }


# ═══════════════════════════════════════════════════════════════════
# 2. OPT-AUDIT-02 — INCREMENTAL MERKLE TREE
# ═══════════════════════════════════════════════════════════════════

def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _hash_pair(left: str, right: str) -> str:
    return _sha256(left + right)


class IncrementalMerkleTree:
    """
    Merkle Tree that adds leaves in O(log N) instead of O(N) rebuild.

    The standard MerkleTree._build() recomputes ALL layers from scratch
    on every add. This version only recomputes the path from the new
    leaf to the root — O(log N) operations.

    Algorithm:
    - Maintain a list of "pending" hashes at each level
    - When a new leaf arrives:
      1. Add it to level 0
      2. If level 0 has a pair, hash them → push to level 1
      3. Repeat up until no more pairs
    - Root = combine all pending hashes top-down

    This is the same algorithm used by Certificate Transparency logs.
    """

    EMPTY_HASH = _sha256("aib:merkle:empty")

    def __init__(self):
        self._leaves: list[str] = []
        self._pending: list[list[str]] = []  # pending[level] = list of hashes
        self._count: int = 0

    def add(self, leaf_hash: str):
        """Add a leaf in O(log N)."""
        self._leaves.append(leaf_hash)
        self._count += 1
        self._insert_at_level(0, leaf_hash)

    def _insert_at_level(self, level: int, hash_val: str):
        """Insert a hash at a given level, propagating up if a pair forms."""
        while level >= len(self._pending):
            self._pending.append([])

        self._pending[level].append(hash_val)

        if len(self._pending[level]) == 2:
            combined = _hash_pair(self._pending[level][0], self._pending[level][1])
            self._pending[level] = []
            self._insert_at_level(level + 1, combined)

    @property
    def root(self) -> str:
        """Compute the root by combining all pending hashes."""
        if not self._pending:
            return self.EMPTY_HASH

        # Combine from bottom to top
        result = None
        for level in range(len(self._pending)):
            for h in self._pending[level]:
                if result is None:
                    result = h
                else:
                    result = _hash_pair(result, h)

        return result or self.EMPTY_HASH

    @property
    def size(self) -> int:
        return self._count

    def get_leaf(self, index: int) -> Optional[str]:
        if 0 <= index < len(self._leaves):
            return self._leaves[index]
        return None

    def verify_leaf(self, index: int, expected_hash: str) -> bool:
        """Verify that a leaf at the given index matches the expected hash."""
        leaf = self.get_leaf(index)
        return leaf == expected_hash


# ═══════════════════════════════════════════════════════════════════
# 3. OPT-OIDC-04 — JWKS WARM CACHE
# ═══════════════════════════════════════════════════════════════════

class JWKSCache:
    """
    Pre-fetching JWKS cache with background refresh.

    Instead of fetching JWKS on the first OIDC request (100-300ms),
    this cache:
    1. Fetches all configured IdP JWKS at boot (warm start)
    2. Refreshes in background every refresh_interval seconds
    3. Falls back to stale cache if refresh fails (resilience)

    No request ever triggers a JWKS fetch — it's always from cache.

    Usage:
        cache = JWKSCache(refresh_interval=1800)  # 30min

        # Register IdPs at boot
        cache.register("entra", "https://login.microsoft.com/.../keys")
        cache.register("okta", "https://dev-xxx.okta.com/oauth2/v1/keys")

        # Warm all caches (call at startup)
        cache.warm_all(fetcher=my_http_fetcher)

        # Start background refresh
        cache.start_refresh(fetcher=my_http_fetcher)

        # Get JWKS (always from cache, never blocks)
        jwks = cache.get("entra")
    """

    def __init__(self, refresh_interval: int = 1800):
        self._providers: dict[str, str] = {}  # name → jwks_uri
        self._cache: dict[str, dict] = {}     # name → jwks data
        self._fetched_at: dict[str, float] = {}
        self._refresh_interval = refresh_interval
        self._lock = threading.Lock()
        self._running = False
        self._worker: Optional[threading.Thread] = None

    def register(self, name: str, jwks_uri: str):
        """Register an IdP's JWKS URI."""
        with self._lock:
            self._providers[name] = jwks_uri

    def warm_all(self, fetcher: Callable[[str], Optional[dict]]):
        """
        Pre-fetch all registered JWKS at startup.

        fetcher: function(url) → dict or None
        """
        with self._lock:
            for name, uri in self._providers.items():
                try:
                    jwks = fetcher(uri)
                    if jwks:
                        self._cache[name] = jwks
                        self._fetched_at[name] = time.time()
                except Exception:
                    pass

    def get(self, name: str) -> Optional[dict]:
        """Get cached JWKS for a provider. Never blocks."""
        with self._lock:
            return self._cache.get(name)

    def is_warm(self, name: str) -> bool:
        with self._lock:
            return name in self._cache

    def age(self, name: str) -> float:
        """How old is the cached JWKS in seconds."""
        with self._lock:
            fetched = self._fetched_at.get(name, 0)
            return time.time() - fetched if fetched else float("inf")

    def start_refresh(self, fetcher: Callable[[str], Optional[dict]]):
        """Start background refresh thread."""
        if self._running:
            return
        self._running = True
        self._worker = threading.Thread(
            target=self._refresh_loop, args=(fetcher,), daemon=True
        )
        self._worker.start()

    def stop_refresh(self):
        self._running = False
        if self._worker:
            self._worker.join(timeout=2)

    def _refresh_loop(self, fetcher):
        while self._running:
            time.sleep(self._refresh_interval)
            if not self._running:
                break
            self.warm_all(fetcher)

    @property
    def stats(self) -> dict:
        with self._lock:
            return {
                "providers": list(self._providers.keys()),
                "cached": list(self._cache.keys()),
                "ages": {
                    name: round(time.time() - ts, 1)
                    for name, ts in self._fetched_at.items()
                },
            }


# ═══════════════════════════════════════════════════════════════════
# 4. OPT-OIDC-02 — TOKEN REPLAY PROTECTION
# ═══════════════════════════════════════════════════════════════════

class TokenReplayProtector:
    """
    Prevents OIDC token replay attacks.

    Tracks the jti (JWT ID) of every exchanged token.
    If the same jti is presented again, the exchange is rejected.

    The cache has a TTL matching the token expiration —
    once a token would have expired naturally, its jti is pruned.

    Usage:
        protector = TokenReplayProtector()

        # Before exchanging an OIDC token:
        if not protector.check_and_record(jti="abc-123", expires_at=1711324800):
            raise SecurityError("Token replay detected")

        # Second use of same token → blocked
        assert protector.check_and_record(jti="abc-123", expires_at=1711324800) is False
    """

    def __init__(self, max_entries: int = 100000):
        self._seen: dict[str, float] = {}  # jti → expires_at_unix
        self._max = max_entries
        self._lock = threading.Lock()

    def check_and_record(self, jti: str, expires_at: float) -> bool:
        """
        Check if a token jti has been seen before.

        Returns True if the token is NEW (allowed).
        Returns False if the token is a REPLAY (blocked).
        """
        if not jti:
            return False  # No jti = cannot protect, reject

        with self._lock:
            # Prune expired entries periodically
            if len(self._seen) > self._max * 0.9:
                self._prune()

            if jti in self._seen:
                return False  # REPLAY

            self._seen[jti] = expires_at
            return True  # NEW

    def is_replay(self, jti: str) -> bool:
        with self._lock:
            return jti in self._seen

    def _prune(self):
        """Remove expired entries."""
        now = time.time()
        expired = [jti for jti, exp in self._seen.items() if exp < now]
        for jti in expired:
            del self._seen[jti]

    @property
    def tracked_count(self) -> int:
        with self._lock:
            return len(self._seen)

    def clear(self):
        with self._lock:
            self._seen.clear()


# ═══════════════════════════════════════════════════════════════════
# 5. OPT-GDPR-04 — PII ACCESS AUDIT
# ═══════════════════════════════════════════════════════════════════

@dataclass
class PIIAccessEvent:
    """Record of a PII data access event."""
    event_id: str
    org_id: str
    operation: str       # encrypt, decrypt, shred, export, pii_scan
    field_name: str = ""
    timestamp: str = ""
    actor: str = ""      # Who triggered the operation (passport_id or "system")
    success: bool = True
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "org_id": self.org_id,
            "operation": self.operation,
            "field_name": self.field_name,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "success": self.success,
            "detail": self.detail,
        }


class PIIAccessAuditor:
    """
    Audits every access to PII-related operations.

    Required for CNIL/DPO audits — proves who accessed, encrypted,
    decrypted, or shredded personal data.

    Usage:
        auditor = PIIAccessAuditor()

        # Record an encryption
        auditor.record("org-acme", "encrypt", field_name="email", actor="system")

        # Record a shred
        auditor.record("org-acme", "shred", actor="urn:aib:agent:acme:admin")

        # Export audit trail for DPO
        events = auditor.query(org_id="org-acme", operation="shred")
    """

    def __init__(self):
        self._events: list[PIIAccessEvent] = []
        self._lock = threading.Lock()

    def record(
        self,
        org_id: str,
        operation: str,
        field_name: str = "",
        actor: str = "system",
        success: bool = True,
        detail: str = "",
    ) -> PIIAccessEvent:
        event = PIIAccessEvent(
            event_id=f"pii_{uuid.uuid4().hex[:12]}",
            org_id=org_id,
            operation=operation,
            field_name=field_name,
            timestamp=datetime.now(timezone.utc).isoformat(),
            actor=actor,
            success=success,
            detail=detail,
        )
        with self._lock:
            self._events.append(event)
        return event

    def query(
        self,
        org_id: Optional[str] = None,
        operation: Optional[str] = None,
        actor: Optional[str] = None,
        limit: int = 100,
    ) -> list[PIIAccessEvent]:
        with self._lock:
            results = []
            for e in reversed(self._events):
                if org_id and e.org_id != org_id:
                    continue
                if operation and e.operation != operation:
                    continue
                if actor and e.actor != actor:
                    continue
                results.append(e)
                if len(results) >= limit:
                    break
            return results

    def count(self, org_id: Optional[str] = None) -> int:
        with self._lock:
            if org_id:
                return sum(1 for e in self._events if e.org_id == org_id)
            return len(self._events)

    def export_for_dpo(self, org_id: str) -> dict:
        """Export audit trail for Data Protection Officer."""
        events = self.query(org_id=org_id, limit=10000)
        ops_count = {}
        for e in events:
            ops_count[e.operation] = ops_count.get(e.operation, 0) + 1

        return {
            "org_id": org_id,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "total_events": len(events),
            "operations_summary": ops_count,
            "events": [e.to_dict() for e in events],
        }
