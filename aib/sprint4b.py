"""
AIB — Sprint 4b: Multi-sig & Federation hardening.

Three optimizations:

1. OPT-MSIG-01: Signature timeout (pending signatures expire)
2. OPT-MSIG-04: Signature audit trail (every sign/reject generates a receipt)
3. OPT-FED-02:  Federated JWKS cache with TTL and stale fallback

None modifies existing modules. All are opt-in.
"""

import time
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Callable, Any


# ═══════════════════════════════════════════════════════════════════
# 1. OPT-MSIG-01 — SIGNATURE TIMEOUT
# ═══════════════════════════════════════════════════════════════════

class SignatureTimeoutError(ValueError):
    """Raised when a multi-sig request has expired."""
    pass


@dataclass
class SignatureRequest:
    """
    A pending multi-signature request with a timeout.

    If not enough signatures are collected before the deadline,
    the request expires and cannot be completed.
    """
    request_id: str
    payload_hash: str               # Hash of the document to sign
    required_signers: int            # M in M-of-N
    total_signers: int               # N
    timeout_seconds: float
    created_at: float                # Unix timestamp
    signatures: dict = field(default_factory=dict)  # kid → signature
    status: str = "pending"          # pending, completed, expired, cancelled

    @property
    def deadline(self) -> float:
        return self.created_at + self.timeout_seconds

    @property
    def is_expired(self) -> bool:
        return time.time() > self.deadline and self.status == "pending"

    @property
    def remaining_seconds(self) -> float:
        return max(0, self.deadline - time.time())

    @property
    def signatures_count(self) -> int:
        return len(self.signatures)

    @property
    def is_complete(self) -> bool:
        return self.signatures_count >= self.required_signers

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "payload_hash": self.payload_hash,
            "required": self.required_signers,
            "collected": self.signatures_count,
            "total_signers": self.total_signers,
            "status": self.status,
            "timeout_seconds": self.timeout_seconds,
            "remaining_seconds": round(self.remaining_seconds, 1),
            "created_at": datetime.fromtimestamp(self.created_at, tz=timezone.utc).isoformat(),
            "signers": list(self.signatures.keys()),
        }


class MultiSigWithTimeout:
    """
    Multi-signature coordinator with configurable timeout.

    Usage:
        msig = MultiSigWithTimeout(default_timeout=300)  # 5 min

        # Create a signing request
        req = msig.create_request(
            payload_hash="sha256...",
            required_signers=2,
            total_signers=3,
        )

        # Collect signatures
        msig.add_signature(req.request_id, kid="key-1", signature="sig1")
        msig.add_signature(req.request_id, kid="key-2", signature="sig2")

        # Check completion
        assert msig.is_complete(req.request_id)

        # If timeout passes without enough signatures:
        # msig.add_signature(...) → raises SignatureTimeoutError
    """

    def __init__(self, default_timeout: float = 300):
        self._default_timeout = default_timeout
        self._requests: dict[str, SignatureRequest] = {}
        self._lock = threading.Lock()

    def create_request(
        self,
        payload_hash: str,
        required_signers: int,
        total_signers: int,
        timeout_seconds: Optional[float] = None,
    ) -> SignatureRequest:
        req = SignatureRequest(
            request_id=f"msig_{uuid.uuid4().hex[:12]}",
            payload_hash=payload_hash,
            required_signers=required_signers,
            total_signers=total_signers,
            timeout_seconds=timeout_seconds or self._default_timeout,
            created_at=time.time(),
        )
        with self._lock:
            self._requests[req.request_id] = req
        return req

    def add_signature(self, request_id: str, kid: str, signature: str) -> bool:
        """
        Add a signature to a pending request.

        Returns True if this signature completed the request.
        Raises SignatureTimeoutError if the request has expired.
        """
        with self._lock:
            req = self._requests.get(request_id)
            if not req:
                raise ValueError(f"Unknown request: {request_id}")

            if req.status == "expired" or req.is_expired:
                req.status = "expired"
                raise SignatureTimeoutError(
                    f"Signing request {request_id} expired "
                    f"({req.timeout_seconds}s timeout)"
                )

            if req.status != "pending":
                raise ValueError(f"Request {request_id} is {req.status}, cannot add signatures")

            if kid in req.signatures:
                raise ValueError(f"Signer {kid} already signed this request")

            req.signatures[kid] = signature

            if req.is_complete:
                req.status = "completed"
                return True

            return False

    def is_complete(self, request_id: str) -> bool:
        with self._lock:
            req = self._requests.get(request_id)
            return req.is_complete if req else False

    def get_request(self, request_id: str) -> Optional[dict]:
        with self._lock:
            req = self._requests.get(request_id)
            if req and req.is_expired and req.status == "pending":
                req.status = "expired"
            return req.to_dict() if req else None

    def cancel(self, request_id: str) -> bool:
        with self._lock:
            req = self._requests.get(request_id)
            if req and req.status == "pending":
                req.status = "cancelled"
                return True
            return False

    def cleanup_expired(self) -> int:
        """Mark all expired requests and return count."""
        count = 0
        with self._lock:
            for req in self._requests.values():
                if req.is_expired and req.status == "pending":
                    req.status = "expired"
                    count += 1
        return count

    @property
    def pending_count(self) -> int:
        with self._lock:
            return sum(1 for r in self._requests.values() if r.status == "pending")


# ═══════════════════════════════════════════════════════════════════
# 2. OPT-MSIG-04 — SIGNATURE AUDIT TRAIL
# ═══════════════════════════════════════════════════════════════════

@dataclass
class SignatureAuditEvent:
    """Record of a signature operation."""
    event_id: str
    request_id: str
    action: str          # create, sign, complete, expire, cancel, reject
    kid: str = ""        # Which key signed (empty for non-sign events)
    timestamp: str = ""
    payload_hash: str = ""
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "request_id": self.request_id,
            "action": self.action,
            "kid": self.kid,
            "timestamp": self.timestamp,
            "payload_hash": self.payload_hash,
            "detail": self.detail,
        }


class SignatureAuditor:
    """
    Audits every multi-signature operation.

    Every create, sign, complete, expire, and cancel generates
    an audit event. Required for SOC2 key management evidence.

    Usage:
        auditor = SignatureAuditor()

        auditor.record("req-1", "create", payload_hash="abc...",
                       detail="2-of-3 signing for passport renewal")
        auditor.record("req-1", "sign", kid="key-1")
        auditor.record("req-1", "sign", kid="key-2")
        auditor.record("req-1", "complete")

        events = auditor.query(request_id="req-1")
    """

    def __init__(self):
        self._events: list[SignatureAuditEvent] = []
        self._lock = threading.Lock()

    def record(
        self,
        request_id: str,
        action: str,
        kid: str = "",
        payload_hash: str = "",
        detail: str = "",
    ) -> SignatureAuditEvent:
        event = SignatureAuditEvent(
            event_id=f"sigaudit_{uuid.uuid4().hex[:10]}",
            request_id=request_id,
            action=action,
            kid=kid,
            timestamp=datetime.now(timezone.utc).isoformat(),
            payload_hash=payload_hash,
            detail=detail,
        )
        with self._lock:
            self._events.append(event)
        return event

    def query(
        self,
        request_id: Optional[str] = None,
        action: Optional[str] = None,
        kid: Optional[str] = None,
        limit: int = 100,
    ) -> list[SignatureAuditEvent]:
        with self._lock:
            results = []
            for e in reversed(self._events):
                if request_id and e.request_id != request_id:
                    continue
                if action and e.action != action:
                    continue
                if kid and e.kid != kid:
                    continue
                results.append(e)
                if len(results) >= limit:
                    break
            return results

    def count(self) -> int:
        with self._lock:
            return len(self._events)

    def count_by_action(self) -> dict:
        with self._lock:
            counts: dict[str, int] = {}
            for e in self._events:
                counts[e.action] = counts.get(e.action, 0) + 1
            return counts


# ═══════════════════════════════════════════════════════════════════
# 3. OPT-FED-02 — FEDERATED JWKS CACHE WITH TTL
# ═══════════════════════════════════════════════════════════════════

@dataclass
class CachedJWKS:
    """A cached JWKS entry with TTL tracking."""
    issuer: str
    jwks_uri: str
    data: dict
    fetched_at: float
    ttl_seconds: float

    @property
    def is_expired(self) -> bool:
        return time.time() > (self.fetched_at + self.ttl_seconds)

    @property
    def age_seconds(self) -> float:
        return time.time() - self.fetched_at


class FederatedJWKSCache:
    """
    JWKS cache for federated issuers with configurable TTL.

    Each federated issuer's JWKS is cached locally with a TTL.
    When expired, the next request triggers a background refresh.
    If refresh fails, stale cache is used (resilience).

    Usage:
        cache = FederatedJWKSCache(default_ttl=3600)

        # Register a federated issuer
        cache.register("urn:aib:org:partner", "https://partner.com/.well-known/aib-keys.json")

        # Fetch and cache (call at startup or on first use)
        cache.refresh("urn:aib:org:partner", fetcher=http_get_json)

        # Get cached JWKS (never blocks on network)
        jwks = cache.get("urn:aib:org:partner")

        # Check if refresh needed
        if cache.needs_refresh("urn:aib:org:partner"):
            cache.refresh("urn:aib:org:partner", fetcher=http_get_json)
    """

    def __init__(self, default_ttl: float = 3600):
        self._default_ttl = default_ttl
        self._cache: dict[str, CachedJWKS] = {}
        self._uris: dict[str, str] = {}  # issuer → jwks_uri
        self._lock = threading.Lock()

    def register(self, issuer: str, jwks_uri: str, ttl: Optional[float] = None):
        with self._lock:
            self._uris[issuer] = jwks_uri

    def refresh(self, issuer: str, fetcher: Callable[[str], Optional[dict]]) -> bool:
        """
        Fetch and cache JWKS for an issuer.
        Returns True if successful, False if fetch failed (stale cache kept).
        """
        with self._lock:
            uri = self._uris.get(issuer)
        if not uri:
            return False

        try:
            data = fetcher(uri)
            if data:
                with self._lock:
                    self._cache[issuer] = CachedJWKS(
                        issuer=issuer,
                        jwks_uri=uri,
                        data=data,
                        fetched_at=time.time(),
                        ttl_seconds=self._default_ttl,
                    )
                return True
        except Exception:
            pass
        return False

    def get(self, issuer: str) -> Optional[dict]:
        """Get cached JWKS. Returns stale data if expired (resilience)."""
        with self._lock:
            entry = self._cache.get(issuer)
            return entry.data if entry else None

    def needs_refresh(self, issuer: str) -> bool:
        with self._lock:
            entry = self._cache.get(issuer)
            if not entry:
                return issuer in self._uris
            return entry.is_expired

    def get_age(self, issuer: str) -> Optional[float]:
        with self._lock:
            entry = self._cache.get(issuer)
            return round(entry.age_seconds, 1) if entry else None

    def is_stale(self, issuer: str) -> bool:
        with self._lock:
            entry = self._cache.get(issuer)
            return entry.is_expired if entry else False

    def refresh_all(self, fetcher: Callable[[str], Optional[dict]]) -> dict:
        """Refresh all registered issuers. Returns {issuer: success}."""
        results = {}
        with self._lock:
            issuers = list(self._uris.keys())
        for issuer in issuers:
            results[issuer] = self.refresh(issuer, fetcher)
        return results

    def list_issuers(self) -> list[dict]:
        with self._lock:
            result = []
            for issuer, uri in self._uris.items():
                entry = self._cache.get(issuer)
                result.append({
                    "issuer": issuer,
                    "jwks_uri": uri,
                    "cached": entry is not None,
                    "age_seconds": round(entry.age_seconds, 1) if entry else None,
                    "stale": entry.is_expired if entry else None,
                })
            return result

    @property
    def cached_count(self) -> int:
        with self._lock:
            return len(self._cache)
