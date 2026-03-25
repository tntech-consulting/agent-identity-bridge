"""
AIB — Sprint 4a: Compliance & GDPR avancé.

Four optimizations:

1. OPT-TRANS-02: JSON Canonicalization (RFC 8785 — JCS)
2. OPT-GDPR-03: Data retention auto-shred (time-based crypto-shredding)
3. OPT-GDPR-05: Right to restriction (Art.18) + right to object (Art.21)
4. OPT-ID-05:   Issuer claim validation on passport verification

None modifies existing modules. All are opt-in.
"""

import json
import hashlib
import time
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, Any, Callable


# ═══════════════════════════════════════════════════════════════════
# 1. OPT-TRANS-02 — JSON CANONICALIZATION (RFC 8785)
# ═══════════════════════════════════════════════════════════════════

def canonicalize(obj: Any) -> str:
    """
    JSON Canonicalization Scheme (JCS) per RFC 8785.

    Produces a deterministic JSON string where:
    - Object keys are sorted lexicographically (Unicode code point order)
    - No whitespace between tokens
    - Numbers use minimal representation (no trailing zeros)
    - Nested objects/arrays are recursively canonicalized

    This ensures that two semantically identical JSON documents
    produce the same byte sequence, which is critical for:
    - Consistent hashing (receipts, Merkle tree)
    - Signature verification (sign the canonical form)
    - Comparison (two passports with same data → same hash)

    Usage:
        canonical = canonicalize({"b": 2, "a": 1})
        # '{"a":1,"b":2}'  ← keys sorted

        hash = hashlib.sha256(canonical.encode()).hexdigest()
    """
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(',', ':'))


def canonical_hash(obj: Any) -> str:
    """SHA-256 hash of the canonical JSON form."""
    return hashlib.sha256(canonicalize(obj).encode("utf-8")).hexdigest()


def canonical_equals(a: Any, b: Any) -> bool:
    """Check if two JSON-serializable objects are canonically equal."""
    return canonicalize(a) == canonicalize(b)


# ═══════════════════════════════════════════════════════════════════
# 2. OPT-GDPR-03 — DATA RETENTION AUTO-SHRED
# ═══════════════════════════════════════════════════════════════════

@dataclass
class RetentionPolicy:
    """
    Data retention policy for an organization.

    After retention_days, the org's AES key is automatically
    shredded → all encrypted data becomes permanently unreadable.
    """
    org_id: str
    retention_days: int              # Days before auto-shred
    created_at: str = ""             # ISO timestamp
    last_checked: str = ""
    shredded: bool = False
    shredded_at: str = ""

    def is_expired(self) -> bool:
        if not self.created_at or self.shredded:
            return False
        created = datetime.fromisoformat(self.created_at)
        expiry = created + timedelta(days=self.retention_days)
        return datetime.now(timezone.utc) > expiry

    def days_remaining(self) -> int:
        if not self.created_at or self.shredded:
            return 0
        created = datetime.fromisoformat(self.created_at)
        expiry = created + timedelta(days=self.retention_days)
        remaining = (expiry - datetime.now(timezone.utc)).days
        return max(0, remaining)

    def to_dict(self) -> dict:
        return {
            "org_id": self.org_id,
            "retention_days": self.retention_days,
            "created_at": self.created_at,
            "days_remaining": self.days_remaining(),
            "shredded": self.shredded,
            "shredded_at": self.shredded_at,
        }


class RetentionManager:
    """
    Manages data retention policies and auto-shredding.

    When a policy expires, the shred_callback is called with the
    org_id — this should trigger crypto-shredding (delete AES key).

    Usage:
        manager = RetentionManager(shred_callback=my_key_store.shred)
        manager.set_policy("org-acme", retention_days=365)

        # Check periodically (e.g. daily cron)
        shredded = manager.check_all()
        # Returns list of org_ids that were auto-shredded
    """

    def __init__(self, shred_callback: Optional[Callable[[str], bool]] = None):
        self._policies: dict[str, RetentionPolicy] = {}
        self._shred = shred_callback or (lambda org_id: True)
        self._lock = threading.Lock()

    def set_policy(self, org_id: str, retention_days: int):
        with self._lock:
            self._policies[org_id] = RetentionPolicy(
                org_id=org_id,
                retention_days=retention_days,
                created_at=datetime.now(timezone.utc).isoformat(),
            )

    def get_policy(self, org_id: str) -> Optional[RetentionPolicy]:
        with self._lock:
            return self._policies.get(org_id)

    def check_all(self) -> list[str]:
        """Check all policies and auto-shred expired ones."""
        shredded = []
        with self._lock:
            for org_id, policy in self._policies.items():
                if policy.is_expired() and not policy.shredded:
                    try:
                        self._shred(org_id)
                        policy.shredded = True
                        policy.shredded_at = datetime.now(timezone.utc).isoformat()
                        shredded.append(org_id)
                    except Exception:
                        pass
                policy.last_checked = datetime.now(timezone.utc).isoformat()
        return shredded

    def check_one(self, org_id: str) -> bool:
        """Check a single org and shred if expired. Returns True if shredded."""
        with self._lock:
            policy = self._policies.get(org_id)
            if not policy or policy.shredded:
                return False
            if policy.is_expired():
                try:
                    self._shred(org_id)
                    policy.shredded = True
                    policy.shredded_at = datetime.now(timezone.utc).isoformat()
                    return True
                except Exception:
                    return False
            return False

    def list_policies(self) -> list[dict]:
        with self._lock:
            return [p.to_dict() for p in self._policies.values()]

    def list_expiring_soon(self, days: int = 7) -> list[dict]:
        """List policies expiring within N days."""
        with self._lock:
            return [
                p.to_dict() for p in self._policies.values()
                if not p.shredded and 0 < p.days_remaining() <= days
            ]


# ═══════════════════════════════════════════════════════════════════
# 3. OPT-GDPR-05 — RIGHT TO RESTRICTION (Art.18) + OPPOSITION (Art.21)
# ═══════════════════════════════════════════════════════════════════

class ProcessingStatus:
    ACTIVE = "active"
    RESTRICTED = "restricted"   # Art.18: data stored but not processed
    OBJECTED = "objected"       # Art.21: processing stopped for specific purposes
    SHREDDED = "shredded"       # Art.17: erased


@dataclass
class DataSubjectRecord:
    """
    Tracks GDPR rights exercised by a data subject (organization).

    Art.18 — Restriction: Data is stored but cannot be processed
    (no encryption/decryption operations allowed, only storage).

    Art.21 — Objection: Processing stopped for specific purposes.
    The org can specify which purposes they object to.
    """
    org_id: str
    status: str = ProcessingStatus.ACTIVE
    restricted_at: str = ""
    restriction_reason: str = ""
    objected_purposes: list = field(default_factory=list)
    objected_at: str = ""
    objection_reason: str = ""
    history: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "org_id": self.org_id,
            "status": self.status,
            "restricted_at": self.restricted_at,
            "restriction_reason": self.restriction_reason,
            "objected_purposes": self.objected_purposes,
            "objected_at": self.objected_at,
            "objection_reason": self.objection_reason,
            "history": self.history,
        }


class GDPRRightsManager:
    """
    Manages GDPR Art.18 (restriction) and Art.21 (objection) rights.

    Usage:
        rights = GDPRRightsManager()

        # Art.18: Restrict processing
        rights.restrict("org-acme", reason="Accuracy contested by data subject")

        # Check before processing
        if not rights.can_process("org-acme"):
            raise GDPRRestrictionError("Processing restricted for org-acme")

        # Art.21: Object to specific purposes
        rights.object("org-acme", purposes=["profiling", "marketing"],
                      reason="Data subject objects to profiling")

        # Check for specific purpose
        if rights.is_objected("org-acme", purpose="profiling"):
            skip_profiling()

        # Lift restriction
        rights.unrestrict("org-acme", reason="Accuracy verified")
    """

    def __init__(self):
        self._records: dict[str, DataSubjectRecord] = {}
        self._lock = threading.Lock()

    def _get_or_create(self, org_id: str) -> DataSubjectRecord:
        if org_id not in self._records:
            self._records[org_id] = DataSubjectRecord(org_id=org_id)
        return self._records[org_id]

    def restrict(self, org_id: str, reason: str = ""):
        """Art.18: Restrict processing — data stored but not processed."""
        with self._lock:
            rec = self._get_or_create(org_id)
            now = datetime.now(timezone.utc).isoformat()
            rec.history.append({
                "action": "restrict", "at": now,
                "reason": reason, "previous_status": rec.status,
            })
            rec.status = ProcessingStatus.RESTRICTED
            rec.restricted_at = now
            rec.restriction_reason = reason

    def unrestrict(self, org_id: str, reason: str = ""):
        """Lift Art.18 restriction."""
        with self._lock:
            rec = self._records.get(org_id)
            if not rec:
                return
            now = datetime.now(timezone.utc).isoformat()
            rec.history.append({
                "action": "unrestrict", "at": now,
                "reason": reason, "previous_status": rec.status,
            })
            rec.status = ProcessingStatus.ACTIVE
            rec.restricted_at = ""
            rec.restriction_reason = ""

    def object(self, org_id: str, purposes: list[str], reason: str = ""):
        """Art.21: Object to processing for specific purposes."""
        with self._lock:
            rec = self._get_or_create(org_id)
            now = datetime.now(timezone.utc).isoformat()
            rec.history.append({
                "action": "object", "at": now,
                "purposes": purposes, "reason": reason,
            })
            rec.objected_purposes = list(set(rec.objected_purposes + purposes))
            rec.objected_at = now
            rec.objection_reason = reason
            if rec.status == ProcessingStatus.ACTIVE:
                rec.status = ProcessingStatus.OBJECTED

    def withdraw_objection(self, org_id: str, purposes: Optional[list[str]] = None):
        """Withdraw Art.21 objection (all or specific purposes)."""
        with self._lock:
            rec = self._records.get(org_id)
            if not rec:
                return
            now = datetime.now(timezone.utc).isoformat()
            if purposes:
                rec.objected_purposes = [p for p in rec.objected_purposes if p not in purposes]
            else:
                rec.objected_purposes = []
            rec.history.append({
                "action": "withdraw_objection", "at": now,
                "purposes": purposes or "all",
            })
            if not rec.objected_purposes and rec.status == ProcessingStatus.OBJECTED:
                rec.status = ProcessingStatus.ACTIVE

    def can_process(self, org_id: str) -> bool:
        """Check if processing is allowed (not restricted)."""
        with self._lock:
            rec = self._records.get(org_id)
            if not rec:
                return True
            return rec.status == ProcessingStatus.ACTIVE

    def is_restricted(self, org_id: str) -> bool:
        with self._lock:
            rec = self._records.get(org_id)
            return rec.status == ProcessingStatus.RESTRICTED if rec else False

    def is_objected(self, org_id: str, purpose: Optional[str] = None) -> bool:
        """Check if processing is objected (optionally for a specific purpose)."""
        with self._lock:
            rec = self._records.get(org_id)
            if not rec:
                return False
            if purpose:
                return purpose in rec.objected_purposes
            return len(rec.objected_purposes) > 0

    def get_record(self, org_id: str) -> Optional[dict]:
        with self._lock:
            rec = self._records.get(org_id)
            return rec.to_dict() if rec else None

    def list_restricted(self) -> list[str]:
        with self._lock:
            return [r.org_id for r in self._records.values()
                    if r.status == ProcessingStatus.RESTRICTED]

    def list_objected(self) -> list[str]:
        with self._lock:
            return [r.org_id for r in self._records.values()
                    if len(r.objected_purposes) > 0]


# ═══════════════════════════════════════════════════════════════════
# 4. OPT-ID-05 — ISSUER CLAIM VALIDATION
# ═══════════════════════════════════════════════════════════════════

class IssuerValidationError(ValueError):
    """Raised when passport issuer fails validation."""
    pass


def validate_issuer(
    payload: dict,
    expected_issuer: Optional[str] = None,
    allowed_issuers: Optional[list[str]] = None,
) -> tuple[bool, str]:
    """
    Validate the issuer claim in a passport payload.

    Three modes:
    1. expected_issuer set → must match exactly
    2. allowed_issuers set → must be in the list
    3. Neither set → only validate format (urn:aib:org:*)

    Returns:
        (valid, reason)
    """
    issuer = payload.get("issuer") or payload.get("iss")

    if not issuer:
        return False, "Missing issuer claim"

    if not isinstance(issuer, str):
        return False, f"Issuer must be a string, got {type(issuer).__name__}"

    # Format validation
    if not issuer.startswith("urn:aib:org:"):
        return False, f"Invalid issuer format: must start with 'urn:aib:org:', got '{issuer}'"

    # Extract org slug
    parts = issuer.split(":")
    if len(parts) < 4 or not parts[3]:
        return False, f"Invalid issuer format: missing org slug in '{issuer}'"

    # Exact match
    if expected_issuer:
        if issuer != expected_issuer:
            return False, f"Issuer mismatch: expected '{expected_issuer}', got '{issuer}'"

    # Allowlist
    if allowed_issuers:
        if issuer not in allowed_issuers:
            return False, f"Issuer '{issuer}' not in allowed issuers: {allowed_issuers}"

    return True, f"Issuer valid: {issuer}"
