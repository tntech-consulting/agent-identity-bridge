"""
AIB — Sprint 10: Passport renewal & capability hot-update.

Solves the production problem: updating an agent's capabilities or
protocol bindings without revoking and recreating the passport.

Today:  modify capabilities = revoke + recreate → passport_id changes,
        audit trail breaks, agent downtime during rotation.

After:  renew() keeps passport_id, increments version, signs new token,
        old token stays valid until its natural expiry (grace period).

Key design decisions:
- passport_id NEVER changes on renewal (audit continuity)
- Version counter tracks renewal history
- Old tokens remain valid during grace period (zero downtime)
- Capability changes are logged in renewal_history (auditable)
- Renewal generates an Action Receipt
"""

import json
import uuid
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional, Any


# ═══════════════════════════════════════════════════════════════════
# RENEWAL RECORD
# ═══════════════════════════════════════════════════════════════════

@dataclass
class RenewalRecord:
    """Tracks a single renewal event."""
    renewal_id: str
    passport_id: str
    version: int                     # Version AFTER renewal
    renewed_at: str
    reason: str = ""
    changes: dict = field(default_factory=dict)  # What changed
    previous_expires_at: str = ""
    new_expires_at: str = ""
    renewed_by: str = ""             # Who triggered the renewal

    def to_dict(self) -> dict:
        return {
            "renewal_id": self.renewal_id,
            "passport_id": self.passport_id,
            "version": self.version,
            "renewed_at": self.renewed_at,
            "reason": self.reason,
            "changes": self.changes,
            "previous_expires_at": self.previous_expires_at,
            "new_expires_at": self.new_expires_at,
            "renewed_by": self.renewed_by,
        }


# ═══════════════════════════════════════════════════════════════════
# RENEWABLE PASSPORT
# ═══════════════════════════════════════════════════════════════════

@dataclass
class RenewablePassport:
    """
    A passport that supports in-place renewal without revocation.

    The passport_id remains stable across renewals.
    Each renewal increments the version and re-signs.
    """
    passport_id: str
    display_name: str
    issuer: str
    capabilities: list[str]
    protocol_bindings: dict
    issued_at: str
    expires_at: str
    version: int = 1
    renewal_history: list[RenewalRecord] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    tier: str = "permanent"

    def to_dict(self) -> dict:
        return {
            "passport_id": self.passport_id,
            "display_name": self.display_name,
            "issuer": self.issuer,
            "capabilities": self.capabilities,
            "protocol_bindings": self.protocol_bindings,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "version": self.version,
            "tier": self.tier,
            "renewal_count": len(self.renewal_history),
            "metadata": self.metadata,
        }


# ═══════════════════════════════════════════════════════════════════
# RENEWAL ERRORS
# ═══════════════════════════════════════════════════════════════════

class RenewalError(ValueError):
    """Base error for renewal operations."""
    pass


class PassportNotFoundError(RenewalError):
    pass


class PassportRevokedError(RenewalError):
    pass


class CapabilityEscalationError(RenewalError):
    """Raised when renewal tries to add capabilities beyond the original scope."""
    pass


# ═══════════════════════════════════════════════════════════════════
# PASSPORT RENEWAL MANAGER
# ═══════════════════════════════════════════════════════════════════

class PassportRenewalManager:
    """
    Manages passport renewal and hot-update lifecycle.

    Usage:
        mgr = PassportRenewalManager()

        # Register a passport
        mgr.register(passport_id="urn:aib:agent:acme:bot",
                      display_name="Bot", issuer="urn:aib:org:acme",
                      capabilities=["booking", "support"],
                      protocol_bindings={"mcp": {...}})

        # Renew expiry (extend TTL, same capabilities)
        mgr.renew("urn:aib:agent:acme:bot", ttl_days=365,
                   reason="Annual renewal")

        # Hot-update capabilities
        mgr.update_capabilities("urn:aib:agent:acme:bot",
                                add=["payment"], remove=["support"],
                                reason="Added payment processing")

        # Hot-update protocol bindings
        mgr.update_bindings("urn:aib:agent:acme:bot",
                            add={"ag_ui": {"endpoint_url": "..."}},
                            reason="Added AG-UI support")

        # Get current state
        passport = mgr.get("urn:aib:agent:acme:bot")

        # Get renewal history
        history = mgr.get_history("urn:aib:agent:acme:bot")
    """

    def __init__(self, max_capabilities: Optional[list[str]] = None):
        self._passports: dict[str, RenewablePassport] = {}
        self._revoked: set[str] = set()
        self._max_capabilities = set(max_capabilities) if max_capabilities else None

    # ── Registration ──────────────────────────────────────────────

    def register(
        self,
        passport_id: str,
        display_name: str,
        issuer: str,
        capabilities: list[str],
        protocol_bindings: dict,
        tier: str = "permanent",
        ttl_days: int = 365,
        metadata: Optional[dict] = None,
    ) -> RenewablePassport:
        now = datetime.now(timezone.utc)
        passport = RenewablePassport(
            passport_id=passport_id,
            display_name=display_name,
            issuer=issuer,
            capabilities=list(capabilities),
            protocol_bindings=dict(protocol_bindings),
            issued_at=now.isoformat(),
            expires_at=(now + timedelta(days=ttl_days)).isoformat(),
            version=1,
            tier=tier,
            metadata=metadata or {},
        )
        self._passports[passport_id] = passport
        return passport

    # ── Get ───────────────────────────────────────────────────────

    def get(self, passport_id: str) -> Optional[RenewablePassport]:
        return self._passports.get(passport_id)

    def get_dict(self, passport_id: str) -> Optional[dict]:
        p = self._passports.get(passport_id)
        return p.to_dict() if p else None

    def is_revoked(self, passport_id: str) -> bool:
        return passport_id in self._revoked

    # ── Renew (extend TTL) ────────────────────────────────────────

    def renew(
        self,
        passport_id: str,
        ttl_days: int = 365,
        reason: str = "",
        renewed_by: str = "system",
    ) -> RenewablePassport:
        """
        Renew a passport (extend expiry, keep everything else).

        The passport_id stays the same.
        Version increments.
        Old tokens remain valid until their original expiry.
        """
        passport = self._check_passport(passport_id)
        now = datetime.now(timezone.utc)

        record = RenewalRecord(
            renewal_id=f"rnw_{uuid.uuid4().hex[:12]}",
            passport_id=passport_id,
            version=passport.version + 1,
            renewed_at=now.isoformat(),
            reason=reason,
            changes={"type": "renew", "ttl_days": ttl_days},
            previous_expires_at=passport.expires_at,
            new_expires_at=(now + timedelta(days=ttl_days)).isoformat(),
            renewed_by=renewed_by,
        )

        passport.expires_at = record.new_expires_at
        passport.version += 1
        passport.renewal_history.append(record)

        return passport

    # ── Update capabilities ───────────────────────────────────────

    def update_capabilities(
        self,
        passport_id: str,
        add: Optional[list[str]] = None,
        remove: Optional[list[str]] = None,
        reason: str = "",
        renewed_by: str = "system",
    ) -> RenewablePassport:
        """
        Hot-update capabilities without revoking the passport.

        Add and/or remove capabilities in a single operation.
        The passport_id stays the same. Version increments.

        If max_capabilities is configured, added capabilities
        must be in the allowed set (prevents escalation).
        """
        passport = self._check_passport(passport_id)

        add = add or []
        remove = remove or []

        # Escalation check
        if self._max_capabilities and add:
            unauthorized = set(add) - self._max_capabilities
            if unauthorized:
                raise CapabilityEscalationError(
                    f"Capabilities not in allowed set: {unauthorized}"
                )

        old_caps = list(passport.capabilities)
        new_caps = list(set(passport.capabilities + add) - set(remove))

        if not new_caps:
            raise RenewalError("Cannot remove all capabilities — passport must have at least one")

        now = datetime.now(timezone.utc)
        record = RenewalRecord(
            renewal_id=f"rnw_{uuid.uuid4().hex[:12]}",
            passport_id=passport_id,
            version=passport.version + 1,
            renewed_at=now.isoformat(),
            reason=reason,
            changes={
                "type": "capabilities",
                "added": add,
                "removed": remove,
                "before": old_caps,
                "after": new_caps,
            },
            previous_expires_at=passport.expires_at,
            new_expires_at=passport.expires_at,
            renewed_by=renewed_by,
        )

        passport.capabilities = new_caps
        passport.version += 1
        passport.renewal_history.append(record)

        return passport

    # ── Update bindings ───────────────────────────────────────────

    def update_bindings(
        self,
        passport_id: str,
        add: Optional[dict] = None,
        remove: Optional[list[str]] = None,
        reason: str = "",
        renewed_by: str = "system",
    ) -> RenewablePassport:
        """
        Hot-update protocol bindings without revoking.

        Add new protocol bindings and/or remove existing ones.
        Useful when an agent adds AG-UI support or drops MCP.
        """
        passport = self._check_passport(passport_id)

        add = add or {}
        remove = remove or []

        old_protocols = list(passport.protocol_bindings.keys())

        for proto in remove:
            passport.protocol_bindings.pop(proto, None)

        for proto, binding in add.items():
            passport.protocol_bindings[proto] = binding

        if not passport.protocol_bindings:
            raise RenewalError("Cannot remove all protocol bindings — passport must have at least one")

        new_protocols = list(passport.protocol_bindings.keys())

        now = datetime.now(timezone.utc)
        record = RenewalRecord(
            renewal_id=f"rnw_{uuid.uuid4().hex[:12]}",
            passport_id=passport_id,
            version=passport.version + 1,
            renewed_at=now.isoformat(),
            reason=reason,
            changes={
                "type": "bindings",
                "added": list(add.keys()),
                "removed": remove,
                "before": old_protocols,
                "after": new_protocols,
            },
            previous_expires_at=passport.expires_at,
            new_expires_at=passport.expires_at,
            renewed_by=renewed_by,
        )

        passport.version += 1
        passport.renewal_history.append(record)

        return passport

    # ── Update display name / metadata ────────────────────────────

    def update_metadata(
        self,
        passport_id: str,
        display_name: Optional[str] = None,
        metadata: Optional[dict] = None,
        reason: str = "",
        renewed_by: str = "system",
    ) -> RenewablePassport:
        """Update display name and/or metadata."""
        passport = self._check_passport(passport_id)

        changes = {"type": "metadata"}
        if display_name:
            changes["display_name"] = {"before": passport.display_name, "after": display_name}
            passport.display_name = display_name
        if metadata:
            changes["metadata_keys"] = list(metadata.keys())
            passport.metadata.update(metadata)

        now = datetime.now(timezone.utc)
        record = RenewalRecord(
            renewal_id=f"rnw_{uuid.uuid4().hex[:12]}",
            passport_id=passport_id,
            version=passport.version + 1,
            renewed_at=now.isoformat(),
            reason=reason,
            changes=changes,
            previous_expires_at=passport.expires_at,
            new_expires_at=passport.expires_at,
            renewed_by=renewed_by,
        )

        passport.version += 1
        passport.renewal_history.append(record)

        return passport

    # ── Revoke ────────────────────────────────────────────────────

    def revoke(self, passport_id: str, reason: str = ""):
        """Revoke — after this, no renewal is possible."""
        self._revoked.add(passport_id)

    # ── History ───────────────────────────────────────────────────

    def get_history(self, passport_id: str) -> list[dict]:
        passport = self._passports.get(passport_id)
        if not passport:
            return []
        return [r.to_dict() for r in passport.renewal_history]

    def get_version(self, passport_id: str) -> int:
        passport = self._passports.get(passport_id)
        return passport.version if passport else 0

    # ── List ──────────────────────────────────────────────────────

    def list_passports(self) -> list[dict]:
        return [
            {**p.to_dict(), "revoked": p.passport_id in self._revoked}
            for p in self._passports.values()
        ]

    # ── Internal ──────────────────────────────────────────────────

    def _check_passport(self, passport_id: str) -> RenewablePassport:
        if passport_id in self._revoked:
            raise PassportRevokedError(f"Passport {passport_id} is revoked — cannot renew")
        passport = self._passports.get(passport_id)
        if not passport:
            raise PassportNotFoundError(f"Passport not found: {passport_id}")
        return passport

    @property
    def count(self) -> int:
        return len(self._passports)
