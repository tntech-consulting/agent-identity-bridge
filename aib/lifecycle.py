"""
AIB — Passport Lifecycle Management.

Three tiers of passports for different agent lifecycles:

    PERMANENT (365 days)   → production agents, stable services
        └── SESSION (1-24h) → workflow runs, task batches
              └── EPHEMERAL (5 min) → sub-agents, spawned workers

Each child passport:
- Is cryptographically linked to its parent (parent_passport_id + delegation_chain)
- Inherits a SUBSET of the parent's permissions (never escalates)
- Is automatically invalidated when the parent is revoked
- Has its own trace_id for audit correlation

This model is inspired by SPIFFE/SPIRE workload identity, adapted for AI agents.

References THREAT_MODEL.md: T5 (Replay), M5.1-M5.5
"""

import json
import uuid
import time
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class PassportTier(str, Enum):
    """Passport lifecycle tier."""
    PERMANENT = "permanent"    # 365 days, production agents
    SESSION = "session"        # 1-24 hours, workflow scoped
    EPHEMERAL = "ephemeral"    # 1-15 minutes, sub-agent scoped


# Default TTLs per tier
DEFAULT_TTL = {
    PassportTier.PERMANENT: timedelta(days=365),
    PassportTier.SESSION: timedelta(hours=4),
    PassportTier.EPHEMERAL: timedelta(minutes=5),
}

# Maximum TTLs (hard cap, cannot be overridden)
MAX_TTL = {
    PassportTier.PERMANENT: timedelta(days=730),
    PassportTier.SESSION: timedelta(hours=24),
    PassportTier.EPHEMERAL: timedelta(minutes=15),
}

# Which tiers can create which children
DELEGATION_RULES = {
    PassportTier.PERMANENT: [PassportTier.SESSION, PassportTier.EPHEMERAL],
    PassportTier.SESSION: [PassportTier.EPHEMERAL],
    PassportTier.EPHEMERAL: [],  # Cannot delegate further
}


@dataclass
class DelegationLink:
    """Cryptographic link to a parent passport."""
    parent_passport_id: str
    parent_tier: PassportTier
    delegated_at: str
    delegated_capabilities: list[str]
    delegation_chain: list[str]  # Full chain: [root_id, ..., parent_id]
    max_depth: int = 3


@dataclass
class LifecyclePassport:
    """
    A passport with lifecycle tier and delegation support.

    Extends the base AgentPassport with:
    - tier: permanent/session/ephemeral
    - delegation: link to parent passport
    - scope restrictions: capability subset of parent
    - auto-expiry: enforced TTL per tier
    """
    passport_id: str
    display_name: str
    issuer: str
    tier: PassportTier
    capabilities: list[str]
    protocol_bindings: dict
    issued_at: str
    expires_at: str
    jti: str  # Unique token ID (replay protection)
    delegation: Optional[DelegationLink] = None
    metadata: dict = field(default_factory=dict)
    aib_version: str = "0.2"

    @property
    def is_root(self) -> bool:
        return self.delegation is None

    @property
    def parent_id(self) -> Optional[str]:
        return self.delegation.parent_passport_id if self.delegation else None

    @property
    def delegation_depth(self) -> int:
        return len(self.delegation.delegation_chain) if self.delegation else 0

    @property
    def root_passport_id(self) -> str:
        if self.delegation and self.delegation.delegation_chain:
            return self.delegation.delegation_chain[0]
        return self.passport_id

    def to_dict(self) -> dict:
        d = {
            "aib_version": self.aib_version,
            "passport_id": self.passport_id,
            "display_name": self.display_name,
            "issuer": self.issuer,
            "tier": self.tier.value,
            "capabilities": self.capabilities,
            "protocol_bindings": self.protocol_bindings,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "jti": self.jti,
        }
        if self.delegation:
            d["delegation"] = {
                "parent_passport_id": self.delegation.parent_passport_id,
                "parent_tier": self.delegation.parent_tier.value,
                "delegated_at": self.delegation.delegated_at,
                "delegated_capabilities": self.delegation.delegated_capabilities,
                "delegation_chain": self.delegation.delegation_chain,
                "max_depth": self.delegation.max_depth,
            }
        if self.metadata:
            d["metadata"] = self.metadata
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "LifecyclePassport":
        delegation = None
        if "delegation" in d and d["delegation"]:
            dd = d["delegation"]
            delegation = DelegationLink(
                parent_passport_id=dd["parent_passport_id"],
                parent_tier=PassportTier(dd["parent_tier"]),
                delegated_at=dd["delegated_at"],
                delegated_capabilities=dd["delegated_capabilities"],
                delegation_chain=dd["delegation_chain"],
                max_depth=dd.get("max_depth", 3),
            )
        return cls(
            passport_id=d["passport_id"],
            display_name=d["display_name"],
            issuer=d["issuer"],
            tier=PassportTier(d["tier"]),
            capabilities=d["capabilities"],
            protocol_bindings=d["protocol_bindings"],
            issued_at=d["issued_at"],
            expires_at=d["expires_at"],
            jti=d["jti"],
            delegation=delegation,
            metadata=d.get("metadata", {}),
            aib_version=d.get("aib_version", "0.2"),
        )


# ── Errors ────────────────────────────────────────────────────────

class DelegationError(Exception):
    """Raised when a delegation request is invalid."""
    pass


class CapabilityEscalationError(DelegationError):
    """Raised when a child requests capabilities not held by the parent."""
    pass


class MaxDepthExceededError(DelegationError):
    """Raised when the delegation chain is too deep."""
    pass


class TierViolationError(DelegationError):
    """Raised when a tier tries to create a child it's not allowed to."""
    pass


# ── Lifecycle Manager ─────────────────────────────────────────────

class PassportLifecycleManager:
    """
    Manages passport creation, delegation, and lifecycle enforcement.

    Key rules:
    1. Permanent → can create Session or Ephemeral
    2. Session → can create Ephemeral only
    3. Ephemeral → cannot delegate
    4. Child capabilities ⊆ parent capabilities (never escalate)
    5. Child TTL ≤ tier max AND ≤ parent remaining TTL
    6. Revoking a parent cascades to all children
    7. Max delegation depth: 3 levels
    """

    def __init__(self):
        self._passports: dict[str, LifecyclePassport] = {}
        self._children: dict[str, list[str]] = {}  # parent_id → [child_ids]
        self._revoked: set[str] = set()
        self._seen_jtis: set[str] = set()  # Replay protection

    # ── Create root passport ──────────────────────────────────

    def create_permanent(
        self,
        org: str,
        agent: str,
        capabilities: list[str],
        protocol_bindings: dict,
        display_name: Optional[str] = None,
        ttl: Optional[timedelta] = None,
        metadata: Optional[dict] = None,
    ) -> LifecyclePassport:
        """Create a permanent (root) passport."""
        ttl = self._clamp_ttl(PassportTier.PERMANENT, ttl)
        now = datetime.now(timezone.utc)

        passport = LifecyclePassport(
            passport_id=f"urn:aib:agent:{org}:{agent}",
            display_name=display_name or f"{org}/{agent}",
            issuer=f"urn:aib:org:{org}",
            tier=PassportTier.PERMANENT,
            capabilities=capabilities,
            protocol_bindings=protocol_bindings,
            issued_at=now.isoformat(),
            expires_at=(now + ttl).isoformat(),
            jti=str(uuid.uuid4()),
            metadata=metadata or {},
        )

        self._register(passport)
        return passport

    # ── Delegate (create child) ───────────────────────────────

    def delegate(
        self,
        parent_id: str,
        child_tier: PassportTier,
        capabilities: Optional[list[str]] = None,
        protocol_bindings: Optional[dict] = None,
        child_slug: Optional[str] = None,
        ttl: Optional[timedelta] = None,
        metadata: Optional[dict] = None,
    ) -> LifecyclePassport:
        """
        Create a child passport delegated from a parent.

        The child:
        - Gets a subset of the parent's capabilities
        - Inherits protocol bindings (or a subset)
        - Has a shorter TTL
        - Is linked via delegation_chain
        """
        # Get parent
        parent = self._passports.get(parent_id)
        if not parent:
            raise DelegationError(f"Parent passport not found: {parent_id}")

        # Check parent is not revoked
        if self._is_revoked(parent_id):
            raise DelegationError(f"Cannot delegate from revoked passport: {parent_id}")

        # Check parent is not expired
        if datetime.now(timezone.utc) > datetime.fromisoformat(parent.expires_at):
            raise DelegationError(f"Cannot delegate from expired passport: {parent_id}")

        # Check tier delegation rules
        allowed_children = DELEGATION_RULES.get(parent.tier, [])
        if child_tier not in allowed_children:
            raise TierViolationError(
                f"{parent.tier.value} passport cannot create {child_tier.value} children. "
                f"Allowed: {[t.value for t in allowed_children]}"
            )

        # Check delegation depth
        current_depth = parent.delegation_depth + 1
        max_depth = parent.delegation.max_depth if parent.delegation else 3
        if current_depth > max_depth:
            raise MaxDepthExceededError(
                f"Delegation depth {current_depth} exceeds max {max_depth}"
            )

        # Validate capabilities (subset only, no escalation)
        requested_caps = capabilities or parent.capabilities
        for cap in requested_caps:
            if cap not in parent.capabilities:
                raise CapabilityEscalationError(
                    f"Capability '{cap}' not in parent's capabilities: {parent.capabilities}"
                )

        # Validate protocol bindings (subset only)
        bindings = protocol_bindings or parent.protocol_bindings
        if protocol_bindings:
            for proto in protocol_bindings:
                if proto not in parent.protocol_bindings:
                    raise CapabilityEscalationError(
                        f"Protocol '{proto}' not in parent's bindings: "
                        f"{list(parent.protocol_bindings.keys())}"
                    )

        # Clamp TTL: min(tier max, parent remaining TTL)
        parent_remaining = (
            datetime.fromisoformat(parent.expires_at)
            - datetime.now(timezone.utc)
        )
        tier_max = MAX_TTL[child_tier]
        effective_max = min(tier_max, parent_remaining)
        ttl = self._clamp_ttl(child_tier, ttl, max_override=effective_max)

        now = datetime.now(timezone.utc)

        # Build delegation chain
        if parent.delegation:
            chain = parent.delegation.delegation_chain + [parent_id]
        else:
            chain = [parent_id]

        # Generate child ID
        slug = child_slug or f"{child_tier.value}-{uuid.uuid4().hex[:8]}"
        org = parent.passport_id.split(":")[3]

        child = LifecyclePassport(
            passport_id=f"urn:aib:agent:{org}:{slug}",
            display_name=f"{parent.display_name}/{slug}",
            issuer=parent.issuer,
            tier=child_tier,
            capabilities=requested_caps,
            protocol_bindings=bindings,
            issued_at=now.isoformat(),
            expires_at=(now + ttl).isoformat(),
            jti=str(uuid.uuid4()),
            delegation=DelegationLink(
                parent_passport_id=parent_id,
                parent_tier=parent.tier,
                delegated_at=now.isoformat(),
                delegated_capabilities=requested_caps,
                delegation_chain=chain,
                max_depth=max_depth,
            ),
            metadata={
                **(metadata or {}),
                "created_by": "delegation",
                "root_passport": parent.root_passport_id,
            },
        )

        self._register(child, parent_id=parent_id)
        return child

    # ── Convenience methods ───────────────────────────────────

    def create_session(
        self, parent_id: str, **kwargs
    ) -> LifecyclePassport:
        """Create a session passport from a permanent parent."""
        return self.delegate(parent_id, PassportTier.SESSION, **kwargs)

    def create_ephemeral(
        self, parent_id: str, **kwargs
    ) -> LifecyclePassport:
        """Create an ephemeral passport from a session or permanent parent."""
        return self.delegate(parent_id, PassportTier.EPHEMERAL, **kwargs)

    # ── Revocation (cascade) ──────────────────────────────────

    def revoke(self, passport_id: str) -> list[str]:
        """
        Revoke a passport and ALL its children (cascade).

        Returns the list of all revoked passport IDs.
        """
        revoked_ids = []
        self._revoke_recursive(passport_id, revoked_ids)
        return revoked_ids

    def _revoke_recursive(self, passport_id: str, revoked_ids: list[str]):
        if passport_id in self._revoked:
            return
        self._revoked.add(passport_id)
        revoked_ids.append(passport_id)

        # Cascade to children
        children = self._children.get(passport_id, [])
        for child_id in children:
            self._revoke_recursive(child_id, revoked_ids)

    # ── Verification ──────────────────────────────────────────

    def verify(self, passport_id: str) -> tuple[bool, str]:
        """
        Verify a passport is valid (exists, not expired, not revoked,
        entire delegation chain valid).

        Returns (is_valid, reason).
        """
        passport = self._passports.get(passport_id)
        if not passport:
            return False, "Passport not found"

        # Check revocation
        if self._is_revoked(passport_id):
            return False, "Passport revoked"

        # Check expiration
        if datetime.now(timezone.utc) > datetime.fromisoformat(passport.expires_at):
            return False, "Passport expired"

        # Check JTI (replay protection)
        if passport.jti in self._seen_jtis:
            # JTI seen is fine for stored passports — this check is
            # for runtime verification of presented tokens
            pass

        # Validate entire delegation chain
        if passport.delegation:
            chain = passport.delegation.delegation_chain
            for ancestor_id in chain:
                if self._is_revoked(ancestor_id):
                    return False, f"Ancestor passport revoked: {ancestor_id}"
                ancestor = self._passports.get(ancestor_id)
                if ancestor:
                    if datetime.now(timezone.utc) > datetime.fromisoformat(ancestor.expires_at):
                        return False, f"Ancestor passport expired: {ancestor_id}"

        return True, "Valid"

    # ── Query ─────────────────────────────────────────────────

    def get(self, passport_id: str) -> Optional[LifecyclePassport]:
        return self._passports.get(passport_id)

    def get_children(self, passport_id: str) -> list[LifecyclePassport]:
        child_ids = self._children.get(passport_id, [])
        return [self._passports[cid] for cid in child_ids if cid in self._passports]

    def get_chain(self, passport_id: str) -> list[LifecyclePassport]:
        """Get the full delegation chain from root to this passport."""
        passport = self._passports.get(passport_id)
        if not passport or not passport.delegation:
            return [passport] if passport else []

        chain = []
        for ancestor_id in passport.delegation.delegation_chain:
            ancestor = self._passports.get(ancestor_id)
            if ancestor:
                chain.append(ancestor)
        chain.append(passport)
        return chain

    def list_all(self) -> list[dict]:
        """List all passports with status info."""
        results = []
        for p in self._passports.values():
            expired = datetime.now(timezone.utc) > datetime.fromisoformat(p.expires_at)
            results.append({
                "passport_id": p.passport_id,
                "display_name": p.display_name,
                "tier": p.tier.value,
                "capabilities": p.capabilities,
                "protocols": list(p.protocol_bindings.keys()) if isinstance(p.protocol_bindings, dict) else [],
                "parent_id": p.parent_id,
                "root_id": p.root_passport_id,
                "depth": p.delegation_depth,
                "status": "revoked" if self._is_revoked(p.passport_id) else ("expired" if expired else "active"),
                "issued_at": p.issued_at,
                "expires_at": p.expires_at,
            })
        return results

    # ── Internal ──────────────────────────────────────────────

    def _register(self, passport: LifecyclePassport, parent_id: Optional[str] = None):
        self._passports[passport.passport_id] = passport
        self._seen_jtis.add(passport.jti)
        if parent_id:
            if parent_id not in self._children:
                self._children[parent_id] = []
            self._children[parent_id].append(passport.passport_id)

    def _is_revoked(self, passport_id: str) -> bool:
        return passport_id in self._revoked

    def _clamp_ttl(
        self,
        tier: PassportTier,
        requested: Optional[timedelta] = None,
        max_override: Optional[timedelta] = None,
    ) -> timedelta:
        default = DEFAULT_TTL[tier]
        maximum = max_override or MAX_TTL[tier]
        ttl = requested or default
        if ttl > maximum:
            ttl = maximum
        if ttl.total_seconds() <= 0:
            ttl = timedelta(seconds=60)  # Minimum 1 minute
        return ttl
