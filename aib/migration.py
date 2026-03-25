"""
AIB — Protocol Migration.

Enables agents to add, retire, and migrate protocols on live passports
without losing identity or audit history.

Three operations:
1. ADD PROTOCOL: Agent starts with MCP, later needs A2A → add binding hot
2. RETIRE PROTOCOL: Agent stops using ANP → mark as retired with end date
3. MIGRATE PROTOCOL: MCP v1 → MCP v2 → re-translate bindings, grace period

Key constraint: the passport_id NEVER changes. All audit receipts (past
and future) remain linked to the same identity. The migration history
is itself an auditable trail.

This module wraps PassportLifecycleManager — does not modify it.
"""

import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum


class MigrationAction(str, Enum):
    """Types of protocol migration operations."""
    ADD = "add"                  # New protocol binding added
    RETIRE = "retire"            # Protocol marked as retired (with end date)
    REACTIVATE = "reactivate"    # Previously retired protocol restored
    MIGRATE = "migrate"          # Protocol version upgraded (old → new)


class MigrationError(Exception):
    """Raised when a migration operation is invalid."""
    pass


class ProtocolAlreadyExistsError(MigrationError):
    """Raised when adding a protocol that already exists on the passport."""
    pass


class ProtocolNotFoundError(MigrationError):
    """Raised when operating on a protocol that doesn't exist on the passport."""
    pass


class PassportNotFoundError(MigrationError):
    """Raised when the passport doesn't exist."""
    pass


# ── Migration Event ───────────────────────────────────────────────

@dataclass
class MigrationEvent:
    """
    Record of a protocol migration operation.

    These events form an auditable history of how an agent's
    protocol bindings evolved over time.
    """
    event_id: str
    passport_id: str
    action: MigrationAction
    protocol: str
    timestamp: str
    details: dict = field(default_factory=dict)

    # For MIGRATE actions
    old_binding: Optional[dict] = None
    new_binding: Optional[dict] = None

    # For RETIRE actions
    retired_at: Optional[str] = None
    retirement_reason: str = ""

    # For ADD actions
    added_binding: Optional[dict] = None

    def to_dict(self) -> dict:
        d = {
            "event_id": self.event_id,
            "passport_id": self.passport_id,
            "action": self.action.value,
            "protocol": self.protocol,
            "timestamp": self.timestamp,
            "details": self.details,
        }
        if self.old_binding:
            d["old_binding"] = self.old_binding
        if self.new_binding:
            d["new_binding"] = self.new_binding
        if self.added_binding:
            d["added_binding"] = self.added_binding
        if self.retired_at:
            d["retired_at"] = self.retired_at
        if self.retirement_reason:
            d["retirement_reason"] = self.retirement_reason
        return d


# ── Retired Protocol Record ──────────────────────────────────────

@dataclass
class RetiredProtocol:
    """
    Record of a retired protocol binding.

    The binding is preserved for audit purposes but no longer
    active for new requests. Past receipts referencing this
    protocol remain valid and queryable.
    """
    protocol: str
    binding: dict
    retired_at: str
    reason: str
    active_from: Optional[str] = None   # When the binding was first added
    active_until: str = ""              # = retired_at
    receipt_count: int = 0              # Receipts during active period


# ── Protocol Migration Manager ────────────────────────────────────

class ProtocolMigrationManager:
    """
    Manages protocol migrations on live passports.

    Usage:
        mgr = ProtocolMigrationManager()

        # Register a passport (wraps the lifecycle manager's passport)
        mgr.register("urn:aib:agent:acme:bot", passport_obj)

        # Add a new protocol
        mgr.add_protocol("urn:aib:agent:acme:bot", "anp", {
            "auth_method": "did-auth",
            "did": "did:web:acme.com:agents:bot"
        })

        # Retire a protocol (keeps history)
        mgr.retire_protocol("urn:aib:agent:acme:bot", "a2a",
            reason="Partner migrated to MCP")

        # Migrate protocol version
        mgr.migrate_protocol("urn:aib:agent:acme:bot", "mcp",
            new_binding={"auth_method": "oauth2", "version": "2.0"},
            reason="MCP v2 upgrade")

        # Get full history
        history = mgr.get_history("urn:aib:agent:acme:bot")
    """

    def __init__(self):
        self._passports: dict[str, Any] = {}  # passport_id → passport object
        self._events: list[MigrationEvent] = []
        self._retired: dict[str, list[RetiredProtocol]] = {}  # passport_id → retired list
        self._history: dict[str, list[str]] = {}  # passport_id → [event_ids]

    def register(self, passport_id: str, passport: Any):
        """Register a passport for migration management."""
        self._passports[passport_id] = passport
        if passport_id not in self._history:
            self._history[passport_id] = []
        if passport_id not in self._retired:
            self._retired[passport_id] = []

    def _get_passport(self, passport_id: str) -> Any:
        p = self._passports.get(passport_id)
        if not p:
            raise PassportNotFoundError(f"Passport not found: {passport_id}")
        return p

    def _get_bindings(self, passport: Any) -> dict:
        """Extract protocol_bindings from passport (supports dict and object)."""
        if hasattr(passport, 'protocol_bindings'):
            return passport.protocol_bindings
        if isinstance(passport, dict):
            return passport.get('protocol_bindings', {})
        return {}

    def _set_bindings(self, passport: Any, bindings: dict):
        """Set protocol_bindings on passport."""
        if hasattr(passport, 'protocol_bindings'):
            passport.protocol_bindings = bindings
        elif isinstance(passport, dict):
            passport['protocol_bindings'] = bindings

    # ── ADD PROTOCOL ──────────────────────────────────────────

    def add_protocol(
        self,
        passport_id: str,
        protocol: str,
        binding: dict,
        reason: str = "",
    ) -> MigrationEvent:
        """
        Add a new protocol binding to a live passport.

        The passport_id stays the same. All past audit receipts
        remain linked. The agent can now operate on the new protocol.

        Raises ProtocolAlreadyExistsError if the protocol is already active.
        (Use migrate_protocol to upgrade an existing binding.)
        """
        passport = self._get_passport(passport_id)
        bindings = self._get_bindings(passport)

        # Check not already active
        if protocol in bindings:
            raise ProtocolAlreadyExistsError(
                f"Protocol '{protocol}' already exists on passport {passport_id}. "
                f"Use migrate_protocol() to update it."
            )

        # Check if it was previously retired (reactivation)
        was_retired = False
        for rp in self._retired.get(passport_id, []):
            if rp.protocol == protocol:
                was_retired = True
                break

        # Add the binding
        bindings[protocol] = binding
        self._set_bindings(passport, bindings)

        now = datetime.now(timezone.utc).isoformat()
        action = MigrationAction.REACTIVATE if was_retired else MigrationAction.ADD

        event = MigrationEvent(
            event_id=f"mig_{uuid.uuid4().hex[:12]}",
            passport_id=passport_id,
            action=action,
            protocol=protocol,
            timestamp=now,
            added_binding=binding,
            details={
                "reason": reason or (f"Reactivated protocol {protocol}" if was_retired else f"Added protocol {protocol}"),
                "was_retired": was_retired,
                "active_protocols": list(bindings.keys()),
            },
        )

        self._events.append(event)
        self._history[passport_id].append(event.event_id)
        return event

    # ── RETIRE PROTOCOL ───────────────────────────────────────

    def retire_protocol(
        self,
        passport_id: str,
        protocol: str,
        reason: str = "",
    ) -> MigrationEvent:
        """
        Retire a protocol binding from a passport.

        The binding is removed from active use but preserved in the
        retirement archive. Past audit receipts referencing this
        protocol remain queryable. The agent can no longer make new
        requests via this protocol.

        Raises ProtocolNotFoundError if the protocol isn't active.
        """
        passport = self._get_passport(passport_id)
        bindings = self._get_bindings(passport)

        if protocol not in bindings:
            raise ProtocolNotFoundError(
                f"Protocol '{protocol}' not found on passport {passport_id}"
            )

        # Archive the binding
        now = datetime.now(timezone.utc).isoformat()
        old_binding = bindings[protocol]

        retired = RetiredProtocol(
            protocol=protocol,
            binding=old_binding if isinstance(old_binding, dict) else {"data": str(old_binding)},
            retired_at=now,
            reason=reason or f"Protocol {protocol} retired",
            active_until=now,
        )
        self._retired[passport_id].append(retired)

        # Remove from active bindings
        del bindings[protocol]
        self._set_bindings(passport, bindings)

        event = MigrationEvent(
            event_id=f"mig_{uuid.uuid4().hex[:12]}",
            passport_id=passport_id,
            action=MigrationAction.RETIRE,
            protocol=protocol,
            timestamp=now,
            old_binding=retired.binding,
            retired_at=now,
            retirement_reason=reason or f"Protocol {protocol} retired",
            details={
                "remaining_protocols": list(bindings.keys()),
                "retired_protocols": [rp.protocol for rp in self._retired[passport_id]],
            },
        )

        self._events.append(event)
        self._history[passport_id].append(event.event_id)
        return event

    # ── MIGRATE PROTOCOL (VERSION UPGRADE) ────────────────────

    def migrate_protocol(
        self,
        passport_id: str,
        protocol: str,
        new_binding: dict,
        reason: str = "",
    ) -> MigrationEvent:
        """
        Migrate a protocol binding to a new version.

        Replaces the current binding with a new one. The old binding
        is archived in the retirement list with a "migrated" reason.
        The passport_id stays the same. All history preserved.

        Use case: MCP v1 → MCP v2, OAuth2.0 → OAuth2.1, etc.
        """
        passport = self._get_passport(passport_id)
        bindings = self._get_bindings(passport)

        if protocol not in bindings:
            raise ProtocolNotFoundError(
                f"Protocol '{protocol}' not found on passport {passport_id}. "
                f"Use add_protocol() to add a new protocol."
            )

        now = datetime.now(timezone.utc).isoformat()
        old_binding = bindings[protocol]
        old_binding_dict = old_binding if isinstance(old_binding, dict) else {"data": str(old_binding)}

        # Archive old version
        retired = RetiredProtocol(
            protocol=f"{protocol}_migrated",
            binding=old_binding_dict,
            retired_at=now,
            reason=reason or f"Migrated to new version",
            active_until=now,
        )
        self._retired[passport_id].append(retired)

        # Replace with new binding
        bindings[protocol] = new_binding
        self._set_bindings(passport, bindings)

        event = MigrationEvent(
            event_id=f"mig_{uuid.uuid4().hex[:12]}",
            passport_id=passport_id,
            action=MigrationAction.MIGRATE,
            protocol=protocol,
            timestamp=now,
            old_binding=old_binding_dict,
            new_binding=new_binding,
            details={
                "reason": reason or f"Protocol {protocol} migrated to new version",
                "active_protocols": list(bindings.keys()),
            },
        )

        self._events.append(event)
        self._history[passport_id].append(event.event_id)
        return event

    # ── QUERIES ───────────────────────────────────────────────

    def get_history(self, passport_id: str) -> list[MigrationEvent]:
        """Get the full migration history for a passport."""
        event_ids = self._history.get(passport_id, [])
        return [e for e in self._events if e.event_id in event_ids]

    def get_retired(self, passport_id: str) -> list[RetiredProtocol]:
        """Get all retired protocols for a passport."""
        return self._retired.get(passport_id, [])

    def get_active_protocols(self, passport_id: str) -> list[str]:
        """Get currently active protocol names for a passport."""
        passport = self._get_passport(passport_id)
        bindings = self._get_bindings(passport)
        return list(bindings.keys())

    def get_full_protocol_timeline(self, passport_id: str) -> list[dict]:
        """
        Get the complete protocol timeline for a passport.

        Returns a chronological list of every protocol state change:
        additions, retirements, migrations, reactivations.
        Useful for compliance audits ("show me the full identity history").
        """
        events = self.get_history(passport_id)
        timeline = []
        for e in events:
            timeline.append({
                "timestamp": e.timestamp,
                "action": e.action.value,
                "protocol": e.protocol,
                "event_id": e.event_id,
                "details": e.details,
            })
        return sorted(timeline, key=lambda x: x["timestamp"])

    def export_migration_report(self, passport_id: str) -> dict:
        """
        Export a complete migration report for compliance.

        Contains: current bindings, retired bindings, full event timeline,
        and summary statistics.
        """
        passport = self._get_passport(passport_id)
        bindings = self._get_bindings(passport)
        retired = self.get_retired(passport_id)
        history = self.get_history(passport_id)

        return {
            "passport_id": passport_id,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "current_protocols": list(bindings.keys()),
            "retired_protocols": [
                {
                    "protocol": rp.protocol,
                    "retired_at": rp.retired_at,
                    "reason": rp.reason,
                    "binding": rp.binding,
                }
                for rp in retired
            ],
            "migration_events": [e.to_dict() for e in history],
            "statistics": {
                "total_migrations": len(history),
                "protocols_added": sum(1 for e in history if e.action == MigrationAction.ADD),
                "protocols_retired": sum(1 for e in history if e.action == MigrationAction.RETIRE),
                "protocols_migrated": sum(1 for e in history if e.action == MigrationAction.MIGRATE),
                "protocols_reactivated": sum(1 for e in history if e.action == MigrationAction.REACTIVATE),
            },
        }
