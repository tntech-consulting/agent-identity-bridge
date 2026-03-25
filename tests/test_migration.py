"""Tests for protocol migration — add, retire, migrate protocols on live passports."""

import pytest
from aib.migration import (
    ProtocolMigrationManager, MigrationAction, MigrationEvent,
    MigrationError, ProtocolAlreadyExistsError,
    ProtocolNotFoundError, PassportNotFoundError,
    RetiredProtocol,
)
from aib.lifecycle import PassportLifecycleManager


@pytest.fixture
def mgr():
    return ProtocolMigrationManager()


@pytest.fixture
def lifecycle():
    return PassportLifecycleManager()


@pytest.fixture
def setup(mgr, lifecycle):
    """Create a passport with MCP + A2A and register it."""
    passport = lifecycle.create_permanent(
        org="acme", agent="bot",
        capabilities=["booking", "search"],
        protocol_bindings={
            "mcp": {"auth_method": "oauth2", "server_card_url": "https://acme.com/mcp"},
            "a2a": {"auth_method": "bearer", "agent_card_url": "https://acme.com/agent"},
        },
    )
    mgr.register(passport.passport_id, passport)
    return mgr, passport


# ═══════════════════════════════════════════════════════════════════
# ADD PROTOCOL
# ═══════════════════════════════════════════════════════════════════

class TestAddProtocol:

    def test_add_new_protocol(self, setup):
        mgr, passport = setup
        event = mgr.add_protocol(
            passport.passport_id, "anp",
            {"auth_method": "did-auth", "did": "did:web:acme.com:bot"},
            reason="Partner requires ANP",
        )
        assert event.action == MigrationAction.ADD
        assert event.protocol == "anp"
        assert "anp" in passport.protocol_bindings
        assert "mcp" in passport.protocol_bindings  # Still there
        assert "a2a" in passport.protocol_bindings  # Still there

    def test_passport_id_unchanged(self, setup):
        mgr, passport = setup
        old_id = passport.passport_id
        mgr.add_protocol(passport.passport_id, "anp", {"auth_method": "did-auth"})
        assert passport.passport_id == old_id

    def test_add_duplicate_raises(self, setup):
        mgr, passport = setup
        with pytest.raises(ProtocolAlreadyExistsError, match="already exists"):
            mgr.add_protocol(passport.passport_id, "mcp", {"auth_method": "oauth2"})

    def test_add_to_nonexistent_passport_raises(self, mgr):
        with pytest.raises(PassportNotFoundError):
            mgr.add_protocol("urn:aib:agent:fake:x", "mcp", {})

    def test_add_creates_event(self, setup):
        mgr, passport = setup
        event = mgr.add_protocol(passport.passport_id, "ag-ui", {"auth_method": "none"})
        assert event.event_id.startswith("mig_")
        assert event.added_binding == {"auth_method": "none"}
        assert "active_protocols" in event.details

    def test_active_protocols_after_add(self, setup):
        mgr, passport = setup
        mgr.add_protocol(passport.passport_id, "anp", {"auth_method": "did-auth"})
        active = mgr.get_active_protocols(passport.passport_id)
        assert set(active) == {"mcp", "a2a", "anp"}


# ═══════════════════════════════════════════════════════════════════
# RETIRE PROTOCOL
# ═══════════════════════════════════════════════════════════════════

class TestRetireProtocol:

    def test_retire(self, setup):
        mgr, passport = setup
        event = mgr.retire_protocol(
            passport.passport_id, "a2a",
            reason="Partner migrated to MCP",
        )
        assert event.action == MigrationAction.RETIRE
        assert "a2a" not in passport.protocol_bindings
        assert "mcp" in passport.protocol_bindings  # Unaffected

    def test_retire_preserves_in_archive(self, setup):
        mgr, passport = setup
        mgr.retire_protocol(passport.passport_id, "a2a")
        retired = mgr.get_retired(passport.passport_id)
        assert len(retired) == 1
        assert retired[0].protocol == "a2a"
        assert retired[0].retired_at is not None
        assert retired[0].binding["auth_method"] == "bearer"

    def test_retire_nonexistent_raises(self, setup):
        mgr, passport = setup
        with pytest.raises(ProtocolNotFoundError, match="not found"):
            mgr.retire_protocol(passport.passport_id, "anp")

    def test_retire_creates_event(self, setup):
        mgr, passport = setup
        event = mgr.retire_protocol(passport.passport_id, "a2a")
        assert event.old_binding is not None
        assert event.retired_at is not None
        assert "remaining_protocols" in event.details

    def test_active_protocols_after_retire(self, setup):
        mgr, passport = setup
        mgr.retire_protocol(passport.passport_id, "a2a")
        active = mgr.get_active_protocols(passport.passport_id)
        assert active == ["mcp"]


# ═══════════════════════════════════════════════════════════════════
# REACTIVATE PROTOCOL
# ═══════════════════════════════════════════════════════════════════

class TestReactivateProtocol:

    def test_reactivate_retired_protocol(self, setup):
        mgr, passport = setup
        mgr.retire_protocol(passport.passport_id, "a2a")
        assert "a2a" not in passport.protocol_bindings

        event = mgr.add_protocol(
            passport.passport_id, "a2a",
            {"auth_method": "bearer", "agent_card_url": "https://acme.com/v2/agent"},
        )
        assert event.action == MigrationAction.REACTIVATE
        assert "a2a" in passport.protocol_bindings
        assert event.details["was_retired"] is True

    def test_reactivate_with_new_binding(self, setup):
        mgr, passport = setup
        mgr.retire_protocol(passport.passport_id, "a2a")
        mgr.add_protocol(passport.passport_id, "a2a", {"auth_method": "oauth2", "version": "2.0"})
        assert passport.protocol_bindings["a2a"]["auth_method"] == "oauth2"


# ═══════════════════════════════════════════════════════════════════
# MIGRATE PROTOCOL (VERSION UPGRADE)
# ═══════════════════════════════════════════════════════════════════

class TestMigrateProtocol:

    def test_migrate_version(self, setup):
        mgr, passport = setup
        old_binding = dict(passport.protocol_bindings["mcp"])

        event = mgr.migrate_protocol(
            passport.passport_id, "mcp",
            new_binding={"auth_method": "oauth2.1", "version": "2.0", "transport": "sse"},
            reason="MCP v2 upgrade",
        )

        assert event.action == MigrationAction.MIGRATE
        assert event.old_binding == old_binding
        assert event.new_binding["auth_method"] == "oauth2.1"
        assert passport.protocol_bindings["mcp"]["version"] == "2.0"

    def test_migrate_archives_old_version(self, setup):
        mgr, passport = setup
        mgr.migrate_protocol(passport.passport_id, "mcp", new_binding={"auth_method": "oauth2.1"})

        retired = mgr.get_retired(passport.passport_id)
        assert len(retired) == 1
        assert retired[0].protocol == "mcp_migrated"
        assert retired[0].binding["auth_method"] == "oauth2"

    def test_migrate_nonexistent_raises(self, setup):
        mgr, passport = setup
        with pytest.raises(ProtocolNotFoundError, match="not found"):
            mgr.migrate_protocol(passport.passport_id, "anp", new_binding={})

    def test_migrate_passport_id_unchanged(self, setup):
        mgr, passport = setup
        old_id = passport.passport_id
        mgr.migrate_protocol(passport.passport_id, "mcp", new_binding={"auth_method": "oauth2.1"})
        assert passport.passport_id == old_id

    def test_multiple_migrations(self, setup):
        mgr, passport = setup
        mgr.migrate_protocol(passport.passport_id, "mcp", new_binding={"version": "2.0"})
        mgr.migrate_protocol(passport.passport_id, "mcp", new_binding={"version": "3.0"})

        retired = mgr.get_retired(passport.passport_id)
        assert len(retired) == 2  # Two old versions archived

        assert passport.protocol_bindings["mcp"]["version"] == "3.0"


# ═══════════════════════════════════════════════════════════════════
# HISTORY & TIMELINE
# ═══════════════════════════════════════════════════════════════════

class TestHistory:

    def test_history_tracks_all_events(self, setup):
        mgr, passport = setup
        mgr.add_protocol(passport.passport_id, "anp", {"auth_method": "did-auth"})
        mgr.retire_protocol(passport.passport_id, "a2a")
        mgr.migrate_protocol(passport.passport_id, "mcp", new_binding={"version": "2.0"})

        history = mgr.get_history(passport.passport_id)
        assert len(history) == 3
        actions = [e.action for e in history]
        assert MigrationAction.ADD in actions
        assert MigrationAction.RETIRE in actions
        assert MigrationAction.MIGRATE in actions

    def test_timeline_is_chronological(self, setup):
        mgr, passport = setup
        mgr.add_protocol(passport.passport_id, "anp", {"auth_method": "did-auth"})
        mgr.retire_protocol(passport.passport_id, "a2a")

        timeline = mgr.get_full_protocol_timeline(passport.passport_id)
        assert len(timeline) == 2
        assert timeline[0]["timestamp"] <= timeline[1]["timestamp"]

    def test_empty_history(self, setup):
        mgr, passport = setup
        history = mgr.get_history(passport.passport_id)
        assert history == []

    def test_event_to_dict(self, setup):
        mgr, passport = setup
        event = mgr.add_protocol(passport.passport_id, "anp", {"auth_method": "did-auth"})
        d = event.to_dict()
        assert d["action"] == "add"
        assert d["protocol"] == "anp"
        assert "added_binding" in d


# ═══════════════════════════════════════════════════════════════════
# MIGRATION REPORT
# ═══════════════════════════════════════════════════════════════════

class TestMigrationReport:

    def test_full_report(self, setup):
        mgr, passport = setup
        mgr.add_protocol(passport.passport_id, "anp", {"auth_method": "did-auth"})
        mgr.retire_protocol(passport.passport_id, "a2a", reason="Deprecated")
        mgr.migrate_protocol(passport.passport_id, "mcp", new_binding={"version": "2.0"})

        report = mgr.export_migration_report(passport.passport_id)

        assert report["passport_id"] == passport.passport_id
        assert set(report["current_protocols"]) == {"mcp", "anp"}
        assert len(report["retired_protocols"]) == 2  # a2a + mcp_migrated
        assert len(report["migration_events"]) == 3
        assert report["statistics"]["total_migrations"] == 3
        assert report["statistics"]["protocols_added"] == 1
        assert report["statistics"]["protocols_retired"] == 1
        assert report["statistics"]["protocols_migrated"] == 1

    def test_report_has_timestamp(self, setup):
        mgr, passport = setup
        report = mgr.export_migration_report(passport.passport_id)
        assert "exported_at" in report


# ═══════════════════════════════════════════════════════════════════
# COMPLEX SCENARIO
# ═══════════════════════════════════════════════════════════════════

class TestComplexScenario:

    def test_full_lifecycle(self, setup):
        """
        Simulate a real agent's protocol evolution:
        1. Start with MCP + A2A
        2. Add ANP for a decentralized partner
        3. Partner migrates, retire ANP
        4. Upgrade MCP to v2
        5. Reactivate ANP with new partner
        """
        mgr, passport = setup
        pid = passport.passport_id

        # 1. Already has MCP + A2A
        assert set(mgr.get_active_protocols(pid)) == {"mcp", "a2a"}

        # 2. Add ANP
        mgr.add_protocol(pid, "anp", {"auth_method": "did-auth", "did": "did:web:acme"})
        assert set(mgr.get_active_protocols(pid)) == {"mcp", "a2a", "anp"}

        # 3. Retire ANP
        mgr.retire_protocol(pid, "anp", reason="Partner sunset")
        assert set(mgr.get_active_protocols(pid)) == {"mcp", "a2a"}

        # 4. Upgrade MCP
        mgr.migrate_protocol(pid, "mcp", new_binding={"auth_method": "oauth2.1", "version": "2.0"})
        assert passport.protocol_bindings["mcp"]["version"] == "2.0"

        # 5. Reactivate ANP
        event = mgr.add_protocol(pid, "anp", {"auth_method": "did-auth", "did": "did:web:newpartner"})
        assert event.action == MigrationAction.REACTIVATE
        assert set(mgr.get_active_protocols(pid)) == {"mcp", "a2a", "anp"}

        # Verify passport_id never changed
        assert passport.passport_id == pid

        # Verify full history
        history = mgr.get_history(pid)
        assert len(history) == 4  # add + retire + migrate + reactivate

        # Verify archived bindings
        retired = mgr.get_retired(pid)
        assert len(retired) == 2  # anp (retired) + mcp_migrated

        # Verify report
        report = mgr.export_migration_report(pid)
        assert report["statistics"]["total_migrations"] == 4
