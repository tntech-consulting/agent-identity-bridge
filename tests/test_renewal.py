"""Tests for Sprint 10 — Passport renewal & capability hot-update."""

import pytest
from aib.renewal import (
    PassportRenewalManager, RenewablePassport, RenewalRecord,
    RenewalError, PassportNotFoundError, PassportRevokedError,
    CapabilityEscalationError,
)


@pytest.fixture
def mgr():
    return PassportRenewalManager()


@pytest.fixture
def registered(mgr):
    mgr.register(
        passport_id="urn:aib:agent:acme:bot",
        display_name="Acme Bot",
        issuer="urn:aib:org:acme",
        capabilities=["booking", "support", "scheduling"],
        protocol_bindings={
            "mcp": {"auth_method": "oauth2", "server_card_url": "https://acme.com/mcp"},
            "a2a": {"auth_method": "bearer", "agent_card_url": "https://acme.com/agent"},
        },
    )
    return mgr


PID = "urn:aib:agent:acme:bot"


# ═══════════════════════════════════════════════════════════════════
# REGISTRATION
# ═══════════════════════════════════════════════════════════════════

class TestRegistration:

    def test_register(self, mgr):
        p = mgr.register("p1", "Bot", "urn:aib:org:test", ["cap1"], {"mcp": {}})
        assert p.passport_id == "p1"
        assert p.version == 1
        assert len(p.renewal_history) == 0

    def test_get(self, registered):
        p = registered.get(PID)
        assert p is not None
        assert p.display_name == "Acme Bot"

    def test_get_nonexistent(self, mgr):
        assert mgr.get("nonexistent") is None

    def test_get_dict(self, registered):
        d = registered.get_dict(PID)
        assert d["version"] == 1
        assert d["renewal_count"] == 0

    def test_count(self, registered):
        assert registered.count == 1


# ═══════════════════════════════════════════════════════════════════
# RENEW (EXTEND TTL)
# ═══════════════════════════════════════════════════════════════════

class TestRenew:

    def test_renew_extends_expiry(self, registered):
        old_expires = registered.get(PID).expires_at
        registered.renew(PID, ttl_days=730, reason="Extended for 2 years")
        p = registered.get(PID)
        assert p.expires_at != old_expires
        assert p.version == 2

    def test_passport_id_unchanged(self, registered):
        registered.renew(PID, ttl_days=365)
        assert registered.get(PID).passport_id == PID

    def test_capabilities_unchanged(self, registered):
        old_caps = list(registered.get(PID).capabilities)
        registered.renew(PID, ttl_days=365)
        assert registered.get(PID).capabilities == old_caps

    def test_renewal_recorded(self, registered):
        registered.renew(PID, reason="Annual renewal", renewed_by="admin")
        history = registered.get_history(PID)
        assert len(history) == 1
        assert history[0]["reason"] == "Annual renewal"
        assert history[0]["renewed_by"] == "admin"
        assert history[0]["version"] == 2
        assert "previous_expires_at" in history[0]

    def test_multiple_renewals(self, registered):
        registered.renew(PID, ttl_days=30)
        registered.renew(PID, ttl_days=60)
        registered.renew(PID, ttl_days=90)
        assert registered.get_version(PID) == 4
        assert len(registered.get_history(PID)) == 3

    def test_renew_nonexistent_fails(self, mgr):
        with pytest.raises(PassportNotFoundError):
            mgr.renew("nonexistent")

    def test_renew_revoked_fails(self, registered):
        registered.revoke(PID)
        with pytest.raises(PassportRevokedError):
            registered.renew(PID)


# ═══════════════════════════════════════════════════════════════════
# CAPABILITY HOT-UPDATE
# ═══════════════════════════════════════════════════════════════════

class TestCapabilityUpdate:

    def test_add_capability(self, registered):
        registered.update_capabilities(PID, add=["payment"])
        p = registered.get(PID)
        assert "payment" in p.capabilities
        assert p.version == 2

    def test_remove_capability(self, registered):
        registered.update_capabilities(PID, remove=["support"])
        p = registered.get(PID)
        assert "support" not in p.capabilities
        assert "booking" in p.capabilities

    def test_add_and_remove(self, registered):
        registered.update_capabilities(PID, add=["payment"], remove=["support"])
        p = registered.get(PID)
        assert "payment" in p.capabilities
        assert "support" not in p.capabilities

    def test_passport_id_unchanged(self, registered):
        registered.update_capabilities(PID, add=["new"])
        assert registered.get(PID).passport_id == PID

    def test_changes_recorded(self, registered):
        registered.update_capabilities(PID, add=["payment"], remove=["support"],
                                        reason="Added payment, dropped support")
        history = registered.get_history(PID)
        assert len(history) == 1
        changes = history[0]["changes"]
        assert changes["type"] == "capabilities"
        assert "payment" in changes["added"]
        assert "support" in changes["removed"]
        assert "before" in changes
        assert "after" in changes

    def test_cannot_remove_all(self, registered):
        with pytest.raises(RenewalError, match="at least one"):
            registered.update_capabilities(PID,
                remove=["booking", "support", "scheduling"])

    def test_escalation_blocked(self):
        mgr = PassportRenewalManager(max_capabilities=["booking", "support", "scheduling"])
        mgr.register("p1", "Bot", "issuer", ["booking"], {"mcp": {}})
        with pytest.raises(CapabilityEscalationError, match="not in allowed"):
            mgr.update_capabilities("p1", add=["admin"])

    def test_escalation_allowed_within_max(self):
        mgr = PassportRenewalManager(max_capabilities=["booking", "support", "payment"])
        mgr.register("p1", "Bot", "issuer", ["booking"], {"mcp": {}})
        mgr.update_capabilities("p1", add=["payment"])
        assert "payment" in mgr.get("p1").capabilities

    def test_no_max_capabilities_allows_all(self, registered):
        registered.update_capabilities(PID, add=["admin", "superuser"])
        p = registered.get(PID)
        assert "admin" in p.capabilities

    def test_duplicate_add_idempotent(self, registered):
        registered.update_capabilities(PID, add=["booking"])  # Already exists
        assert registered.get(PID).capabilities.count("booking") == 1


# ═══════════════════════════════════════════════════════════════════
# BINDING HOT-UPDATE
# ═══════════════════════════════════════════════════════════════════

class TestBindingUpdate:

    def test_add_binding(self, registered):
        registered.update_bindings(PID, add={
            "ag_ui": {"endpoint_url": "https://acme.com/agent-ui"},
        })
        p = registered.get(PID)
        assert "ag_ui" in p.protocol_bindings
        assert p.version == 2

    def test_remove_binding(self, registered):
        registered.update_bindings(PID, remove=["a2a"])
        p = registered.get(PID)
        assert "a2a" not in p.protocol_bindings
        assert "mcp" in p.protocol_bindings

    def test_add_and_remove_binding(self, registered):
        registered.update_bindings(PID,
            add={"anp": {"did": "did:web:acme.com:bot"}},
            remove=["a2a"],
            reason="Switched from A2A to ANP",
        )
        p = registered.get(PID)
        assert "anp" in p.protocol_bindings
        assert "a2a" not in p.protocol_bindings

    def test_cannot_remove_all_bindings(self, registered):
        with pytest.raises(RenewalError, match="at least one"):
            registered.update_bindings(PID, remove=["mcp", "a2a"])

    def test_changes_recorded(self, registered):
        registered.update_bindings(PID,
            add={"ag_ui": {"endpoint_url": "https://ui.test"}},
            reason="Added AG-UI",
        )
        history = registered.get_history(PID)
        changes = history[0]["changes"]
        assert changes["type"] == "bindings"
        assert "ag_ui" in changes["added"]

    def test_passport_id_unchanged(self, registered):
        registered.update_bindings(PID, add={"anp": {}})
        assert registered.get(PID).passport_id == PID


# ═══════════════════════════════════════════════════════════════════
# METADATA UPDATE
# ═══════════════════════════════════════════════════════════════════

class TestMetadataUpdate:

    def test_update_display_name(self, registered):
        registered.update_metadata(PID, display_name="Acme Booking Bot v2")
        assert registered.get(PID).display_name == "Acme Booking Bot v2"

    def test_update_metadata(self, registered):
        registered.update_metadata(PID, metadata={"region": "eu-west-1"})
        assert registered.get(PID).metadata["region"] == "eu-west-1"

    def test_metadata_merge(self, registered):
        registered.update_metadata(PID, metadata={"a": "1"})
        registered.update_metadata(PID, metadata={"b": "2"})
        m = registered.get(PID).metadata
        assert m["a"] == "1"
        assert m["b"] == "2"

    def test_changes_recorded(self, registered):
        registered.update_metadata(PID, display_name="New Name")
        history = registered.get_history(PID)
        changes = history[0]["changes"]
        assert changes["display_name"]["before"] == "Acme Bot"
        assert changes["display_name"]["after"] == "New Name"


# ═══════════════════════════════════════════════════════════════════
# VERSION TRACKING
# ═══════════════════════════════════════════════════════════════════

class TestVersioning:

    def test_initial_version(self, registered):
        assert registered.get_version(PID) == 1

    def test_version_increments(self, registered):
        registered.renew(PID)
        assert registered.get_version(PID) == 2
        registered.update_capabilities(PID, add=["new"])
        assert registered.get_version(PID) == 3
        registered.update_bindings(PID, add={"anp": {}})
        assert registered.get_version(PID) == 4
        registered.update_metadata(PID, display_name="X")
        assert registered.get_version(PID) == 5

    def test_version_zero_for_unknown(self, mgr):
        assert mgr.get_version("nonexistent") == 0


# ═══════════════════════════════════════════════════════════════════
# REVOCATION
# ═══════════════════════════════════════════════════════════════════

class TestRevocation:

    def test_revoke_blocks_all_operations(self, registered):
        registered.revoke(PID, reason="Compromised")
        assert registered.is_revoked(PID) is True

        with pytest.raises(PassportRevokedError):
            registered.renew(PID)
        with pytest.raises(PassportRevokedError):
            registered.update_capabilities(PID, add=["x"])
        with pytest.raises(PassportRevokedError):
            registered.update_bindings(PID, add={"x": {}})
        with pytest.raises(PassportRevokedError):
            registered.update_metadata(PID, display_name="X")


# ═══════════════════════════════════════════════════════════════════
# END-TO-END
# ═══════════════════════════════════════════════════════════════════

class TestEndToEnd:

    def test_full_lifecycle(self, mgr):
        """Agent lifecycle: create → update caps → add protocol → renew → revoke."""
        # Create
        mgr.register("p1", "Agent v1", "urn:aib:org:test",
                      ["booking"], {"mcp": {"url": "https://test.com"}})
        assert mgr.get_version("p1") == 1

        # Add capability
        mgr.update_capabilities("p1", add=["payment"], reason="Payment feature launched")
        assert "payment" in mgr.get("p1").capabilities
        assert mgr.get_version("p1") == 2

        # Add AG-UI protocol
        mgr.update_bindings("p1",
            add={"ag_ui": {"endpoint_url": "https://test.com/ui"}},
            reason="Added user interface",
        )
        assert "ag_ui" in mgr.get("p1").protocol_bindings
        assert mgr.get_version("p1") == 3

        # Rename
        mgr.update_metadata("p1", display_name="Agent v2")
        assert mgr.get("p1").display_name == "Agent v2"
        assert mgr.get_version("p1") == 4

        # Renew for another year
        mgr.renew("p1", ttl_days=365, reason="Annual renewal")
        assert mgr.get_version("p1") == 5

        # Full history
        history = mgr.get_history("p1")
        assert len(history) == 4  # caps + bindings + metadata + renew
        assert history[0]["changes"]["type"] == "capabilities"
        assert history[1]["changes"]["type"] == "bindings"
        assert history[2]["changes"]["type"] == "metadata"
        assert history[3]["changes"]["type"] == "renew"

        # passport_id never changed
        assert mgr.get("p1").passport_id == "p1"

        # Revoke
        mgr.revoke("p1")
        with pytest.raises(PassportRevokedError):
            mgr.renew("p1")

    def test_list_passports(self, mgr):
        mgr.register("p1", "Bot 1", "issuer", ["a"], {"mcp": {}})
        mgr.register("p2", "Bot 2", "issuer", ["b"], {"a2a": {}})
        mgr.revoke("p2")

        result = mgr.list_passports()
        assert len(result) == 2
        p2 = next(p for p in result if p["passport_id"] == "p2")
        assert p2["revoked"] is True
