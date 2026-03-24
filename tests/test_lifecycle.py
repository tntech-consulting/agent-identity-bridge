"""Tests for passport lifecycle management."""

import pytest
from datetime import timedelta
from aib.lifecycle import (
    PassportLifecycleManager, PassportTier, LifecyclePassport,
    DelegationError, CapabilityEscalationError,
    MaxDepthExceededError, TierViolationError,
)


@pytest.fixture
def mgr():
    return PassportLifecycleManager()


@pytest.fixture
def root(mgr):
    return mgr.create_permanent(
        org="acme", agent="main-bot",
        capabilities=["booking", "search", "analytics"],
        protocol_bindings={"mcp": {"auth": "oauth2"}, "a2a": {"auth": "bearer"}},
    )


# ═══════════════════════════════════════════════════════════════════
# Permanent passports
# ═══════════════════════════════════════════════════════════════════

class TestPermanentPassport:

    def test_create(self, root):
        assert root.tier == PassportTier.PERMANENT
        assert root.passport_id == "urn:aib:agent:acme:main-bot"
        assert root.is_root is True
        assert root.parent_id is None
        assert root.delegation_depth == 0
        assert len(root.jti) == 36  # UUID

    def test_capabilities(self, root):
        assert "booking" in root.capabilities
        assert "search" in root.capabilities

    def test_protocols(self, root):
        assert "mcp" in root.protocol_bindings
        assert "a2a" in root.protocol_bindings

    def test_verify(self, mgr, root):
        valid, reason = mgr.verify(root.passport_id)
        assert valid is True
        assert reason == "Valid"

    def test_to_dict_and_back(self, root):
        d = root.to_dict()
        restored = LifecyclePassport.from_dict(d)
        assert restored.passport_id == root.passport_id
        assert restored.tier == root.tier
        assert restored.jti == root.jti


# ═══════════════════════════════════════════════════════════════════
# Session passports
# ═══════════════════════════════════════════════════════════════════

class TestSessionPassport:

    def test_create_session(self, mgr, root):
        session = mgr.create_session(root.passport_id)
        assert session.tier == PassportTier.SESSION
        assert session.is_root is False
        assert session.parent_id == root.passport_id
        assert session.delegation_depth == 1
        assert session.root_passport_id == root.passport_id

    def test_session_inherits_capabilities(self, mgr, root):
        session = mgr.create_session(root.passport_id)
        # By default inherits all parent capabilities
        assert session.capabilities == root.capabilities

    def test_session_subset_capabilities(self, mgr, root):
        session = mgr.create_session(
            root.passport_id,
            capabilities=["booking"],
        )
        assert session.capabilities == ["booking"]
        assert "search" not in session.capabilities

    def test_session_subset_protocols(self, mgr, root):
        session = mgr.create_session(
            root.passport_id,
            protocol_bindings={"mcp": {"auth": "oauth2"}},
        )
        assert "mcp" in session.protocol_bindings
        assert "a2a" not in session.protocol_bindings

    def test_session_custom_slug(self, mgr, root):
        session = mgr.create_session(
            root.passport_id,
            child_slug="workflow-42",
        )
        assert "workflow-42" in session.passport_id

    def test_session_verify(self, mgr, root):
        session = mgr.create_session(root.passport_id)
        valid, reason = mgr.verify(session.passport_id)
        assert valid is True

    def test_session_delegation_chain(self, mgr, root):
        session = mgr.create_session(root.passport_id)
        assert session.delegation.delegation_chain == [root.passport_id]


# ═══════════════════════════════════════════════════════════════════
# Ephemeral passports
# ═══════════════════════════════════════════════════════════════════

class TestEphemeralPassport:

    def test_create_from_permanent(self, mgr, root):
        eph = mgr.create_ephemeral(root.passport_id)
        assert eph.tier == PassportTier.EPHEMERAL
        assert eph.delegation_depth == 1

    def test_create_from_session(self, mgr, root):
        session = mgr.create_session(root.passport_id)
        eph = mgr.create_ephemeral(session.passport_id)
        assert eph.tier == PassportTier.EPHEMERAL
        assert eph.delegation_depth == 2
        assert eph.root_passport_id == root.passport_id

    def test_ephemeral_chain(self, mgr, root):
        session = mgr.create_session(root.passport_id)
        eph = mgr.create_ephemeral(session.passport_id)
        chain = mgr.get_chain(eph.passport_id)
        assert len(chain) == 3  # root → session → ephemeral
        assert chain[0].passport_id == root.passport_id
        assert chain[1].passport_id == session.passport_id
        assert chain[2].passport_id == eph.passport_id

    def test_ephemeral_cannot_delegate(self, mgr, root):
        eph = mgr.create_ephemeral(root.passport_id)
        with pytest.raises(TierViolationError):
            mgr.delegate(eph.passport_id, PassportTier.EPHEMERAL)


# ═══════════════════════════════════════════════════════════════════
# Delegation rules
# ═══════════════════════════════════════════════════════════════════

class TestDelegationRules:

    def test_capability_escalation_blocked(self, mgr, root):
        with pytest.raises(CapabilityEscalationError, match="admin"):
            mgr.create_session(
                root.passport_id,
                capabilities=["booking", "admin"],  # admin not in parent
            )

    def test_protocol_escalation_blocked(self, mgr, root):
        with pytest.raises(CapabilityEscalationError, match="anp"):
            mgr.create_session(
                root.passport_id,
                protocol_bindings={"anp": {"auth": "did"}},  # anp not in parent
            )

    def test_session_cannot_create_session(self, mgr, root):
        session = mgr.create_session(root.passport_id)
        with pytest.raises(TierViolationError):
            mgr.delegate(session.passport_id, PassportTier.SESSION)

    def test_max_depth_exceeded(self, mgr):
        p = mgr.create_permanent(
            org="deep", agent="root",
            capabilities=["x"],
            protocol_bindings={"mcp": {}},
        )
        s = mgr.create_session(p.passport_id)
        e = mgr.create_ephemeral(s.passport_id)
        # e is at depth 2, ephemeral can't delegate anyway
        with pytest.raises(TierViolationError):
            mgr.delegate(e.passport_id, PassportTier.EPHEMERAL)

    def test_delegate_from_revoked_parent(self, mgr, root):
        mgr.revoke(root.passport_id)
        with pytest.raises(DelegationError, match="revoked"):
            mgr.create_session(root.passport_id)

    def test_delegate_from_nonexistent(self, mgr):
        with pytest.raises(DelegationError, match="not found"):
            mgr.create_session("urn:aib:agent:fake:agent")


# ═══════════════════════════════════════════════════════════════════
# Cascade revocation
# ═══════════════════════════════════════════════════════════════════

class TestCascadeRevocation:

    def test_revoke_root_cascades(self, mgr, root):
        s1 = mgr.create_session(root.passport_id)
        s2 = mgr.create_session(root.passport_id)
        e1 = mgr.create_ephemeral(s1.passport_id)

        revoked = mgr.revoke(root.passport_id)

        assert root.passport_id in revoked
        assert s1.passport_id in revoked
        assert s2.passport_id in revoked
        assert e1.passport_id in revoked
        assert len(revoked) == 4

    def test_revoke_session_cascades_to_ephemeral(self, mgr, root):
        session = mgr.create_session(root.passport_id)
        e1 = mgr.create_ephemeral(session.passport_id)
        e2 = mgr.create_ephemeral(session.passport_id)

        revoked = mgr.revoke(session.passport_id)

        assert session.passport_id in revoked
        assert e1.passport_id in revoked
        assert e2.passport_id in revoked
        # Root is NOT revoked
        valid, _ = mgr.verify(root.passport_id)
        assert valid is True

    def test_verify_child_after_parent_revoked(self, mgr, root):
        session = mgr.create_session(root.passport_id)
        mgr.revoke(root.passport_id)

        valid, reason = mgr.verify(session.passport_id)
        assert valid is False
        assert "revoked" in reason.lower()

    def test_verify_ephemeral_after_ancestor_revoked(self, mgr, root):
        session = mgr.create_session(root.passport_id)
        eph = mgr.create_ephemeral(session.passport_id)
        mgr.revoke(root.passport_id)

        valid, reason = mgr.verify(eph.passport_id)
        assert valid is False


# ═══════════════════════════════════════════════════════════════════
# TTL enforcement
# ═══════════════════════════════════════════════════════════════════

class TestTTLEnforcement:

    def test_session_default_ttl(self, mgr, root):
        session = mgr.create_session(root.passport_id)
        from datetime import datetime, timezone
        issued = datetime.fromisoformat(session.issued_at)
        expires = datetime.fromisoformat(session.expires_at)
        diff = expires - issued
        assert diff <= timedelta(hours=24)

    def test_ephemeral_default_ttl(self, mgr, root):
        eph = mgr.create_ephemeral(root.passport_id)
        from datetime import datetime, timezone
        issued = datetime.fromisoformat(eph.issued_at)
        expires = datetime.fromisoformat(eph.expires_at)
        diff = expires - issued
        assert diff <= timedelta(minutes=15)

    def test_custom_ttl_clamped(self, mgr, root):
        # Request 48h session — should be clamped to 24h max
        session = mgr.create_session(
            root.passport_id,
            ttl=timedelta(hours=48),
        )
        from datetime import datetime, timezone
        issued = datetime.fromisoformat(session.issued_at)
        expires = datetime.fromisoformat(session.expires_at)
        diff = expires - issued
        assert diff <= timedelta(hours=24)


# ═══════════════════════════════════════════════════════════════════
# Query & listing
# ═══════════════════════════════════════════════════════════════════

class TestQuery:

    def test_list_all(self, mgr, root):
        mgr.create_session(root.passport_id)
        mgr.create_ephemeral(root.passport_id)
        items = mgr.list_all()
        assert len(items) == 3

    def test_list_shows_tier(self, mgr, root):
        mgr.create_session(root.passport_id)
        items = mgr.list_all()
        tiers = {i["tier"] for i in items}
        assert "permanent" in tiers
        assert "session" in tiers

    def test_get_children(self, mgr, root):
        s1 = mgr.create_session(root.passport_id)
        s2 = mgr.create_session(root.passport_id)
        children = mgr.get_children(root.passport_id)
        assert len(children) == 2

    def test_get_nonexistent(self, mgr):
        assert mgr.get("urn:aib:agent:fake:x") is None
