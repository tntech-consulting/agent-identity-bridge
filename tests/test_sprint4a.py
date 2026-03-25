"""Tests for Sprint 4a — Compliance & GDPR avancé."""

import time
import pytest
from datetime import datetime, timezone, timedelta
from aib.sprint4a import (
    canonicalize, canonical_hash, canonical_equals,
    RetentionPolicy, RetentionManager,
    GDPRRightsManager, ProcessingStatus,
    validate_issuer, IssuerValidationError,
)


# ═══════════════════════════════════════════════════════════════════
# 1. JSON CANONICALIZATION
# ═══════════════════════════════════════════════════════════════════

class TestCanonicalization:

    def test_key_sorting(self):
        assert canonicalize({"b": 2, "a": 1}) == '{"a":1,"b":2}'

    def test_nested_sorting(self):
        obj = {"z": {"b": 2, "a": 1}, "a": 0}
        result = canonicalize(obj)
        assert result == '{"a":0,"z":{"a":1,"b":2}}'

    def test_no_whitespace(self):
        result = canonicalize({"key": "value"})
        assert " " not in result

    def test_array_order_preserved(self):
        result = canonicalize({"items": [3, 1, 2]})
        assert result == '{"items":[3,1,2]}'

    def test_empty_object(self):
        assert canonicalize({}) == '{}'

    def test_empty_array(self):
        assert canonicalize([]) == '[]'

    def test_null_value(self):
        assert canonicalize({"a": None}) == '{"a":null}'

    def test_boolean(self):
        assert canonicalize({"t": True, "f": False}) == '{"f":false,"t":true}'

    def test_canonical_hash_deterministic(self):
        h1 = canonical_hash({"b": 2, "a": 1})
        h2 = canonical_hash({"a": 1, "b": 2})
        assert h1 == h2

    def test_canonical_hash_different_data(self):
        h1 = canonical_hash({"a": 1})
        h2 = canonical_hash({"a": 2})
        assert h1 != h2

    def test_canonical_equals(self):
        assert canonical_equals({"b": 2, "a": 1}, {"a": 1, "b": 2})
        assert not canonical_equals({"a": 1}, {"a": 2})

    def test_passport_canonical(self):
        """Two passports with same data but different key order → same hash."""
        p1 = {
            "passport_id": "urn:aib:agent:acme:bot",
            "issuer": "urn:aib:org:acme",
            "capabilities": ["booking"],
        }
        p2 = {
            "capabilities": ["booking"],
            "issuer": "urn:aib:org:acme",
            "passport_id": "urn:aib:agent:acme:bot",
        }
        assert canonical_hash(p1) == canonical_hash(p2)

    def test_unicode(self):
        result = canonicalize({"name": "Héllo"})
        assert "Héllo" in result


# ═══════════════════════════════════════════════════════════════════
# 2. DATA RETENTION AUTO-SHRED
# ═══════════════════════════════════════════════════════════════════

class TestRetentionPolicy:

    def test_not_expired(self):
        p = RetentionPolicy(
            org_id="org-a",
            retention_days=365,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        assert p.is_expired() is False
        assert p.days_remaining() > 360

    def test_expired(self):
        past = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        p = RetentionPolicy(org_id="org-a", retention_days=5, created_at=past)
        assert p.is_expired() is True
        assert p.days_remaining() == 0

    def test_shredded_not_expired(self):
        past = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        p = RetentionPolicy(org_id="org-a", retention_days=5, created_at=past, shredded=True)
        assert p.is_expired() is False  # Already shredded


class TestRetentionManager:

    def test_set_and_get_policy(self):
        mgr = RetentionManager()
        mgr.set_policy("org-a", retention_days=365)
        p = mgr.get_policy("org-a")
        assert p is not None
        assert p.retention_days == 365

    def test_check_not_expired(self):
        mgr = RetentionManager()
        mgr.set_policy("org-a", retention_days=365)
        shredded = mgr.check_all()
        assert shredded == []

    def test_check_expired_triggers_shred(self):
        shred_log = []
        mgr = RetentionManager(shred_callback=lambda org: shred_log.append(org) or True)
        mgr.set_policy("org-a", retention_days=0)  # Expires immediately

        # Manually set created_at to the past
        mgr._policies["org-a"].created_at = (
            datetime.now(timezone.utc) - timedelta(days=1)
        ).isoformat()

        shredded = mgr.check_all()
        assert "org-a" in shredded
        assert "org-a" in shred_log
        assert mgr.get_policy("org-a").shredded is True

    def test_check_one(self):
        shred_log = []
        mgr = RetentionManager(shred_callback=lambda org: shred_log.append(org) or True)
        mgr.set_policy("org-a", retention_days=0)
        mgr._policies["org-a"].created_at = (
            datetime.now(timezone.utc) - timedelta(days=1)
        ).isoformat()

        result = mgr.check_one("org-a")
        assert result is True
        assert "org-a" in shred_log

    def test_double_shred_prevented(self):
        count = {"n": 0}
        mgr = RetentionManager(shred_callback=lambda org: (count.__setitem__("n", count["n"]+1)) or True)
        mgr.set_policy("org-a", retention_days=0)
        mgr._policies["org-a"].created_at = (
            datetime.now(timezone.utc) - timedelta(days=1)
        ).isoformat()

        mgr.check_all()
        mgr.check_all()  # Second check
        assert count["n"] == 1  # Only shredded once

    def test_list_expiring_soon(self):
        mgr = RetentionManager()
        mgr.set_policy("org-a", retention_days=3)
        mgr.set_policy("org-b", retention_days=365)
        expiring = mgr.list_expiring_soon(days=7)
        assert len(expiring) == 1
        assert expiring[0]["org_id"] == "org-a"


# ═══════════════════════════════════════════════════════════════════
# 3. GDPR RIGHTS (Art.18 + Art.21)
# ═══════════════════════════════════════════════════════════════════

class TestGDPRRights:

    @pytest.fixture
    def rights(self):
        return GDPRRightsManager()

    def test_default_active(self, rights):
        assert rights.can_process("org-a") is True

    def test_restrict(self, rights):
        rights.restrict("org-a", reason="Accuracy contested")
        assert rights.can_process("org-a") is False
        assert rights.is_restricted("org-a") is True

    def test_unrestrict(self, rights):
        rights.restrict("org-a")
        rights.unrestrict("org-a", reason="Accuracy verified")
        assert rights.can_process("org-a") is True
        assert rights.is_restricted("org-a") is False

    def test_object_purpose(self, rights):
        rights.object("org-a", purposes=["profiling"], reason="Subject objects")
        assert rights.is_objected("org-a", purpose="profiling") is True
        assert rights.is_objected("org-a", purpose="support") is False

    def test_object_multiple_purposes(self, rights):
        rights.object("org-a", purposes=["profiling", "marketing"])
        assert rights.is_objected("org-a", purpose="profiling") is True
        assert rights.is_objected("org-a", purpose="marketing") is True

    def test_withdraw_objection_specific(self, rights):
        rights.object("org-a", purposes=["profiling", "marketing"])
        rights.withdraw_objection("org-a", purposes=["profiling"])
        assert rights.is_objected("org-a", purpose="profiling") is False
        assert rights.is_objected("org-a", purpose="marketing") is True

    def test_withdraw_objection_all(self, rights):
        rights.object("org-a", purposes=["profiling", "marketing"])
        rights.withdraw_objection("org-a")
        assert rights.is_objected("org-a") is False
        assert rights.can_process("org-a") is True

    def test_history_tracked(self, rights):
        rights.restrict("org-a", reason="R1")
        rights.unrestrict("org-a", reason="R2")
        rec = rights.get_record("org-a")
        assert len(rec["history"]) == 2
        assert rec["history"][0]["action"] == "restrict"
        assert rec["history"][1]["action"] == "unrestrict"

    def test_list_restricted(self, rights):
        rights.restrict("org-a")
        rights.restrict("org-b")
        assert set(rights.list_restricted()) == {"org-a", "org-b"}

    def test_list_objected(self, rights):
        rights.object("org-a", purposes=["profiling"])
        assert rights.list_objected() == ["org-a"]

    def test_get_nonexistent(self, rights):
        assert rights.get_record("org-none") is None


# ═══════════════════════════════════════════════════════════════════
# 4. ISSUER VALIDATION
# ═══════════════════════════════════════════════════════════════════

class TestIssuerValidation:

    def test_valid_issuer(self):
        valid, _ = validate_issuer({"issuer": "urn:aib:org:acme"})
        assert valid is True

    def test_missing_issuer(self):
        valid, reason = validate_issuer({})
        assert valid is False
        assert "missing" in reason.lower()

    def test_invalid_format(self):
        valid, reason = validate_issuer({"issuer": "not-a-urn"})
        assert valid is False
        assert "format" in reason.lower()

    def test_missing_org_slug(self):
        valid, _ = validate_issuer({"issuer": "urn:aib:org:"})
        assert valid is False

    def test_expected_issuer_match(self):
        valid, _ = validate_issuer(
            {"issuer": "urn:aib:org:acme"},
            expected_issuer="urn:aib:org:acme",
        )
        assert valid is True

    def test_expected_issuer_mismatch(self):
        valid, reason = validate_issuer(
            {"issuer": "urn:aib:org:acme"},
            expected_issuer="urn:aib:org:other",
        )
        assert valid is False
        assert "mismatch" in reason.lower()

    def test_allowed_issuers_match(self):
        valid, _ = validate_issuer(
            {"issuer": "urn:aib:org:acme"},
            allowed_issuers=["urn:aib:org:acme", "urn:aib:org:partner"],
        )
        assert valid is True

    def test_allowed_issuers_no_match(self):
        valid, reason = validate_issuer(
            {"issuer": "urn:aib:org:stranger"},
            allowed_issuers=["urn:aib:org:acme"],
        )
        assert valid is False
        assert "not in allowed" in reason.lower()

    def test_iss_claim_fallback(self):
        """JWT standard uses 'iss' not 'issuer'."""
        valid, _ = validate_issuer({"iss": "urn:aib:org:acme"})
        assert valid is True

    def test_non_string_issuer(self):
        valid, reason = validate_issuer({"issuer": 12345})
        assert valid is False
        assert "string" in reason.lower()
