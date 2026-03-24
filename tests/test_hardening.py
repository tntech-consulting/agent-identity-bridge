"""Tests for security hardening — auto-rotation + multi-signature."""

import pytest
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from aib.security_hardening import (
    AutoRotationManager, KeyLifecycle, RotationEvent, RotationPolicy,
    MultiSigVerifier, MultiSigPolicy, SignatureSlot, MultiSigResult,
)


# ── Helpers ───────────────────────────────────────────────────────

def make_rsa_key():
    return rsa.generate_private_key(65537, 2048, default_backend())


def past_date(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


# ═══════════════════════════════════════════════════════════════════
# Auto-Rotation
# ═══════════════════════════════════════════════════════════════════

class TestKeyLifecycle:

    def test_new_key_not_needs_rotation(self):
        lc = KeyLifecycle(kid="k1", created_at=datetime.now(timezone.utc).isoformat())
        assert lc.needs_rotation is False
        assert lc.age_days < 1

    def test_old_key_needs_rotation(self):
        lc = KeyLifecycle(kid="k1", created_at=past_date(91), max_age_days=90)
        assert lc.needs_rotation is True

    def test_days_until_rotation(self):
        lc = KeyLifecycle(kid="k1", created_at=past_date(80), max_age_days=90)
        assert 9 < lc.days_until_rotation < 11

    def test_rotated_key_not_needs_rotation(self):
        lc = KeyLifecycle(kid="k1", created_at=past_date(100), max_age_days=90, status="rotated")
        assert lc.needs_rotation is False  # Already rotated

    def test_to_dict(self):
        lc = KeyLifecycle(kid="k1", created_at=datetime.now(timezone.utc).isoformat())
        d = lc.to_dict()
        assert d["kid"] == "k1"
        assert d["status"] == "active"
        assert "age_days" in d


class TestAutoRotation:

    @pytest.fixture
    def arm(self):
        return AutoRotationManager(max_age_days=90)

    def test_register_key(self, arm):
        lc = arm.register_key("k1")
        assert lc.kid == "k1"
        assert arm.active_kid == "k1"

    def test_check_rotation_no_key(self, arm):
        assert arm.check_rotation() is True

    def test_check_rotation_fresh_key(self, arm):
        arm.register_key("k1")
        assert arm.check_rotation() is False

    def test_check_rotation_expired_key(self, arm):
        arm.register_key("k1", created_at=past_date(91))
        assert arm.check_rotation() is True

    def test_auto_rotate(self, arm):
        arm.register_key("old-key", created_at=past_date(91))
        event = arm.auto_rotate("new-key")

        assert event.old_kid == "old-key"
        assert event.new_kid == "new-key"
        assert event.policy == RotationPolicy.SCHEDULED
        assert event.old_key_status == "retained"
        assert arm.active_kid == "new-key"

    def test_auto_rotate_retains_old_key(self, arm):
        arm.register_key("old-key")
        arm.auto_rotate("new-key")

        old = arm.get_lifecycle("old-key")
        assert old.status == "rotated"
        assert old.rotated_at is not None

    def test_emergency_rotate(self, arm):
        arm.register_key("compromised-key")
        event = arm.emergency_rotate("emergency-key", revoke_old=True, reason="Key exposed in logs")

        assert event.policy == RotationPolicy.EMERGENCY
        assert event.old_key_status == "revoked"

        old = arm.get_lifecycle("compromised-key")
        assert old.status == "revoked"
        assert old.revoked_at is not None

    def test_emergency_rotate_retain(self, arm):
        arm.register_key("old-key")
        event = arm.emergency_rotate("new-key", revoke_old=False)
        old = arm.get_lifecycle("old-key")
        assert old.status == "rotated"

    def test_is_key_valid_active(self, arm):
        arm.register_key("k1")
        valid, reason = arm.is_key_valid("k1")
        assert valid is True

    def test_is_key_valid_revoked(self, arm):
        arm.register_key("k1")
        arm.emergency_rotate("k2", revoke_old=True)
        valid, reason = arm.is_key_valid("k1")
        assert valid is False
        assert "revoked" in reason.lower()

    def test_is_key_valid_unknown(self, arm):
        valid, reason = arm.is_key_valid("nonexistent")
        assert valid is False

    def test_record_signature(self, arm):
        arm.register_key("k1")
        arm.record_signature("k1")
        arm.record_signature("k1")
        lc = arm.get_lifecycle("k1")
        assert lc.signatures_count == 2

    def test_list_keys(self, arm):
        arm.register_key("k1")
        arm.auto_rotate("k2")
        keys = arm.list_keys()
        assert len(keys) == 2

    def test_get_events(self, arm):
        arm.register_key("k1")
        arm.auto_rotate("k2")
        arm.emergency_rotate("k3")
        events = arm.get_events()
        assert len(events) == 2

    def test_rotation_event_to_dict(self, arm):
        arm.register_key("k1")
        event = arm.auto_rotate("k2")
        d = event.to_dict()
        assert d["old_kid"] == "k1"
        assert d["new_kid"] == "k2"
        assert d["policy"] == "scheduled"


# ═══════════════════════════════════════════════════════════════════
# Multi-Signature
# ═══════════════════════════════════════════════════════════════════

class TestMultiSigPolicy:

    def test_policy_creation(self):
        policy = MultiSigPolicy(
            required_signatures=2,
            total_signers=3,
            signer_ids=["gateway", "oidc", "admin"],
        )
        assert policy.required_signatures == 2
        assert policy.total_signers == 3

    def test_policy_to_dict(self):
        policy = MultiSigPolicy(2, 3, ["a", "b", "c"], "Test policy")
        d = policy.to_dict()
        assert d["required_signatures"] == 2
        assert d["description"] == "Test policy"


class TestMultiSigSigning:

    @pytest.fixture
    def setup_2of3(self):
        policy = MultiSigPolicy(
            required_signatures=2,
            total_signers=3,
            signer_ids=["gateway", "oidc", "admin"],
        )
        verifier = MultiSigVerifier(policy)

        keys = {}
        for signer in ["gateway", "oidc", "admin"]:
            key = make_rsa_key()
            keys[signer] = key
            verifier.register_signer(signer, private_key=key)

        return verifier, keys

    def test_sign_and_verify_2of3(self, setup_2of3):
        verifier, keys = setup_2of3
        payload = {"passport_id": "urn:aib:agent:acme:bot", "action": "test"}
        digest = verifier.compute_digest(payload)

        sig1 = verifier.sign(digest, "gateway")
        sig2 = verifier.sign(digest, "oidc")

        result = verifier.verify(digest, [sig1, sig2])
        assert result.valid is True
        assert result.valid_signatures == 2

    def test_1of3_insufficient(self, setup_2of3):
        verifier, keys = setup_2of3
        digest = verifier.compute_digest({"test": True})

        sig1 = verifier.sign(digest, "gateway")

        result = verifier.verify(digest, [sig1])
        assert result.valid is False
        assert result.valid_signatures == 1
        assert "INSUFFICIENT" in result.reason

    def test_3of3_valid(self, setup_2of3):
        verifier, keys = setup_2of3
        digest = verifier.compute_digest({"test": True})

        sigs = [verifier.sign(digest, s) for s in ["gateway", "oidc", "admin"]]
        result = verifier.verify(digest, sigs)
        assert result.valid is True
        assert result.valid_signatures == 3

    def test_tampered_digest_fails(self, setup_2of3):
        verifier, keys = setup_2of3
        digest = verifier.compute_digest({"original": True})

        sig1 = verifier.sign(digest, "gateway")
        sig2 = verifier.sign(digest, "oidc")

        # Verify with different digest
        tampered = verifier.compute_digest({"tampered": True})
        result = verifier.verify(tampered, [sig1, sig2])
        assert result.valid is False
        assert result.valid_signatures == 0

    def test_duplicate_signer_rejected(self, setup_2of3):
        verifier, keys = setup_2of3
        digest = verifier.compute_digest({"test": True})

        sig1 = verifier.sign(digest, "gateway")
        sig2 = verifier.sign(digest, "gateway")  # Same signer twice

        result = verifier.verify(digest, [sig1, sig2])
        assert result.valid is False
        assert result.valid_signatures == 1
        assert any("Duplicate" in d["reason"] for d in result.details)

    def test_unauthorized_signer_rejected(self, setup_2of3):
        verifier, keys = setup_2of3

        # Register an unauthorized signer manually
        rogue_key = make_rsa_key()
        verifier._private_keys["rogue"] = rogue_key
        verifier._public_keys["rogue"] = rogue_key.public_key()

        digest = verifier.compute_digest({"test": True})
        sig_rogue = SignatureSlot(
            signer_id="rogue", kid="rogue-key",
            signature=rogue_key.sign(
                digest,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                utils.Prehashed(hashes.SHA256()),
            ),
            signed_at="2026-01-01",
        )
        sig_legit = verifier.sign(digest, "gateway")

        result = verifier.verify(digest, [sig_rogue, sig_legit])
        assert result.valid is False  # Only 1 legit signature
        assert any("Unauthorized" in d["reason"] for d in result.details)


class TestMultiSig1of1:
    """Test simple single-signer mode (backward compatible)."""

    def test_1of1(self):
        policy = MultiSigPolicy(1, 1, ["gateway"])
        verifier = MultiSigVerifier(policy)
        key = make_rsa_key()
        verifier.register_signer("gateway", private_key=key)

        digest = verifier.compute_digest({"passport_id": "test"})
        sig = verifier.sign(digest, "gateway")
        result = verifier.verify(digest, [sig])
        assert result.valid is True


class TestMultiSigEdgeCases:

    def test_register_unknown_signer_raises(self):
        policy = MultiSigPolicy(1, 1, ["gateway"])
        verifier = MultiSigVerifier(policy)
        with pytest.raises(ValueError, match="not in policy"):
            verifier.register_signer("rogue", private_key=make_rsa_key())

    def test_sign_without_key_raises(self):
        policy = MultiSigPolicy(1, 1, ["gateway"])
        verifier = MultiSigVerifier(policy)
        digest = b"x" * 32
        with pytest.raises(ValueError, match="No private key"):
            verifier.sign(digest, "gateway")

    def test_result_bool(self):
        r = MultiSigResult(True, 2, 2, 2, [], "ok")
        assert bool(r) is True
        r2 = MultiSigResult(False, 1, 2, 1, [], "fail")
        assert bool(r2) is False

    def test_result_to_dict(self):
        r = MultiSigResult(True, 2, 2, 2, [{"signer_id": "a", "valid": True}], "ok")
        d = r.to_dict()
        assert d["valid"] is True
        assert d["valid_signatures"] == 2

    def test_signature_slot_serialization(self):
        key = make_rsa_key()
        import hashlib
        digest = hashlib.sha256(b"test").digest()
        sig_bytes = key.sign(
            digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            utils.Prehashed(hashes.SHA256()),
        )
        slot = SignatureSlot(
            signer_id="test", kid="k1", signature=sig_bytes,
            signed_at="2026-01-01", signer_role="primary",
        )
        d = slot.to_dict()
        restored = SignatureSlot.from_dict(d)
        assert restored.signer_id == "test"
        assert restored.signature == sig_bytes
