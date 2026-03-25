"""Tests for Sprint 5 — Enterprise hardening."""

import time
import threading
import pytest
from aib.sprint5_enterprise import (
    CircuitBreaker, CircuitState, CircuitBreakerError,
    AlgorithmRegistry, SigningAlgorithm, ALGORITHM_PROFILES,
    SignedCRL, CRLEntry,
)


# ═══════════════════════════════════════════════════════════════════
# 1. CIRCUIT BREAKER
# ═══════════════════════════════════════════════════════════════════

class TestCircuitBreaker:

    @pytest.fixture
    def cb(self):
        return CircuitBreaker(failure_threshold=3, recovery_timeout=1.0)

    def test_initial_state_closed(self, cb):
        assert cb.get_state("https://partner.com") == CircuitState.CLOSED

    def test_allows_request_when_closed(self, cb):
        assert cb.allow_request("https://partner.com") is True

    def test_stays_closed_under_threshold(self, cb):
        cb.record_failure("https://partner.com")
        cb.record_failure("https://partner.com")
        assert cb.get_state("https://partner.com") == CircuitState.CLOSED
        assert cb.allow_request("https://partner.com") is True

    def test_opens_at_threshold(self, cb):
        for _ in range(3):
            cb.record_failure("https://partner.com")
        assert cb.get_state("https://partner.com") == CircuitState.OPEN

    def test_blocks_when_open(self, cb):
        for _ in range(3):
            cb.record_failure("https://partner.com")
        assert cb.allow_request("https://partner.com") is False

    def test_transitions_to_half_open(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.3)
        cb.record_failure("t")
        cb.record_failure("t")
        assert cb.get_state("t") == CircuitState.OPEN

        time.sleep(0.4)
        assert cb.get_state("t") == CircuitState.HALF_OPEN

    def test_half_open_success_closes(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.3)
        cb.record_failure("t")
        cb.record_failure("t")
        time.sleep(0.4)

        assert cb.allow_request("t") is True  # half-open allows one
        cb.record_success("t")
        assert cb.get_state("t") == CircuitState.CLOSED

    def test_half_open_failure_reopens(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.3)
        cb.record_failure("t")
        cb.record_failure("t")
        time.sleep(0.4)

        cb.allow_request("t")
        cb.record_failure("t")
        assert cb.get_state("t") == CircuitState.OPEN

    def test_independent_targets(self, cb):
        for _ in range(3):
            cb.record_failure("https://bad.com")
        assert cb.get_state("https://bad.com") == CircuitState.OPEN
        assert cb.get_state("https://good.com") == CircuitState.CLOSED

    def test_reset(self, cb):
        for _ in range(3):
            cb.record_failure("t")
        assert cb.get_state("t") == CircuitState.OPEN
        cb.reset("t")
        assert cb.get_state("t") == CircuitState.CLOSED

    def test_get_stats(self, cb):
        cb.record_success("t")
        cb.record_failure("t")
        stats = cb.get_stats("t")
        assert stats["successes"] == 1
        assert stats["failures"] == 1
        assert stats["state"] == "closed"

    def test_list_open_circuits(self, cb):
        for _ in range(3):
            cb.record_failure("https://a.com")
        for _ in range(3):
            cb.record_failure("https://b.com")
        open_circuits = cb.list_open_circuits()
        assert set(open_circuits) == {"https://a.com", "https://b.com"}

    def test_total_circuits(self, cb):
        cb.allow_request("a")
        cb.allow_request("b")
        cb.allow_request("c")
        assert cb.total_circuits == 3

    def test_thread_safe(self):
        cb = CircuitBreaker(failure_threshold=100, recovery_timeout=10)
        def hammer():
            for i in range(50):
                cb.record_failure("shared")
                cb.record_success("shared")

        threads = [threading.Thread(target=hammer) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # No crash, state consistent
        stats = cb.get_stats("shared")
        assert stats["failures"] == 200
        assert stats["successes"] == 200


# ═══════════════════════════════════════════════════════════════════
# 2. MULTI-ALGORITHM SUPPORT
# ═══════════════════════════════════════════════════════════════════

class TestAlgorithmRegistry:

    @pytest.fixture
    def registry(self):
        return AlgorithmRegistry(default=SigningAlgorithm.RS256)

    def test_default(self, registry):
        assert registry.default == SigningAlgorithm.RS256

    def test_all_accepted_by_default(self, registry):
        assert registry.is_accepted(SigningAlgorithm.RS256)
        assert registry.is_accepted(SigningAlgorithm.ES256)
        assert registry.is_accepted(SigningAlgorithm.EdDSA)

    def test_set_default(self, registry):
        registry.set_default(SigningAlgorithm.ES256)
        assert registry.default == SigningAlgorithm.ES256

    def test_restrict_accepted(self, registry):
        registry.set_accepted([SigningAlgorithm.RS256, SigningAlgorithm.ES256])
        assert registry.is_accepted(SigningAlgorithm.RS256)
        assert registry.is_accepted(SigningAlgorithm.ES256)
        assert not registry.is_accepted(SigningAlgorithm.EdDSA)

    def test_default_moves_if_not_accepted(self):
        reg = AlgorithmRegistry(default=SigningAlgorithm.EdDSA)
        reg.set_accepted([SigningAlgorithm.RS256, SigningAlgorithm.ES256])
        assert reg.default in [SigningAlgorithm.RS256, SigningAlgorithm.ES256]

    def test_get_profile(self, registry):
        profile = registry.get_profile(SigningAlgorithm.ES256)
        assert profile.key_size_bits == 256
        assert profile.speed == "faster"

    def test_validate_valid(self, registry):
        valid, _ = registry.validate_algorithm("RS256")
        assert valid is True

    def test_validate_unknown(self, registry):
        valid, reason = registry.validate_algorithm("XYZ999")
        assert valid is False
        assert "unknown" in reason.lower()

    def test_validate_not_accepted(self):
        reg = AlgorithmRegistry(default=SigningAlgorithm.RS256)
        reg.set_accepted([SigningAlgorithm.RS256])
        valid, reason = reg.validate_algorithm("EdDSA")
        assert valid is False
        assert "not accepted" in reason.lower()

    def test_list_accepted(self, registry):
        accepted = registry.list_accepted()
        assert len(accepted) == 3
        names = [a["algorithm"] for a in accepted]
        assert "RS256" in names

    def test_profiles_complete(self):
        for algo in SigningAlgorithm:
            assert algo in ALGORITHM_PROFILES
            p = ALGORITHM_PROFILES[algo]
            assert p.key_size_bits > 0
            assert p.signature_size_bytes > 0
            assert p.speed in ("fast", "faster", "fastest")

    def test_es256_profile(self):
        p = ALGORITHM_PROFILES[SigningAlgorithm.ES256]
        assert p.name == "ECDSA P-256"
        assert p.signature_size_bytes == 64

    def test_eddsa_profile(self):
        p = ALGORITHM_PROFILES[SigningAlgorithm.EdDSA]
        assert p.name == "Ed25519"
        assert p.speed == "fastest"


# ═══════════════════════════════════════════════════════════════════
# 3. SIGNED CRL
# ═══════════════════════════════════════════════════════════════════

class TestSignedCRL:

    @pytest.fixture
    def crl(self):
        return SignedCRL(issuer="urn:aib:org:acme")

    def test_empty_crl(self, crl):
        assert crl.count == 0
        assert crl.version == 0

    def test_revoke(self, crl):
        crl.revoke("urn:aib:agent:acme:bot", reason="Key leak")
        assert crl.is_revoked("urn:aib:agent:acme:bot") is True
        assert crl.count == 1
        assert crl.version == 1

    def test_not_revoked(self, crl):
        assert crl.is_revoked("urn:aib:agent:acme:bot") is False

    def test_revoke_idempotent(self, crl):
        crl.revoke("urn:aib:agent:acme:bot")
        crl.revoke("urn:aib:agent:acme:bot")  # Again
        assert crl.count == 1
        assert crl.version == 1  # No version bump on duplicate

    def test_unrevoke(self, crl):
        crl.revoke("urn:aib:agent:acme:bot")
        assert crl.unrevoke("urn:aib:agent:acme:bot") is True
        assert crl.is_revoked("urn:aib:agent:acme:bot") is False

    def test_unrevoke_nonexistent(self, crl):
        assert crl.unrevoke("nonexistent") is False

    def test_get_entry(self, crl):
        crl.revoke("urn:aib:agent:acme:bot", reason="Compromised")
        entry = crl.get_entry("urn:aib:agent:acme:bot")
        assert entry is not None
        assert entry["reason"] == "Compromised"
        assert "revoked_at" in entry

    def test_to_document(self, crl):
        crl.revoke("urn:aib:agent:acme:a")
        crl.revoke("urn:aib:agent:acme:b")
        doc = crl.to_document()
        assert doc["issuer"] == "urn:aib:org:acme"
        assert doc["total_revoked"] == 2
        assert doc["version"] == 2
        assert "crl_hash" in doc
        assert "generated_at" in doc
        assert len(doc["entries"]) == 2

    def test_crl_hash_changes(self, crl):
        crl.revoke("urn:aib:agent:acme:a")
        hash1 = crl.to_document()["crl_hash"]
        crl.revoke("urn:aib:agent:acme:b")
        hash2 = crl.to_document()["crl_hash"]
        assert hash1 != hash2

    def test_list_revoked(self, crl):
        crl.revoke("a")
        crl.revoke("b")
        crl.revoke("c")
        assert set(crl.list_revoked()) == {"a", "b", "c"}

    def test_check_batch(self, crl):
        crl.revoke("a")
        crl.revoke("b")
        result = crl.check_batch(["a", "b", "c"])
        assert result == {"a": True, "b": True, "c": False}

    def test_version_increments(self, crl):
        crl.revoke("a")
        assert crl.version == 1
        crl.revoke("b")
        assert crl.version == 2
        crl.unrevoke("a")
        assert crl.version == 3

    def test_thread_safe(self):
        crl = SignedCRL(issuer="urn:aib:org:test")
        def revoke_batch(prefix):
            for i in range(50):
                crl.revoke(f"{prefix}-{i}")

        threads = [threading.Thread(target=revoke_batch, args=(f"t{t}",)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert crl.count == 200
