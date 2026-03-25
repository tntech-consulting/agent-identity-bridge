"""Tests for Sprint 4b — Multi-sig & Federation hardening."""

import time
import pytest
from aib.sprint4b import (
    MultiSigWithTimeout, SignatureRequest, SignatureTimeoutError,
    SignatureAuditor, SignatureAuditEvent,
    FederatedJWKSCache, CachedJWKS,
)


# ═══════════════════════════════════════════════════════════════════
# 1. SIGNATURE TIMEOUT
# ═══════════════════════════════════════════════════════════════════

class TestMultiSigTimeout:

    @pytest.fixture
    def msig(self):
        return MultiSigWithTimeout(default_timeout=2)

    def test_create_request(self, msig):
        req = msig.create_request("hash123", required_signers=2, total_signers=3)
        assert req.status == "pending"
        assert req.required_signers == 2
        assert req.remaining_seconds > 0

    def test_add_signature(self, msig):
        req = msig.create_request("hash123", 2, 3)
        completed = msig.add_signature(req.request_id, "key-1", "sig1")
        assert completed is False

    def test_complete_with_enough_sigs(self, msig):
        req = msig.create_request("hash123", 2, 3)
        msig.add_signature(req.request_id, "key-1", "sig1")
        completed = msig.add_signature(req.request_id, "key-2", "sig2")
        assert completed is True
        assert msig.is_complete(req.request_id)

    def test_timeout_rejects_late_signature(self):
        msig = MultiSigWithTimeout(default_timeout=0.5)
        req = msig.create_request("hash123", 2, 3)
        msig.add_signature(req.request_id, "key-1", "sig1")

        time.sleep(0.6)

        with pytest.raises(SignatureTimeoutError, match="expired"):
            msig.add_signature(req.request_id, "key-2", "sig2")

    def test_duplicate_signer_rejected(self, msig):
        req = msig.create_request("hash123", 2, 3)
        msig.add_signature(req.request_id, "key-1", "sig1")
        with pytest.raises(ValueError, match="already signed"):
            msig.add_signature(req.request_id, "key-1", "sig_again")

    def test_unknown_request(self, msig):
        with pytest.raises(ValueError, match="Unknown"):
            msig.add_signature("nonexistent", "key-1", "sig1")

    def test_cancel(self, msig):
        req = msig.create_request("hash123", 2, 3)
        assert msig.cancel(req.request_id) is True
        with pytest.raises(ValueError, match="cancelled"):
            msig.add_signature(req.request_id, "key-1", "sig1")

    def test_get_request(self, msig):
        req = msig.create_request("hash123", 2, 3)
        msig.add_signature(req.request_id, "key-1", "sig1")
        info = msig.get_request(req.request_id)
        assert info["collected"] == 1
        assert info["required"] == 2
        assert info["status"] == "pending"

    def test_get_expired_request(self):
        msig = MultiSigWithTimeout(default_timeout=0.3)
        req = msig.create_request("hash123", 2, 3)
        time.sleep(0.4)
        info = msig.get_request(req.request_id)
        assert info["status"] == "expired"

    def test_cleanup_expired(self):
        msig = MultiSigWithTimeout(default_timeout=0.3)
        msig.create_request("h1", 2, 3)
        msig.create_request("h2", 2, 3)
        time.sleep(0.4)
        count = msig.cleanup_expired()
        assert count == 2

    def test_pending_count(self, msig):
        msig.create_request("h1", 2, 3)
        msig.create_request("h2", 2, 3)
        assert msig.pending_count == 2

    def test_custom_timeout(self):
        msig = MultiSigWithTimeout(default_timeout=300)
        req = msig.create_request("h1", 2, 3, timeout_seconds=1)
        assert req.timeout_seconds == 1

    def test_to_dict(self, msig):
        req = msig.create_request("hash123", 2, 3)
        d = req.to_dict()
        assert d["status"] == "pending"
        assert d["required"] == 2
        assert "request_id" in d
        assert "signers" in d


# ═══════════════════════════════════════════════════════════════════
# 2. SIGNATURE AUDIT TRAIL
# ═══════════════════════════════════════════════════════════════════

class TestSignatureAuditor:

    @pytest.fixture
    def auditor(self):
        return SignatureAuditor()

    def test_record_create(self, auditor):
        event = auditor.record("req-1", "create", payload_hash="abc")
        assert event.action == "create"
        assert event.event_id.startswith("sigaudit_")

    def test_record_sign(self, auditor):
        event = auditor.record("req-1", "sign", kid="key-1")
        assert event.kid == "key-1"

    def test_query_by_request(self, auditor):
        auditor.record("req-1", "create")
        auditor.record("req-1", "sign", kid="key-1")
        auditor.record("req-2", "create")
        results = auditor.query(request_id="req-1")
        assert len(results) == 2

    def test_query_by_action(self, auditor):
        auditor.record("req-1", "create")
        auditor.record("req-1", "sign", kid="key-1")
        auditor.record("req-1", "sign", kid="key-2")
        auditor.record("req-1", "complete")
        results = auditor.query(action="sign")
        assert len(results) == 2

    def test_query_by_kid(self, auditor):
        auditor.record("req-1", "sign", kid="key-1")
        auditor.record("req-1", "sign", kid="key-2")
        results = auditor.query(kid="key-1")
        assert len(results) == 1

    def test_count(self, auditor):
        auditor.record("req-1", "create")
        auditor.record("req-1", "sign", kid="k1")
        assert auditor.count() == 2

    def test_count_by_action(self, auditor):
        auditor.record("r1", "create")
        auditor.record("r1", "sign", kid="k1")
        auditor.record("r1", "sign", kid="k2")
        auditor.record("r1", "complete")
        counts = auditor.count_by_action()
        assert counts["create"] == 1
        assert counts["sign"] == 2
        assert counts["complete"] == 1

    def test_event_to_dict(self, auditor):
        event = auditor.record("req-1", "sign", kid="key-1", detail="Signed by admin")
        d = event.to_dict()
        assert d["action"] == "sign"
        assert d["kid"] == "key-1"
        assert d["detail"] == "Signed by admin"


# ═══════════════════════════════════════════════════════════════════
# 3. FEDERATED JWKS CACHE
# ═══════════════════════════════════════════════════════════════════

class TestFederatedJWKSCache:

    @pytest.fixture
    def cache(self):
        return FederatedJWKSCache(default_ttl=2)

    def mock_fetcher(self, url):
        return {"keys": [{"kid": "test", "kty": "RSA", "url": url}]}

    def test_register_and_refresh(self, cache):
        cache.register("urn:aib:org:partner", "https://partner.com/keys")
        success = cache.refresh("urn:aib:org:partner", self.mock_fetcher)
        assert success is True
        jwks = cache.get("urn:aib:org:partner")
        assert jwks is not None
        assert len(jwks["keys"]) == 1

    def test_get_unregistered(self, cache):
        assert cache.get("urn:aib:org:unknown") is None

    def test_needs_refresh_uncached(self, cache):
        cache.register("urn:aib:org:partner", "https://partner.com/keys")
        assert cache.needs_refresh("urn:aib:org:partner") is True

    def test_needs_refresh_after_cache(self, cache):
        cache.register("urn:aib:org:partner", "https://partner.com/keys")
        cache.refresh("urn:aib:org:partner", self.mock_fetcher)
        assert cache.needs_refresh("urn:aib:org:partner") is False

    def test_ttl_expiry(self):
        cache = FederatedJWKSCache(default_ttl=0.5)
        cache.register("urn:aib:org:partner", "https://partner.com/keys")
        cache.refresh("urn:aib:org:partner", self.mock_fetcher)
        assert cache.needs_refresh("urn:aib:org:partner") is False

        time.sleep(0.6)
        assert cache.needs_refresh("urn:aib:org:partner") is True
        assert cache.is_stale("urn:aib:org:partner") is True

    def test_stale_cache_still_returns_data(self):
        cache = FederatedJWKSCache(default_ttl=0.3)
        cache.register("urn:aib:org:partner", "https://partner.com/keys")
        cache.refresh("urn:aib:org:partner", self.mock_fetcher)

        time.sleep(0.4)
        jwks = cache.get("urn:aib:org:partner")
        assert jwks is not None  # Stale but still available

    def test_failed_refresh_keeps_stale(self, cache):
        cache.register("urn:aib:org:partner", "https://partner.com/keys")
        cache.refresh("urn:aib:org:partner", self.mock_fetcher)

        # Failed refresh
        success = cache.refresh("urn:aib:org:partner", lambda url: None)
        assert success is False

        # Original data still available
        jwks = cache.get("urn:aib:org:partner")
        assert jwks is not None

    def test_refresh_all(self, cache):
        cache.register("urn:aib:org:a", "https://a.com/keys")
        cache.register("urn:aib:org:b", "https://b.com/keys")
        results = cache.refresh_all(self.mock_fetcher)
        assert results["urn:aib:org:a"] is True
        assert results["urn:aib:org:b"] is True
        assert cache.cached_count == 2

    def test_list_issuers(self, cache):
        cache.register("urn:aib:org:a", "https://a.com/keys")
        cache.register("urn:aib:org:b", "https://b.com/keys")
        cache.refresh("urn:aib:org:a", self.mock_fetcher)
        issuers = cache.list_issuers()
        assert len(issuers) == 2
        cached_issuer = next(i for i in issuers if i["issuer"] == "urn:aib:org:a")
        assert cached_issuer["cached"] is True

    def test_get_age(self, cache):
        cache.register("urn:aib:org:partner", "https://partner.com/keys")
        cache.refresh("urn:aib:org:partner", self.mock_fetcher)
        age = cache.get_age("urn:aib:org:partner")
        assert age is not None
        assert age < 1.0

    def test_unregistered_refresh(self, cache):
        success = cache.refresh("urn:aib:org:unknown", self.mock_fetcher)
        assert success is False
