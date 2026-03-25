"""Tests for Sprint 6 — Final audit recommendations (45/45)."""

import time
import os
import pytest
from aib.sprint6_final import (
    sign_discovery_document, verify_signed_document, SignedDocumentError,
    generate_code_verifier, generate_code_challenge, verify_pkce,
    PKCEManager,
    TraceContext, new_trace_context, parse_traceparent,
    split_secret, reconstruct_secret, KeyCeremony,
)


# ═══════════════════════════════════════════════════════════════════
# 1. SIGNED DISCOVERY DOCUMENTS
# ═══════════════════════════════════════════════════════════════════

class TestSignedDiscovery:

    def test_sign_and_verify(self):
        doc = {"domain": "example.com", "issuer": "urn:aib:org:example"}
        signed = sign_discovery_document(doc, "my-secret")
        valid, reason = verify_signed_document(signed, "my-secret")
        assert valid is True
        assert "_signature" in signed
        assert "_signed_at" in signed

    def test_wrong_key_fails(self):
        doc = {"domain": "example.com"}
        signed = sign_discovery_document(doc, "correct-key")
        valid, reason = verify_signed_document(signed, "wrong-key")
        assert valid is False
        assert "mismatch" in reason.lower()

    def test_tampered_document_fails(self):
        doc = {"domain": "example.com"}
        signed = sign_discovery_document(doc, "my-secret")
        signed["domain"] = "attacker.com"  # Tamper
        valid, reason = verify_signed_document(signed, "my-secret")
        assert valid is False

    def test_missing_signature_fails(self):
        valid, reason = verify_signed_document({"domain": "test.com"}, "key")
        assert valid is False
        assert "missing" in reason.lower()

    def test_signature_is_deterministic(self):
        doc = {"a": 1, "b": 2}
        sig1 = sign_discovery_document(doc, "key")["_signature"]
        sig2 = sign_discovery_document(doc, "key")["_signature"]
        assert sig1 == sig2  # Same doc + key = same sig

    def test_different_docs_different_sigs(self):
        sig1 = sign_discovery_document({"a": 1}, "key")["_signature"]
        sig2 = sign_discovery_document({"a": 2}, "key")["_signature"]
        assert sig1 != sig2

    def test_underscore_fields_stripped(self):
        doc = {"domain": "test.com"}
        signed = sign_discovery_document(doc, "key")
        # Re-verify should work because _signature fields are stripped
        valid, _ = verify_signed_document(signed, "key")
        assert valid is True


# ═══════════════════════════════════════════════════════════════════
# 2. PKCE SUPPORT
# ═══════════════════════════════════════════════════════════════════

class TestPKCE:

    def test_verifier_length(self):
        v = generate_code_verifier(64)
        assert len(v) == 64

    def test_verifier_min_length(self):
        with pytest.raises(ValueError):
            generate_code_verifier(42)

    def test_verifier_max_length(self):
        with pytest.raises(ValueError):
            generate_code_verifier(129)

    def test_challenge_s256(self):
        v = generate_code_verifier()
        c = generate_code_challenge(v, "S256")
        assert len(c) == 43  # Base64url of SHA-256 without padding

    def test_challenge_plain(self):
        v = generate_code_verifier()
        c = generate_code_challenge(v, "plain")
        assert c == v

    def test_challenge_unknown_method(self):
        with pytest.raises(ValueError):
            generate_code_challenge("test", "MD5")

    def test_verify_s256(self):
        v = generate_code_verifier()
        c = generate_code_challenge(v, "S256")
        assert verify_pkce(v, c, "S256") is True

    def test_verify_wrong_verifier(self):
        v = generate_code_verifier()
        c = generate_code_challenge(v, "S256")
        assert verify_pkce("wrong-verifier-string-that-is-long-enough-43chars", c, "S256") is False

    def test_verify_plain(self):
        v = generate_code_verifier()
        c = generate_code_challenge(v, "plain")
        assert verify_pkce(v, c, "plain") is True


class TestPKCEManager:

    @pytest.fixture
    def mgr(self):
        return PKCEManager(ttl_seconds=2)

    def test_create_session(self, mgr):
        session = mgr.create_session()
        assert session.state == "pending"
        assert session.method == "S256"
        assert session.session_id.startswith("pkce_")

    def test_verify_and_consume(self, mgr):
        session = mgr.create_session()
        result = mgr.verify_and_consume(session.session_id, session.code_verifier)
        assert result is True

    def test_consumed_session_rejected(self, mgr):
        session = mgr.create_session()
        mgr.verify_and_consume(session.session_id, session.code_verifier)
        # Second use rejected
        result = mgr.verify_and_consume(session.session_id, session.code_verifier)
        assert result is False

    def test_wrong_verifier_rejected(self, mgr):
        session = mgr.create_session()
        result = mgr.verify_and_consume(session.session_id, "wrong-verifier-long-enough-string-43chars!!")
        assert result is False

    def test_expired_session(self):
        mgr = PKCEManager(ttl_seconds=0.3)
        session = mgr.create_session()
        time.sleep(0.4)
        result = mgr.verify_and_consume(session.session_id, session.code_verifier)
        assert result is False

    def test_unknown_session(self, mgr):
        assert mgr.verify_and_consume("nonexistent", "verifier") is False

    def test_active_count(self, mgr):
        mgr.create_session()
        mgr.create_session()
        assert mgr.active_count == 2

    def test_get_session(self, mgr):
        session = mgr.create_session()
        info = mgr.get_session(session.session_id)
        assert info is not None
        assert info["state"] == "pending"

    def test_cleanup(self):
        mgr = PKCEManager(ttl_seconds=0.2)
        mgr.create_session()
        mgr.create_session()
        time.sleep(0.3)
        count = mgr.cleanup_expired()
        assert count == 2


# ═══════════════════════════════════════════════════════════════════
# 3. OPENTELEMETRY CONTEXT PROPAGATION
# ═══════════════════════════════════════════════════════════════════

class TestTraceContext:

    def test_new_context(self):
        ctx = new_trace_context(passport_id="urn:aib:agent:test:bot", protocol="a2a")
        assert len(ctx.trace_id) == 32
        assert len(ctx.span_id) == 16
        assert ctx.passport_id == "urn:aib:agent:test:bot"

    def test_child_inherits_trace_id(self):
        parent = new_trace_context(passport_id="p1")
        child = new_trace_context(passport_id="p1", parent=parent)
        assert child.trace_id == parent.trace_id
        assert child.parent_span_id == parent.span_id
        assert child.span_id != parent.span_id

    def test_traceparent_format(self):
        ctx = new_trace_context()
        tp = ctx.to_traceparent()
        parts = tp.split("-")
        assert len(parts) == 4
        assert parts[0] == "00"
        assert len(parts[1]) == 32
        assert len(parts[2]) == 16

    def test_tracestate(self):
        ctx = new_trace_context(passport_id="p1", protocol="mcp")
        ts = ctx.to_tracestate()
        assert "aib_pid=p1" in ts
        assert "aib_proto=mcp" in ts

    def test_tracestate_empty(self):
        ctx = new_trace_context()
        assert ctx.to_tracestate() == ""

    def test_to_headers(self):
        ctx = new_trace_context(passport_id="p1")
        headers = ctx.to_headers()
        assert "traceparent" in headers
        assert "tracestate" in headers

    def test_to_dict(self):
        ctx = new_trace_context(passport_id="p1", protocol="a2a")
        d = ctx.to_dict()
        assert d["passport_id"] == "p1"
        assert d["protocol"] == "a2a"
        assert "traceparent" in d


class TestParseTraceparent:

    def test_valid(self):
        ctx = parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
        assert ctx is not None
        assert ctx.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
        assert ctx.span_id == "00f067aa0ba902b7"
        assert ctx.flags == "01"

    def test_invalid_version(self):
        assert parse_traceparent("ff-1234567890abcdef1234567890abcdef-1234567890abcdef-01") is None

    def test_wrong_format(self):
        assert parse_traceparent("not-a-traceparent") is None

    def test_short_trace_id(self):
        assert parse_traceparent("00-short-1234567890abcdef-01") is None

    def test_roundtrip(self):
        ctx = new_trace_context(passport_id="p1")
        tp = ctx.to_traceparent()
        parsed = parse_traceparent(tp)
        assert parsed.trace_id == ctx.trace_id
        assert parsed.span_id == ctx.span_id


# ═══════════════════════════════════════════════════════════════════
# 4. SHAMIR KEY CEREMONY
# ═══════════════════════════════════════════════════════════════════

class TestShamirSplitReconstruct:

    def test_3_of_5(self):
        secret = os.urandom(32)  # AES-256 key
        shares = split_secret(secret, shares_needed=3, total_shares=5)
        assert len(shares) == 5

        reconstructed = reconstruct_secret(shares[:3], secret_length=32)
        assert reconstructed == secret

    def test_2_of_3(self):
        secret = b"my-secret-key-32-bytes-padding!!"
        shares = split_secret(secret, shares_needed=2, total_shares=3)
        reconstructed = reconstruct_secret(shares[:2], secret_length=len(secret))
        assert reconstructed == secret

    def test_any_k_shares_work(self):
        secret = os.urandom(32)
        shares = split_secret(secret, shares_needed=3, total_shares=5)

        # Any 3 of the 5 should work
        import itertools
        for combo in itertools.combinations(shares, 3):
            result = reconstruct_secret(list(combo), 32)
            assert result == secret

    def test_insufficient_shares_fail(self):
        secret = os.urandom(32)
        shares = split_secret(secret, shares_needed=3, total_shares=5)
        # Only 2 shares — should NOT reconstruct correctly
        bad_result = reconstruct_secret(shares[:2], 32)
        assert bad_result != secret

    def test_shares_needed_greater_than_total(self):
        with pytest.raises(ValueError, match="shares_needed"):
            split_secret(os.urandom(32), shares_needed=6, total_shares=5)

    def test_shares_needed_minimum(self):
        with pytest.raises(ValueError, match="shares_needed"):
            split_secret(os.urandom(32), shares_needed=1, total_shares=3)

    def test_different_secrets_different_shares(self):
        s1 = split_secret(b"secret-a-32-bytes-padding!!!!!", 2, 3)
        s2 = split_secret(b"secret-b-32-bytes-padding!!!!!", 2, 3)
        assert s1[0][1] != s2[0][1]


class TestKeyCeremony:

    @pytest.fixture
    def ceremony(self):
        return KeyCeremony()

    def test_split_and_reconstruct(self, ceremony):
        secret = os.urandom(32)
        shares = ceremony.split(
            secret, shares_needed=3, total_shares=5,
            participants=["alice", "bob", "charlie", "dave", "eve"],
        )
        assert len(shares) == 5

        reconstructed = ceremony.reconstruct(
            shares[:3], key_length=32,
            participants=["alice", "bob", "charlie"],
        )
        assert reconstructed == secret

    def test_records_tracked(self, ceremony):
        secret = os.urandom(32)
        ceremony.split(secret, 2, 3, participants=["a", "b", "c"])
        assert ceremony.ceremony_count == 1
        assert ceremony.records[0]["action"] == "split"
        assert ceremony.records[0]["participants"] == ["a", "b", "c"]

    def test_failed_split_recorded(self, ceremony):
        with pytest.raises(ValueError):
            ceremony.split(os.urandom(32), shares_needed=1, total_shares=3)
        assert ceremony.ceremony_count == 1
        assert ceremony.records[0]["success"] is False

    def test_full_ceremony(self, ceremony):
        """Complete key ceremony lifecycle."""
        master_key = os.urandom(32)

        # Split
        shares = ceremony.split(
            master_key, shares_needed=3, total_shares=5,
            participants=["ciso", "cto", "dpo", "sre-lead", "security-eng"],
        )
        assert len(shares) == 5

        # Reconstruct with 3 participants
        reconstructed = ceremony.reconstruct(
            shares[:3], key_length=32,
            participants=["ciso", "cto", "dpo"],
        )
        assert reconstructed == master_key
        assert ceremony.ceremony_count == 2
