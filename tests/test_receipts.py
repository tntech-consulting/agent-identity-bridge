"""Tests for Action Receipts — cryptographic proof of agent actions."""

import pytest
import json
from aib.receipts import (
    ReceiptStore, ActionReceipt, ActionType, ActionStatus,
    hash_content, compute_receipt_hash,
)


@pytest.fixture
def store():
    return ReceiptStore()


@pytest.fixture
def store_with_receipts(store):
    """Store with 5 diverse receipts."""
    store.emit(
        passport_id="urn:aib:agent:acme:booking",
        action=ActionType.PROXY, status=ActionStatus.SUCCESS,
        target_url="https://partner.com/agent", target_protocol="a2a",
        request_body={"task": "book 3pm"}, response_body={"ok": True},
        latency_ms=34.5, capabilities_used=["booking"],
    )
    store.emit(
        passport_id="urn:aib:agent:acme:support",
        action=ActionType.TRANSLATE, status=ActionStatus.SUCCESS,
        target_protocol="mcp", latency_ms=8.2,
    )
    store.emit(
        passport_id="urn:aib:agent:acme:booking",
        action=ActionType.PROXY, status=ActionStatus.ERROR,
        target_url="https://down.com/api", target_protocol="mcp",
        response_status=502, latency_ms=5012.0,
    )
    store.emit(
        passport_id="urn:aib:agent:acme:support",
        action=ActionType.VERIFY, status=ActionStatus.SUCCESS,
        latency_ms=2.1,
    )
    store.emit(
        passport_id="urn:aib:agent:acme:booking",
        action=ActionType.PROXY, status=ActionStatus.DENIED,
        target_url="https://admin.internal/delete", target_protocol="mcp",
        latency_ms=1.0, capabilities_used=["admin"],
    )
    return store


# ═══════════════════════════════════════════════════════════════════
# Hashing
# ═══════════════════════════════════════════════════════════════════

class TestHashing:

    def test_hash_string(self):
        h = hash_content("hello")
        assert len(h) == 64  # SHA-256 hex

    def test_hash_dict(self):
        h = hash_content({"key": "value"})
        assert len(h) == 64

    def test_hash_none(self):
        h = hash_content(None)
        assert len(h) == 64

    def test_hash_deterministic(self):
        h1 = hash_content({"a": 1, "b": 2})
        h2 = hash_content({"b": 2, "a": 1})  # Different order
        assert h1 == h2  # sort_keys=True

    def test_different_content_different_hash(self):
        h1 = hash_content("hello")
        h2 = hash_content("world")
        assert h1 != h2


# ═══════════════════════════════════════════════════════════════════
# Receipt creation
# ═══════════════════════════════════════════════════════════════════

class TestReceiptCreation:

    def test_emit_basic(self, store):
        r = store.emit(
            passport_id="urn:aib:agent:test:bot",
            action=ActionType.PROXY,
            status=ActionStatus.SUCCESS,
            target_url="https://example.com",
            target_protocol="a2a",
            request_body={"task": "test"},
            response_body={"ok": True},
            latency_ms=42.0,
        )
        assert r.receipt_id.startswith("rcpt_")
        assert r.passport_id == "urn:aib:agent:test:bot"
        assert r.action == ActionType.PROXY
        assert r.status == ActionStatus.SUCCESS
        assert len(r.request_hash) == 64
        assert len(r.response_hash) == 64
        assert len(r.receipt_hash) == 64
        assert r.sequence_number == 1

    def test_first_receipt_links_to_genesis(self, store):
        r = store.emit(
            passport_id="urn:aib:agent:test:bot",
            action=ActionType.VERIFY, status=ActionStatus.SUCCESS,
        )
        assert r.previous_hash == ReceiptStore.GENESIS_HASH

    def test_sequence_increments(self, store):
        r1 = store.emit(passport_id="a", action=ActionType.PROXY, status=ActionStatus.SUCCESS)
        r2 = store.emit(passport_id="b", action=ActionType.PROXY, status=ActionStatus.SUCCESS)
        r3 = store.emit(passport_id="a", action=ActionType.PROXY, status=ActionStatus.SUCCESS)
        assert r1.sequence_number == 1
        assert r2.sequence_number == 2
        assert r3.sequence_number == 3

    def test_receipt_has_timestamp(self, store):
        r = store.emit(passport_id="a", action=ActionType.PROXY, status=ActionStatus.SUCCESS)
        assert "2026" in r.timestamp
        assert r.timestamp_unix > 0

    def test_receipt_to_dict_and_back(self, store):
        r = store.emit(
            passport_id="urn:aib:agent:test:round",
            action=ActionType.TRANSLATE, status=ActionStatus.SUCCESS,
            target_protocol="mcp", latency_ms=10.0,
            metadata={"workflow": "test-42"},
        )
        d = r.to_dict()
        restored = ActionReceipt.from_dict(d)
        assert restored.receipt_id == r.receipt_id
        assert restored.receipt_hash == r.receipt_hash
        assert restored.metadata == {"workflow": "test-42"}

    def test_root_passport_defaults_to_passport(self, store):
        r = store.emit(passport_id="urn:aib:agent:test:bot", action=ActionType.PROXY, status=ActionStatus.SUCCESS)
        assert r.root_passport_id == r.passport_id

    def test_root_passport_explicit(self, store):
        r = store.emit(
            passport_id="urn:aib:agent:test:ephemeral-1",
            root_passport_id="urn:aib:agent:test:root",
            action=ActionType.PROXY, status=ActionStatus.SUCCESS,
            delegation_depth=2,
        )
        assert r.root_passport_id == "urn:aib:agent:test:root"
        assert r.delegation_depth == 2


# ═══════════════════════════════════════════════════════════════════
# Hash chain integrity
# ═══════════════════════════════════════════════════════════════════

class TestHashChain:

    def test_chain_links(self, store):
        r1 = store.emit(passport_id="a", action=ActionType.PROXY, status=ActionStatus.SUCCESS)
        r2 = store.emit(passport_id="b", action=ActionType.PROXY, status=ActionStatus.SUCCESS)
        r3 = store.emit(passport_id="a", action=ActionType.PROXY, status=ActionStatus.SUCCESS)
        assert r2.previous_hash == r1.receipt_hash
        assert r3.previous_hash == r2.receipt_hash

    def test_verify_empty_chain(self, store):
        valid, count, msg = store.verify_chain()
        assert valid is True
        assert count == 0

    def test_verify_valid_chain(self, store_with_receipts):
        valid, count, msg = store_with_receipts.verify_chain()
        assert valid is True
        assert count == 5
        assert "valid" in msg.lower()

    def test_detect_tampered_receipt(self, store):
        store.emit(passport_id="a", action=ActionType.PROXY, status=ActionStatus.SUCCESS)
        store.emit(passport_id="b", action=ActionType.PROXY, status=ActionStatus.SUCCESS)
        store.emit(passport_id="c", action=ActionType.PROXY, status=ActionStatus.SUCCESS)

        # Tamper with the second receipt
        store._receipts[1].target_url = "https://tampered.com"

        valid, idx, msg = store.verify_chain()
        assert valid is False
        assert idx == 1
        assert "mismatch" in msg.lower()

    def test_detect_removed_receipt(self, store):
        store.emit(passport_id="a", action=ActionType.PROXY, status=ActionStatus.SUCCESS)
        r2 = store.emit(passport_id="b", action=ActionType.PROXY, status=ActionStatus.SUCCESS)
        store.emit(passport_id="c", action=ActionType.PROXY, status=ActionStatus.SUCCESS)

        # Remove the middle receipt
        del store._receipts[1]

        valid, idx, msg = store.verify_chain()
        assert valid is False

    def test_detect_inserted_receipt(self, store):
        r1 = store.emit(passport_id="a", action=ActionType.PROXY, status=ActionStatus.SUCCESS)
        r2 = store.emit(passport_id="b", action=ActionType.PROXY, status=ActionStatus.SUCCESS)

        # Insert a fake receipt between them
        fake = ActionReceipt(
            receipt_id="rcpt_fake", passport_id="fake", root_passport_id="fake",
            action=ActionType.PROXY, status=ActionStatus.SUCCESS,
            timestamp="2026-01-01", timestamp_unix=0,
            target_url="", target_protocol="", request_hash="", request_method="POST",
            response_hash="", response_status=200, latency_ms=0,
            capabilities_used=[], delegation_depth=0,
            previous_hash=r1.receipt_hash, sequence_number=2,
            receipt_hash="fakehash",
        )
        store._receipts.insert(1, fake)

        valid, idx, msg = store.verify_chain()
        assert valid is False


# ═══════════════════════════════════════════════════════════════════
# Queries
# ═══════════════════════════════════════════════════════════════════

class TestQueries:

    def test_get_by_id(self, store_with_receipts):
        recent = store_with_receipts.get_recent(1)
        r = store_with_receipts.get(recent[0].receipt_id)
        assert r is not None
        assert r.receipt_id == recent[0].receipt_id

    def test_get_nonexistent(self, store):
        assert store.get("rcpt_doesnotexist") is None

    def test_get_by_passport(self, store_with_receipts):
        booking = store_with_receipts.get_by_passport("urn:aib:agent:acme:booking")
        assert len(booking) == 3  # 2 proxy + 1 denied

    def test_get_by_passport_with_filter(self, store_with_receipts):
        errors = store_with_receipts.get_by_passport(
            "urn:aib:agent:acme:booking",
            action_filter=ActionType.PROXY,
        )
        assert len(errors) == 3

    def test_get_recent(self, store_with_receipts):
        recent = store_with_receipts.get_recent(2)
        assert len(recent) == 2
        assert recent[0].sequence_number > recent[1].sequence_number

    def test_get_errors(self, store_with_receipts):
        errors = store_with_receipts.get_errors()
        assert len(errors) == 2  # 1 error + 1 denied

    def test_get_by_root(self, store):
        store.emit(passport_id="child-1", root_passport_id="root-x", action=ActionType.PROXY, status=ActionStatus.SUCCESS)
        store.emit(passport_id="child-2", root_passport_id="root-x", action=ActionType.PROXY, status=ActionStatus.SUCCESS)
        store.emit(passport_id="other", root_passport_id="root-y", action=ActionType.PROXY, status=ActionStatus.SUCCESS)

        results = store.get_by_root("root-x")
        assert len(results) == 2


# ═══════════════════════════════════════════════════════════════════
# Stats
# ═══════════════════════════════════════════════════════════════════

class TestStats:

    def test_empty_stats(self, store):
        s = store.stats()
        assert s["total"] == 0

    def test_stats_counts(self, store_with_receipts):
        s = store_with_receipts.stats()
        assert s["total"] == 5
        assert s["success"] == 3
        assert s["errors"] == 1
        assert s["denied"] == 1
        assert s["success_rate"] == 60.0
        assert s["unique_passports"] == 2

    def test_stats_by_protocol(self, store_with_receipts):
        s = store_with_receipts.stats()
        assert "a2a" in s["by_protocol"]
        assert "mcp" in s["by_protocol"]

    def test_stats_latency(self, store_with_receipts):
        s = store_with_receipts.stats()
        assert s["avg_latency_ms"] > 0
        assert s["max_latency_ms"] >= 5012.0


# ═══════════════════════════════════════════════════════════════════
# Export
# ═══════════════════════════════════════════════════════════════════

class TestExport:

    def test_export_json(self, store_with_receipts):
        exported = store_with_receipts.export_json()
        data = json.loads(exported)
        assert len(data) == 5
        assert data[0]["receipt_id"].startswith("rcpt_")

    def test_export_subset(self, store_with_receipts):
        errors = store_with_receipts.get_errors()
        exported = store_with_receipts.export_json(errors)
        data = json.loads(exported)
        assert len(data) == 2
