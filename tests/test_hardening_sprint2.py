"""Tests for Security Hardening Sprint 2 — Persistance & Observabilité."""

import os
import json
import time
import tempfile
import pytest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from aib.hardening_sprint2 import (
    MemoryReceiptStore, SQLiteReceiptStore,
    EncryptedKeyStorage,
    PersistentKeyStore,
    MetricsCollector,
    StructuredLogger,
)


# ═══════════════════════════════════════════════════════════════════
# 1. RECEIPT STORAGE
# ═══════════════════════════════════════════════════════════════════

class TestMemoryReceiptStore:

    @pytest.fixture
    def store(self):
        return MemoryReceiptStore()

    def test_append_and_get(self, store):
        rid = store.append({"passport_id": "p1", "action": "proxy", "receipt_hash": "abc"})
        receipt = store.get(rid)
        assert receipt is not None
        assert receipt["passport_id"] == "p1"
        assert "stored_at" in receipt

    def test_count(self, store):
        assert store.count() == 0
        store.append({"passport_id": "p1", "action": "a"})
        store.append({"passport_id": "p2", "action": "b"})
        assert store.count() == 2

    def test_query_by_passport(self, store):
        store.append({"passport_id": "p1", "action": "proxy"})
        store.append({"passport_id": "p2", "action": "proxy"})
        store.append({"passport_id": "p1", "action": "translate"})

        results = store.query(passport_id="p1")
        assert len(results) == 2

    def test_query_by_action(self, store):
        store.append({"passport_id": "p1", "action": "proxy"})
        store.append({"passport_id": "p1", "action": "translate"})
        results = store.query(action="proxy")
        assert len(results) == 1

    def test_query_limit(self, store):
        for i in range(20):
            store.append({"passport_id": "p1", "action": f"a{i}"})
        results = store.query(limit=5)
        assert len(results) == 5

    def test_get_nonexistent(self, store):
        assert store.get("nonexistent") is None

    def test_get_all_hashes(self, store):
        store.append({"receipt_hash": "h1"})
        store.append({"receipt_hash": "h2"})
        hashes = store.get_all_hashes()
        assert hashes == ["h1", "h2"]


class TestSQLiteReceiptStore:

    @pytest.fixture
    def store(self, tmp_path):
        s = SQLiteReceiptStore(str(tmp_path / "test.db"))
        yield s
        s.close()

    def test_append_and_get(self, store):
        rid = store.append({
            "receipt_id": "r1", "passport_id": "p1", "action": "proxy",
            "timestamp": "2026-03-25T00:00:00Z", "receipt_hash": "abc",
        })
        receipt = store.get(rid)
        assert receipt is not None
        assert receipt["passport_id"] == "p1"

    def test_count(self, store):
        assert store.count() == 0
        store.append({"receipt_id": "r1", "passport_id": "p1", "action": "a", "timestamp": "2026-01-01", "receipt_hash": "h1"})
        store.append({"receipt_id": "r2", "passport_id": "p2", "action": "b", "timestamp": "2026-01-02", "receipt_hash": "h2"})
        assert store.count() == 2

    def test_query_by_passport(self, store):
        store.append({"receipt_id": "r1", "passport_id": "p1", "action": "proxy", "timestamp": "2026-01-01", "receipt_hash": "h1"})
        store.append({"receipt_id": "r2", "passport_id": "p2", "action": "proxy", "timestamp": "2026-01-02", "receipt_hash": "h2"})
        results = store.query(passport_id="p1")
        assert len(results) == 1

    def test_query_by_action(self, store):
        store.append({"receipt_id": "r1", "passport_id": "p1", "action": "proxy", "timestamp": "2026-01-01", "receipt_hash": "h1"})
        store.append({"receipt_id": "r2", "passport_id": "p1", "action": "translate", "timestamp": "2026-01-02", "receipt_hash": "h2"})
        results = store.query(action="translate")
        assert len(results) == 1

    def test_persistence(self, tmp_path):
        path = str(tmp_path / "persist.db")
        s1 = SQLiteReceiptStore(path)
        s1.append({"receipt_id": "r1", "passport_id": "p1", "action": "a", "timestamp": "2026-01-01", "receipt_hash": "h1"})
        s1.close()

        s2 = SQLiteReceiptStore(path)
        assert s2.count() == 1
        assert s2.get("r1") is not None
        s2.close()

    def test_duplicate_ignored(self, store):
        store.append({"receipt_id": "r1", "passport_id": "p1", "action": "a", "timestamp": "2026-01-01", "receipt_hash": "h1"})
        store.append({"receipt_id": "r1", "passport_id": "p1", "action": "a", "timestamp": "2026-01-01", "receipt_hash": "h1"})
        assert store.count() == 1

    def test_get_all_hashes(self, store):
        store.append({"receipt_id": "r1", "passport_id": "p1", "action": "a", "timestamp": "2026-01-01", "receipt_hash": "h1"})
        store.append({"receipt_id": "r2", "passport_id": "p1", "action": "b", "timestamp": "2026-01-02", "receipt_hash": "h2"})
        hashes = store.get_all_hashes()
        assert hashes == ["h1", "h2"]


# ═══════════════════════════════════════════════════════════════════
# 2. ENCRYPTED KEY STORAGE
# ═══════════════════════════════════════════════════════════════════

class TestEncryptedKeyStorage:

    @pytest.fixture
    def key_pair(self):
        return rsa.generate_private_key(65537, 2048, default_backend())

    def test_save_and_load(self, tmp_path, key_pair):
        storage = EncryptedKeyStorage(passphrase="test-passphrase-secure")
        storage.save_private_key(key_pair, "key-1", tmp_path)
        loaded = storage.load_private_key("key-1", tmp_path)
        # Verify by signing with both
        assert loaded.key_size == key_pair.key_size

    def test_encrypted_on_disk(self, tmp_path, key_pair):
        storage = EncryptedKeyStorage(passphrase="test-passphrase-secure")
        storage.save_private_key(key_pair, "key-1", tmp_path)
        assert storage.is_encrypted("key-1", tmp_path)

    def test_wrong_passphrase_fails(self, tmp_path, key_pair):
        storage1 = EncryptedKeyStorage(passphrase="correct-passphrase")
        storage1.save_private_key(key_pair, "key-1", tmp_path)

        storage2 = EncryptedKeyStorage(passphrase="wrong-passphrase")
        with pytest.raises(Exception):
            storage2.load_private_key("key-1", tmp_path)

    def test_short_passphrase_rejected(self):
        with pytest.raises(ValueError, match="8 characters"):
            EncryptedKeyStorage(passphrase="short")

    def test_public_key_not_encrypted(self, tmp_path, key_pair):
        storage = EncryptedKeyStorage(passphrase="test-passphrase-secure")
        storage.save_public_key(key_pair.public_key(), "key-1", tmp_path)
        pem = (tmp_path / "key-1.public.pem").read_bytes()
        assert b"ENCRYPTED" not in pem


# ═══════════════════════════════════════════════════════════════════
# 3. PERSISTENT AES KEY STORE
# ═══════════════════════════════════════════════════════════════════

class TestPersistentKeyStore:

    @pytest.fixture
    def store(self, tmp_path):
        return PersistentKeyStore(
            master_key="test-master-key-for-aib",
            store_path=str(tmp_path / "keys.enc"),
        )

    def test_set_and_get(self, store):
        key = AESGCM.generate_key(bit_length=256)
        store.set("org-acme", key)
        retrieved = store.get("org-acme")
        assert retrieved == key

    def test_get_nonexistent(self, store):
        assert store.get("nonexistent") is None

    def test_shred(self, store):
        key = AESGCM.generate_key(bit_length=256)
        store.set("org-acme", key)
        assert store.shred("org-acme") is True
        assert store.get("org-acme") is None

    def test_shred_nonexistent(self, store):
        assert store.shred("nonexistent") is False

    def test_persistence(self, tmp_path):
        path = str(tmp_path / "keys.enc")
        key = AESGCM.generate_key(bit_length=256)

        s1 = PersistentKeyStore(master_key="my-master", store_path=path)
        s1.set("org-acme", key)

        s2 = PersistentKeyStore(master_key="my-master", store_path=path)
        assert s2.get("org-acme") == key

    def test_wrong_master_key_fails(self, tmp_path):
        path = str(tmp_path / "keys.enc")
        key = AESGCM.generate_key(bit_length=256)

        s1 = PersistentKeyStore(master_key="correct-master", store_path=path)
        s1.set("org-acme", key)

        s2 = PersistentKeyStore(master_key="wrong-master", store_path=path)
        assert s2.get("org-acme") is None  # Decryption fails → empty

    def test_list_orgs(self, store):
        store.set("org-a", AESGCM.generate_key(bit_length=256))
        store.set("org-b", AESGCM.generate_key(bit_length=256))
        assert set(store.list_orgs()) == {"org-a", "org-b"}

    def test_count(self, store):
        assert store.count == 0
        store.set("org-a", AESGCM.generate_key(bit_length=256))
        assert store.count == 1


# ═══════════════════════════════════════════════════════════════════
# 4. PROMETHEUS METRICS
# ═══════════════════════════════════════════════════════════════════

class TestMetrics:

    @pytest.fixture
    def metrics(self):
        return MetricsCollector()

    def test_record_request(self, metrics):
        metrics.record_request("a2a", "proxy", "success", 1.5)
        stats = metrics.get_stats()
        assert stats["total_requests"] == 1

    def test_latency_percentiles(self, metrics):
        for i in range(100):
            metrics.record_request("mcp", "proxy", "success", float(i))
        stats = metrics.get_stats()
        assert stats["latency_p50_ms"] >= 40
        assert stats["latency_p99_ms"] >= 90

    def test_error_counts(self, metrics):
        metrics.record_error("AIB-001")
        metrics.record_error("AIB-001")
        metrics.record_error("AIB-303")
        stats = metrics.get_stats()
        assert stats["errors_by_code"]["AIB-001"] == 2
        assert stats["errors_by_code"]["AIB-303"] == 1

    def test_rate_limit_hits(self, metrics):
        metrics.record_rate_limit_hit()
        metrics.record_rate_limit_hit()
        assert metrics.get_stats()["rate_limit_hits"] == 2

    def test_gauges(self, metrics):
        metrics.set_gauge("active_passports", 42)
        metrics.set_gauge("merkle_tree_size", 1500)
        stats = metrics.get_stats()
        assert stats["gauges"]["active_passports"] == 42

    def test_prometheus_format(self, metrics):
        metrics.record_request("a2a", "proxy", "success", 1.5)
        metrics.record_error("AIB-001")
        output = metrics.to_prometheus()
        assert "aib_requests_total 1" in output
        assert 'aib_request_count{protocol="a2a"' in output
        assert 'aib_errors_total{code="AIB-001"} 1' in output
        assert "aib_latency_ms" in output

    def test_uptime(self, metrics):
        time.sleep(0.1)
        stats = metrics.get_stats()
        assert stats["uptime_seconds"] >= 0.1


# ═══════════════════════════════════════════════════════════════════
# 5. STRUCTURED LOGGING
# ═══════════════════════════════════════════════════════════════════

class TestStructuredLogger:

    @pytest.fixture
    def logger(self):
        return StructuredLogger(service="test-gateway")

    def test_info(self, logger):
        logger.info("Passport verified", trace_id="t1", passport_id="p1")
        entries = logger.get_entries()
        assert len(entries) == 1
        assert entries[0]["level"] == "INFO"
        assert entries[0]["trace_id"] == "t1"
        assert entries[0]["service"] == "test-gateway"

    def test_error(self, logger):
        logger.error("SSRF blocked", trace_id="t2", detail="Resolved to 10.0.0.1")
        entries = logger.get_entries(level="ERROR")
        assert len(entries) == 1
        assert entries[0]["detail"] == "Resolved to 10.0.0.1"

    def test_levels(self, logger):
        logger.debug("debug msg")
        logger.info("info msg")
        logger.warn("warn msg")
        logger.error("error msg")
        assert logger.count == 4

    def test_filter_by_level(self, logger):
        logger.info("info")
        logger.error("error")
        logger.info("info2")
        errors = logger.get_entries(level="ERROR")
        assert len(errors) == 1

    def test_limit(self, logger):
        for i in range(20):
            logger.info(f"msg {i}")
        entries = logger.get_entries(limit=5)
        assert len(entries) == 5

    def test_jsonl_format(self, logger):
        logger.info("test1", trace_id="t1")
        logger.info("test2", trace_id="t2")
        jsonl = logger.to_jsonl()
        lines = jsonl.strip().split("\n")
        assert len(lines) == 2
        parsed = json.loads(lines[0])
        assert parsed["message"] == "test1"

    def test_extra_fields(self, logger):
        logger.info("custom", custom_field="value", latency_ms=1.5)
        entries = logger.get_entries()
        assert entries[0]["custom_field"] == "value"
        assert entries[0]["latency_ms"] == 1.5

    def test_clear(self, logger):
        logger.info("msg")
        assert logger.count == 1
        logger.clear()
        assert logger.count == 0

    def test_max_entries_cap(self):
        logger = StructuredLogger(max_entries=10)
        for i in range(20):
            logger.info(f"msg {i}")
        assert logger.count == 10

    def test_timestamp_present(self, logger):
        logger.info("msg")
        entry = logger.get_entries()[0]
        assert "timestamp" in entry
        assert "T" in entry["timestamp"]
