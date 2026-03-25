"""
AIB — Security Hardening Sprint 2: Persistance & Observabilité.

Five optimizations from the Security Audit:

1. OPT-AUDIT-01: Receipt storage interface (memory, SQLite, PostgreSQL-ready)
2. OPT-CRYPTO-01: Encrypted key storage on disk (PBKDF2 passphrase)
3. OPT-GDPR-01: Persistent AES key store (file-based with master key)
4. OPT-OPS-01: Prometheus metrics endpoint
5. OPT-OPS-03: Structured logging with trace_id correlation

None modifies existing modules. All are opt-in.
"""

import os
import json
import time
import hashlib
import base64
import threading
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


# ═══════════════════════════════════════════════════════════════════
# 1. OPT-AUDIT-01 — RECEIPT STORAGE INTERFACE
# ═══════════════════════════════════════════════════════════════════

class ReceiptStore(ABC):
    """
    Abstract interface for receipt persistence.

    Implementations:
    - MemoryReceiptStore: in-process list (dev/test)
    - SQLiteReceiptStore: single-file database (single instance)
    - PostgresReceiptStore: production (multi-instance) — implement with psycopg

    All stores are INSERT-only. No UPDATE. No DELETE.
    This is an append-only audit log by design.
    """

    @abstractmethod
    def append(self, receipt: dict) -> str:
        """Append a receipt. Returns receipt_id."""
        ...

    @abstractmethod
    def get(self, receipt_id: str) -> Optional[dict]:
        """Get a receipt by ID."""
        ...

    @abstractmethod
    def query(
        self,
        passport_id: Optional[str] = None,
        action: Optional[str] = None,
        protocol: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Query receipts with filters."""
        ...

    @abstractmethod
    def count(self) -> int:
        """Total receipt count."""
        ...

    @abstractmethod
    def get_all_hashes(self) -> list[str]:
        """Get all receipt hashes for Merkle tree building."""
        ...


class MemoryReceiptStore(ReceiptStore):
    """In-memory receipt store for development and testing."""

    def __init__(self):
        self._receipts: list[dict] = []
        self._index: dict[str, int] = {}  # receipt_id → position
        self._lock = threading.Lock()

    def append(self, receipt: dict) -> str:
        with self._lock:
            rid = receipt.get("receipt_id", f"rcpt_{len(self._receipts)}")
            receipt["receipt_id"] = rid
            receipt["stored_at"] = datetime.now(timezone.utc).isoformat()
            self._index[rid] = len(self._receipts)
            self._receipts.append(receipt)
            return rid

    def get(self, receipt_id: str) -> Optional[dict]:
        with self._lock:
            idx = self._index.get(receipt_id)
            if idx is not None:
                return dict(self._receipts[idx])
            return None

    def query(
        self,
        passport_id: Optional[str] = None,
        action: Optional[str] = None,
        protocol: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        results = []
        with self._lock:
            for r in reversed(self._receipts):
                if passport_id and r.get("passport_id") != passport_id:
                    continue
                if action and r.get("action") != action:
                    continue
                if protocol and r.get("protocol") != protocol:
                    continue
                if since and r.get("timestamp", "") < since:
                    continue
                results.append(dict(r))
                if len(results) >= limit:
                    break
        return results

    def count(self) -> int:
        with self._lock:
            return len(self._receipts)

    def get_all_hashes(self) -> list[str]:
        with self._lock:
            return [r.get("receipt_hash", "") for r in self._receipts]


class SQLiteReceiptStore(ReceiptStore):
    """
    SQLite-based receipt store for single-instance deployments.

    INSERT-only. The database file is an append-only audit log.
    """

    def __init__(self, db_path: str = "./data/receipts.db"):
        import sqlite3
        self._path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        with self._lock:
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS receipts (
                    receipt_id TEXT PRIMARY KEY,
                    passport_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    protocol TEXT DEFAULT '',
                    target_url TEXT DEFAULT '',
                    timestamp TEXT NOT NULL,
                    receipt_hash TEXT NOT NULL,
                    data TEXT NOT NULL,
                    stored_at TEXT NOT NULL
                )
            """)
            self._conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_passport_id ON receipts(passport_id)
            """)
            self._conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp ON receipts(timestamp)
            """)
            self._conn.commit()

    def append(self, receipt: dict) -> str:
        rid = receipt.get("receipt_id", f"rcpt_{hashlib.sha256(json.dumps(receipt, sort_keys=True).encode()).hexdigest()[:12]}")
        receipt["receipt_id"] = rid
        stored_at = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO receipts (receipt_id, passport_id, action, protocol, target_url, timestamp, receipt_hash, data, stored_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    rid,
                    receipt.get("passport_id", ""),
                    receipt.get("action", ""),
                    receipt.get("protocol", ""),
                    receipt.get("target_url", ""),
                    receipt.get("timestamp", stored_at),
                    receipt.get("receipt_hash", ""),
                    json.dumps(receipt),
                    stored_at,
                ),
            )
            self._conn.commit()
        return rid

    def get(self, receipt_id: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute("SELECT data FROM receipts WHERE receipt_id = ?", (receipt_id,)).fetchone()
        if row:
            return json.loads(row["data"])
        return None

    def query(
        self,
        passport_id: Optional[str] = None,
        action: Optional[str] = None,
        protocol: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        conditions = []
        params = []
        if passport_id:
            conditions.append("passport_id = ?")
            params.append(passport_id)
        if action:
            conditions.append("action = ?")
            params.append(action)
        if protocol:
            conditions.append("protocol = ?")
            params.append(protocol)
        if since:
            conditions.append("timestamp >= ?")
            params.append(since)

        where = " AND ".join(conditions) if conditions else "1=1"
        params.append(limit)

        with self._lock:
            rows = self._conn.execute(
                f"SELECT data FROM receipts WHERE {where} ORDER BY timestamp DESC LIMIT ?",
                params,
            ).fetchall()
        return [json.loads(r["data"]) for r in rows]

    def count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) as c FROM receipts").fetchone()
        return row["c"]

    def get_all_hashes(self) -> list[str]:
        with self._lock:
            rows = self._conn.execute("SELECT receipt_hash FROM receipts ORDER BY rowid").fetchall()
        return [r["receipt_hash"] for r in rows]

    def close(self):
        self._conn.close()


# ═══════════════════════════════════════════════════════════════════
# 2. OPT-CRYPTO-01 — ENCRYPTED KEY STORAGE
# ═══════════════════════════════════════════════════════════════════

class EncryptedKeyStorage:
    """
    Encrypts RSA private keys on disk using a passphrase.

    Instead of storing PEM files with NoEncryption(), this uses
    PBKDF2-derived key from a passphrase to encrypt at rest.

    Usage:
        storage = EncryptedKeyStorage(passphrase="my-strong-passphrase")

        # Save (encrypts with passphrase)
        storage.save_private_key(private_key, kid="aib-key-1", directory=Path("./keys"))

        # Load (decrypts with passphrase)
        private_key = storage.load_private_key(kid="aib-key-1", directory=Path("./keys"))
    """

    def __init__(self, passphrase: str):
        if len(passphrase) < 8:
            raise ValueError("Passphrase must be at least 8 characters")
        self._passphrase = passphrase.encode("utf-8")

    def save_private_key(self, private_key, kid: str, directory: Path):
        """Save an encrypted private key to disk."""
        directory.mkdir(parents=True, exist_ok=True)
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(self._passphrase),
        )
        (directory / f"{kid}.private.pem").write_bytes(pem)

    def load_private_key(self, kid: str, directory: Path):
        """Load and decrypt a private key from disk."""
        pem = (directory / f"{kid}.private.pem").read_bytes()
        return serialization.load_pem_private_key(
            pem, password=self._passphrase, backend=default_backend(),
        )

    def save_public_key(self, public_key, kid: str, directory: Path):
        """Save a public key (not encrypted — it's public)."""
        directory.mkdir(parents=True, exist_ok=True)
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        (directory / f"{kid}.public.pem").write_bytes(pem)

    def is_encrypted(self, kid: str, directory: Path) -> bool:
        """Check if a stored key is encrypted."""
        path = directory / f"{kid}.private.pem"
        if not path.exists():
            return False
        content = path.read_bytes()
        return b"ENCRYPTED" in content


# ═══════════════════════════════════════════════════════════════════
# 3. OPT-GDPR-01 — PERSISTENT AES KEY STORE
# ═══════════════════════════════════════════════════════════════════

class PersistentKeyStore:
    """
    Persists GDPR crypto-shredding AES keys to disk.

    Keys are stored in a JSON file encrypted with a master key.
    Without the master key, the stored keys are unreadable.

    If the master key is lost, all AES keys are lost → all data
    encrypted with those keys becomes permanently unreadable.
    This is by design (crypto-shredding).

    Usage:
        store = PersistentKeyStore(
            master_key="32-byte-hex-master-key",
            store_path="./data/gdpr-keys.enc"
        )

        # Store a key
        store.set("org-acme", aes_key_bytes)

        # Retrieve
        key = store.get("org-acme")

        # Shred (delete key = data unreadable)
        store.shred("org-acme")
    """

    def __init__(self, master_key: str, store_path: str = "./data/gdpr-keys.enc"):
        # Derive encryption key from master key via PBKDF2
        salt = b"aib-gdpr-keystore-v1"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=default_backend(),
        )
        self._enc_key = kdf.derive(master_key.encode("utf-8"))
        self._path = Path(store_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._keys: dict[str, bytes] = {}
        self._lock = threading.Lock()
        self._load()

    def _encrypt_store(self, data: bytes) -> bytes:
        aesgcm = AESGCM(self._enc_key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, data, None)
        return nonce + ct

    def _decrypt_store(self, data: bytes) -> bytes:
        aesgcm = AESGCM(self._enc_key)
        nonce = data[:12]
        ct = data[12:]
        return aesgcm.decrypt(nonce, ct, None)

    def _load(self):
        if self._path.exists():
            encrypted = self._path.read_bytes()
            if encrypted:
                try:
                    decrypted = self._decrypt_store(encrypted)
                    store_data = json.loads(decrypted)
                    self._keys = {
                        k: base64.b64decode(v) for k, v in store_data.items()
                    }
                except Exception:
                    self._keys = {}

    def _save(self):
        store_data = {
            k: base64.b64encode(v).decode() for k, v in self._keys.items()
        }
        plaintext = json.dumps(store_data).encode("utf-8")
        encrypted = self._encrypt_store(plaintext)
        self._path.write_bytes(encrypted)

    def set(self, org_id: str, key: bytes):
        """Store an AES key for an organization."""
        with self._lock:
            self._keys[org_id] = key
            self._save()

    def get(self, org_id: str) -> Optional[bytes]:
        """Retrieve an AES key."""
        with self._lock:
            return self._keys.get(org_id)

    def shred(self, org_id: str) -> bool:
        """Delete an AES key (crypto-shredding)."""
        with self._lock:
            if org_id in self._keys:
                del self._keys[org_id]
                self._save()
                return True
            return False

    def list_orgs(self) -> list[str]:
        with self._lock:
            return list(self._keys.keys())

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._keys)


# ═══════════════════════════════════════════════════════════════════
# 4. OPT-OPS-01 — PROMETHEUS METRICS
# ═══════════════════════════════════════════════════════════════════

class MetricsCollector:
    """
    Collects metrics for monitoring (Prometheus-compatible).

    Tracks:
    - Request counts (by protocol, action, status)
    - Latency histogram (p50, p95, p99)
    - Active passports
    - Revocation count
    - Merkle tree size
    - Rate limit hits
    - Error counts by code

    Usage:
        metrics = MetricsCollector()

        # Record a request
        metrics.record_request(protocol="a2a", action="proxy", status="success", latency_ms=1.3)

        # Get /metrics output (Prometheus text format)
        print(metrics.to_prometheus())
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._request_count: dict[str, int] = defaultdict(int)
        self._latencies: list[float] = []
        self._error_count: dict[str, int] = defaultdict(int)
        self._gauges: dict[str, float] = {}
        self._rate_limit_hits: int = 0
        self._start_time = time.time()

    def record_request(self, protocol: str, action: str, status: str, latency_ms: float):
        key = f"{protocol}:{action}:{status}"
        with self._lock:
            self._request_count[key] += 1
            self._latencies.append(latency_ms)
            if len(self._latencies) > 10000:
                self._latencies = self._latencies[-5000:]

    def record_error(self, error_code: str):
        with self._lock:
            self._error_count[error_code] += 1

    def record_rate_limit_hit(self):
        with self._lock:
            self._rate_limit_hits += 1

    def set_gauge(self, name: str, value: float):
        with self._lock:
            self._gauges[name] = value

    def _percentile(self, values: list[float], p: float) -> float:
        if not values:
            return 0.0
        sorted_v = sorted(values)
        idx = int(len(sorted_v) * p / 100)
        return sorted_v[min(idx, len(sorted_v) - 1)]

    def get_stats(self) -> dict:
        with self._lock:
            total = sum(self._request_count.values())
            return {
                "uptime_seconds": round(time.time() - self._start_time, 1),
                "total_requests": total,
                "requests_by_key": dict(self._request_count),
                "latency_p50_ms": round(self._percentile(self._latencies, 50), 2),
                "latency_p95_ms": round(self._percentile(self._latencies, 95), 2),
                "latency_p99_ms": round(self._percentile(self._latencies, 99), 2),
                "errors_by_code": dict(self._error_count),
                "rate_limit_hits": self._rate_limit_hits,
                "gauges": dict(self._gauges),
            }

    def to_prometheus(self) -> str:
        """Export metrics in Prometheus text exposition format."""
        lines = []
        stats = self.get_stats()

        lines.append("# HELP aib_uptime_seconds Gateway uptime in seconds")
        lines.append("# TYPE aib_uptime_seconds gauge")
        lines.append(f'aib_uptime_seconds {stats["uptime_seconds"]}')

        lines.append("# HELP aib_requests_total Total requests processed")
        lines.append("# TYPE aib_requests_total counter")
        lines.append(f'aib_requests_total {stats["total_requests"]}')

        lines.append("# HELP aib_request_count Requests by protocol, action, status")
        lines.append("# TYPE aib_request_count counter")
        for key, count in stats["requests_by_key"].items():
            parts = key.split(":")
            if len(parts) == 3:
                lines.append(f'aib_request_count{{protocol="{parts[0]}",action="{parts[1]}",status="{parts[2]}"}} {count}')

        lines.append("# HELP aib_latency_ms Request latency in milliseconds")
        lines.append("# TYPE aib_latency_ms summary")
        lines.append(f'aib_latency_ms{{quantile="0.5"}} {stats["latency_p50_ms"]}')
        lines.append(f'aib_latency_ms{{quantile="0.95"}} {stats["latency_p95_ms"]}')
        lines.append(f'aib_latency_ms{{quantile="0.99"}} {stats["latency_p99_ms"]}')

        lines.append("# HELP aib_errors_total Errors by code")
        lines.append("# TYPE aib_errors_total counter")
        for code, count in stats["errors_by_code"].items():
            lines.append(f'aib_errors_total{{code="{code}"}} {count}')

        lines.append("# HELP aib_rate_limit_hits_total Rate limit rejections")
        lines.append("# TYPE aib_rate_limit_hits_total counter")
        lines.append(f'aib_rate_limit_hits_total {stats["rate_limit_hits"]}')

        for name, value in stats["gauges"].items():
            lines.append(f"# HELP aib_{name} {name}")
            lines.append(f"# TYPE aib_{name} gauge")
            lines.append(f"aib_{name} {value}")

        return "\n".join(lines) + "\n"


# ═══════════════════════════════════════════════════════════════════
# 5. OPT-OPS-03 — STRUCTURED LOGGING
# ═══════════════════════════════════════════════════════════════════

class StructuredLogger:
    """
    JSON structured logger with trace_id correlation.

    Each log entry includes: timestamp, level, message, trace_id,
    passport_id, protocol, action, and any extra context.

    Output format: one JSON object per line (jsonl).
    Compatible with: Datadog, Grafana Loki, ELK, Splunk.

    Usage:
        logger = StructuredLogger(service="aib-gateway")

        logger.info("Passport verified", trace_id="abc", passport_id="urn:...")
        logger.error("SSRF blocked", trace_id="abc", detail="Resolved to 10.0.0.1")

        # Get all logs
        entries = logger.get_entries()
    """

    def __init__(self, service: str = "aib-gateway", max_entries: int = 10000):
        self._service = service
        self._entries: list[dict] = []
        self._max = max_entries
        self._lock = threading.Lock()

    def _log(self, level: str, message: str, **kwargs):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "service": self._service,
            "message": message,
        }
        for key in ("trace_id", "passport_id", "protocol", "action", "error_code", "detail", "latency_ms"):
            if key in kwargs:
                entry[key] = kwargs[key]
        # Extra fields
        for k, v in kwargs.items():
            if k not in entry:
                entry[k] = v

        with self._lock:
            self._entries.append(entry)
            if len(self._entries) > self._max:
                self._entries = self._entries[-self._max:]

    def info(self, message: str, **kwargs):
        self._log("INFO", message, **kwargs)

    def warn(self, message: str, **kwargs):
        self._log("WARN", message, **kwargs)

    def error(self, message: str, **kwargs):
        self._log("ERROR", message, **kwargs)

    def debug(self, message: str, **kwargs):
        self._log("DEBUG", message, **kwargs)

    def get_entries(self, limit: int = 100, level: Optional[str] = None) -> list[dict]:
        with self._lock:
            entries = self._entries[-limit:]
            if level:
                entries = [e for e in entries if e["level"] == level]
            return list(entries)

    def to_jsonl(self, limit: int = 100) -> str:
        """Export as JSON Lines (one JSON object per line)."""
        entries = self.get_entries(limit)
        return "\n".join(json.dumps(e) for e in entries) + "\n" if entries else ""

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._entries)

    def clear(self):
        with self._lock:
            self._entries.clear()
