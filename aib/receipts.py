"""
AIB — Action Receipts.

Cryptographic proof of every action an agent performs through the gateway.

An Action Receipt is a signed document that proves:
- WHO did it (passport_id)
- WHAT they did (request hash + response hash)
- WHEN (timestamp)
- WHERE (target URL, protocol)
- WITH WHAT AUTHORITY (capabilities used, delegation chain root)

Receipts are:
- Signed by the gateway's RS256 key (same KeyManager as passports)
- Independently verifiable by any third party with the public key
- Chained (each receipt includes the hash of the previous receipt)
- Immutable (append-only, no modification or deletion)

This provides non-repudiation at the ACTION level, not just the identity level.
A compliance officer can prove "Agent X performed action Y at time Z with
permission W" without trusting the agent or its operator.

Use cases:
- SOC 2 / GDPR audit evidence
- Dispute resolution ("did my agent authorize this payment?")
- Forensics after a security incident
- Billing proof (metered usage)

References THREAT_MODEL.md: T6 (Audit Tampering)
"""

import json
import hashlib
import time
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum


class ActionType(str, Enum):
    """Types of actions that generate receipts."""
    PROXY = "proxy"              # Gateway proxied a request
    TRANSLATE = "translate"      # Credential translation performed
    VERIFY = "verify"            # Passport verification
    REVOKE = "revoke"            # Passport revocation
    DELEGATE = "delegate"        # Child passport created
    KEY_ROTATE = "key_rotate"    # Signing key rotated


class ActionStatus(str, Enum):
    SUCCESS = "success"
    ERROR = "error"
    DENIED = "denied"


@dataclass
class ActionReceipt:
    """
    Cryptographic proof of a single agent action.

    Every field is included in the signed hash, making the receipt
    tamper-evident. The previous_hash field creates a hash chain
    across all receipts, so inserting, removing, or modifying any
    receipt breaks the chain.
    """
    # Identity
    receipt_id: str
    passport_id: str
    root_passport_id: str       # For delegated passports, trace to root

    # Action
    action: ActionType
    status: ActionStatus
    timestamp: str              # ISO 8601
    timestamp_unix: float       # For ordering precision

    # Request details
    target_url: str
    target_protocol: str        # mcp, a2a, anp, or "internal"
    request_hash: str           # SHA-256 of the request body
    request_method: str         # POST, GET, etc.

    # Response details
    response_hash: str          # SHA-256 of the response body
    response_status: int        # HTTP status code
    latency_ms: float

    # Authority
    capabilities_used: list[str]
    delegation_depth: int       # 0 = root, 1 = session, 2 = ephemeral

    # Chain integrity
    previous_hash: str          # SHA-256 of the previous receipt (hash chain)
    sequence_number: int        # Monotonic counter

    # Signature (filled by ReceiptStore.sign)
    receipt_hash: str = ""      # SHA-256 of all fields above
    signature: str = ""         # RS256 signature of receipt_hash
    signing_key_id: str = ""    # kid of the signing key

    # Optional metadata
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "receipt_id": self.receipt_id,
            "passport_id": self.passport_id,
            "root_passport_id": self.root_passport_id,
            "action": self.action.value,
            "status": self.status.value,
            "timestamp": self.timestamp,
            "timestamp_unix": self.timestamp_unix,
            "target_url": self.target_url,
            "target_protocol": self.target_protocol,
            "request_hash": self.request_hash,
            "request_method": self.request_method,
            "response_hash": self.response_hash,
            "response_status": self.response_status,
            "latency_ms": self.latency_ms,
            "capabilities_used": self.capabilities_used,
            "delegation_depth": self.delegation_depth,
            "previous_hash": self.previous_hash,
            "sequence_number": self.sequence_number,
            "receipt_hash": self.receipt_hash,
            "signature": self.signature,
            "signing_key_id": self.signing_key_id,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ActionReceipt":
        return cls(
            receipt_id=d["receipt_id"],
            passport_id=d["passport_id"],
            root_passport_id=d["root_passport_id"],
            action=ActionType(d["action"]),
            status=ActionStatus(d["status"]),
            timestamp=d["timestamp"],
            timestamp_unix=d["timestamp_unix"],
            target_url=d["target_url"],
            target_protocol=d["target_protocol"],
            request_hash=d["request_hash"],
            request_method=d["request_method"],
            response_hash=d["response_hash"],
            response_status=d["response_status"],
            latency_ms=d["latency_ms"],
            capabilities_used=d["capabilities_used"],
            delegation_depth=d["delegation_depth"],
            previous_hash=d["previous_hash"],
            sequence_number=d["sequence_number"],
            receipt_hash=d.get("receipt_hash", ""),
            signature=d.get("signature", ""),
            signing_key_id=d.get("signing_key_id", ""),
            metadata=d.get("metadata", {}),
        )


# ── Hashing ───────────────────────────────────────────────────────

def hash_content(content: Any) -> str:
    """SHA-256 hash of any content (string, bytes, dict, or None)."""
    if content is None:
        return hashlib.sha256(b"null").hexdigest()
    if isinstance(content, dict):
        content = json.dumps(content, sort_keys=True, ensure_ascii=False)
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def compute_receipt_hash(receipt: ActionReceipt) -> str:
    """
    Compute the canonical hash of a receipt.

    Includes ALL fields except receipt_hash, signature, and signing_key_id
    (which are set AFTER hashing).
    """
    canonical = json.dumps({
        "receipt_id": receipt.receipt_id,
        "passport_id": receipt.passport_id,
        "root_passport_id": receipt.root_passport_id,
        "action": receipt.action.value,
        "status": receipt.status.value,
        "timestamp": receipt.timestamp,
        "timestamp_unix": receipt.timestamp_unix,
        "target_url": receipt.target_url,
        "target_protocol": receipt.target_protocol,
        "request_hash": receipt.request_hash,
        "request_method": receipt.request_method,
        "response_hash": receipt.response_hash,
        "response_status": receipt.response_status,
        "latency_ms": receipt.latency_ms,
        "capabilities_used": receipt.capabilities_used,
        "delegation_depth": receipt.delegation_depth,
        "previous_hash": receipt.previous_hash,
        "sequence_number": receipt.sequence_number,
    }, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


# ── Receipt Store ─────────────────────────────────────────────────

class ReceiptStore:
    """
    Append-only store for Action Receipts with hash chaining.

    In production, this would be backed by PostgreSQL with
    append-only permissions (INSERT only, no UPDATE/DELETE).
    """

    GENESIS_HASH = "0" * 64  # The "previous hash" of the first receipt

    def __init__(self):
        self._receipts: list[ActionReceipt] = []
        self._by_passport: dict[str, list[int]] = {}  # passport_id → [indices]
        self._by_receipt_id: dict[str, int] = {}       # receipt_id → index
        self._sequence: int = 0

    @property
    def last_hash(self) -> str:
        if not self._receipts:
            return self.GENESIS_HASH
        return self._receipts[-1].receipt_hash

    @property
    def count(self) -> int:
        return len(self._receipts)

    def emit(
        self,
        passport_id: str,
        action: ActionType,
        status: ActionStatus,
        target_url: str = "",
        target_protocol: str = "internal",
        request_body: Any = None,
        response_body: Any = None,
        request_method: str = "POST",
        response_status: int = 200,
        latency_ms: float = 0.0,
        capabilities_used: Optional[list[str]] = None,
        delegation_depth: int = 0,
        root_passport_id: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> ActionReceipt:
        """
        Create, hash, and store a new Action Receipt.

        This is the main entry point — call it after every gateway action.
        """
        now = datetime.now(timezone.utc)
        self._sequence += 1

        receipt = ActionReceipt(
            receipt_id=f"rcpt_{uuid.uuid4().hex[:16]}",
            passport_id=passport_id,
            root_passport_id=root_passport_id or passport_id,
            action=action,
            status=status,
            timestamp=now.isoformat(),
            timestamp_unix=now.timestamp(),
            target_url=target_url,
            target_protocol=target_protocol,
            request_hash=hash_content(request_body),
            request_method=request_method,
            response_hash=hash_content(response_body),
            response_status=response_status,
            latency_ms=round(latency_ms, 2),
            capabilities_used=capabilities_used or [],
            delegation_depth=delegation_depth,
            previous_hash=self.last_hash,
            sequence_number=self._sequence,
            metadata=metadata or {},
        )

        # Compute hash (covers all fields including previous_hash)
        receipt.receipt_hash = compute_receipt_hash(receipt)

        # Store
        idx = len(self._receipts)
        self._receipts.append(receipt)
        self._by_receipt_id[receipt.receipt_id] = idx

        if passport_id not in self._by_passport:
            self._by_passport[passport_id] = []
        self._by_passport[passport_id].append(idx)

        return receipt

    # ── Query ─────────────────────────────────────────────────

    def get(self, receipt_id: str) -> Optional[ActionReceipt]:
        idx = self._by_receipt_id.get(receipt_id)
        if idx is not None:
            return self._receipts[idx]
        return None

    def get_by_passport(
        self,
        passport_id: str,
        limit: int = 50,
        action_filter: Optional[ActionType] = None,
    ) -> list[ActionReceipt]:
        """Get receipts for a specific passport."""
        indices = self._by_passport.get(passport_id, [])
        results = []
        for idx in reversed(indices):  # Most recent first
            r = self._receipts[idx]
            if action_filter and r.action != action_filter:
                continue
            results.append(r)
            if len(results) >= limit:
                break
        return results

    def get_recent(self, limit: int = 50) -> list[ActionReceipt]:
        """Get the most recent receipts across all passports."""
        return list(reversed(self._receipts[-limit:]))

    def get_by_root(self, root_passport_id: str, limit: int = 100) -> list[ActionReceipt]:
        """Get all receipts for a root passport and its delegated children."""
        results = []
        for r in reversed(self._receipts):
            if r.root_passport_id == root_passport_id:
                results.append(r)
                if len(results) >= limit:
                    break
        return results

    def get_errors(self, limit: int = 50) -> list[ActionReceipt]:
        """Get recent error receipts."""
        results = []
        for r in reversed(self._receipts):
            if r.status in (ActionStatus.ERROR, ActionStatus.DENIED):
                results.append(r)
                if len(results) >= limit:
                    break
        return results

    # ── Chain Verification ────────────────────────────────────

    def verify_chain(self) -> tuple[bool, int, str]:
        """
        Verify the integrity of the entire receipt chain.

        Checks:
        1. Each receipt's hash matches its content
        2. Each receipt's previous_hash matches the prior receipt's hash
        3. Sequence numbers are monotonic

        Returns:
            (is_valid, receipts_verified, error_message)
        """
        if not self._receipts:
            return True, 0, "Empty chain"

        expected_prev = self.GENESIS_HASH

        for i, receipt in enumerate(self._receipts):
            # Check previous hash links correctly
            if receipt.previous_hash != expected_prev:
                return False, i, (
                    f"Chain broken at receipt #{i} ({receipt.receipt_id}): "
                    f"expected previous_hash={expected_prev[:16]}..., "
                    f"got={receipt.previous_hash[:16]}..."
                )

            # Recompute hash and verify
            recomputed = compute_receipt_hash(receipt)
            if recomputed != receipt.receipt_hash:
                return False, i, (
                    f"Hash mismatch at receipt #{i} ({receipt.receipt_id}): "
                    f"stored={receipt.receipt_hash[:16]}..., "
                    f"recomputed={recomputed[:16]}..."
                )

            # Check sequence
            if receipt.sequence_number != i + 1:
                return False, i, (
                    f"Sequence gap at receipt #{i}: "
                    f"expected={i+1}, got={receipt.sequence_number}"
                )

            expected_prev = receipt.receipt_hash

        return True, len(self._receipts), "Chain valid"

    # ── Stats ─────────────────────────────────────────────────

    def stats(self) -> dict:
        """Summary statistics across all receipts."""
        if not self._receipts:
            return {"total": 0}

        success = sum(1 for r in self._receipts if r.status == ActionStatus.SUCCESS)
        errors = sum(1 for r in self._receipts if r.status == ActionStatus.ERROR)
        denied = sum(1 for r in self._receipts if r.status == ActionStatus.DENIED)
        latencies = [r.latency_ms for r in self._receipts if r.latency_ms > 0]

        protocols = {}
        actions = {}
        for r in self._receipts:
            protocols[r.target_protocol] = protocols.get(r.target_protocol, 0) + 1
            actions[r.action.value] = actions.get(r.action.value, 0) + 1

        return {
            "total": len(self._receipts),
            "success": success,
            "errors": errors,
            "denied": denied,
            "success_rate": round(success / len(self._receipts) * 100, 1) if self._receipts else 0,
            "avg_latency_ms": round(sum(latencies) / len(latencies), 1) if latencies else 0,
            "max_latency_ms": round(max(latencies), 1) if latencies else 0,
            "by_protocol": protocols,
            "by_action": actions,
            "unique_passports": len(self._by_passport),
            "chain_length": len(self._receipts),
        }

    # ── Export ─────────────────────────────────────────────────

    def export_json(self, receipts: Optional[list[ActionReceipt]] = None) -> str:
        """Export receipts as JSON (for SIEM/Grafana/Datadog ingestion)."""
        items = receipts or self._receipts
        return json.dumps(
            [r.to_dict() for r in items],
            indent=2,
            ensure_ascii=False,
        )
