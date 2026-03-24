"""
AIB — Security Hardening: Auto-Rotation + Multi-Signature.

Two mechanisms layered on top of existing crypto.py:

1. AUTO-ROTATION
   - Keys have a max_age (default 90 days)
   - check_rotation() tells you if rotation is needed
   - auto_rotate() rotates if overdue, returns event for audit
   - Grace period: old keys remain for verification
   - Emergency rotation: force immediate rotation + optional revocation

2. MULTI-SIGNATURE
   - A passport can require M-of-N signatures to be valid
   - Each signer is an independent key (potentially on different machines)
   - Forging a passport requires compromising M keys, not just 1
   - Use case: gateway signs + OIDC module co-signs + admin counter-signs

Neither mechanism modifies crypto.py. They wrap and extend.
"""

import json
import uuid
import hashlib
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.backends import default_backend


# ═══════════════════════════════════════════════════════════════════
# 1. AUTO-ROTATION
# ═══════════════════════════════════════════════════════════════════

class RotationPolicy(str, Enum):
    """When to rotate keys."""
    SCHEDULED = "scheduled"      # Regular interval (default 90 days)
    EMERGENCY = "emergency"      # Compromise detected, rotate NOW
    MANUAL = "manual"            # Explicitly triggered


@dataclass
class KeyLifecycle:
    """Tracks the lifecycle of a single signing key."""
    kid: str
    created_at: str
    max_age_days: int = 90
    status: str = "active"       # active, rotated, revoked
    rotated_at: Optional[str] = None
    revoked_at: Optional[str] = None
    rotation_reason: Optional[str] = None
    signatures_count: int = 0

    @property
    def age_days(self) -> float:
        created = datetime.fromisoformat(self.created_at)
        return (datetime.now(timezone.utc) - created).total_seconds() / 86400

    @property
    def needs_rotation(self) -> bool:
        return self.status == "active" and self.age_days >= self.max_age_days

    @property
    def days_until_rotation(self) -> float:
        return max(0, self.max_age_days - self.age_days)

    def to_dict(self) -> dict:
        return {
            "kid": self.kid,
            "created_at": self.created_at,
            "max_age_days": self.max_age_days,
            "age_days": round(self.age_days, 1),
            "status": self.status,
            "needs_rotation": self.needs_rotation,
            "days_until_rotation": round(self.days_until_rotation, 1),
            "rotated_at": self.rotated_at,
            "revoked_at": self.revoked_at,
            "rotation_reason": self.rotation_reason,
            "signatures_count": self.signatures_count,
        }


@dataclass
class RotationEvent:
    """Record of a key rotation for audit trail."""
    event_id: str
    old_kid: Optional[str]
    new_kid: str
    policy: RotationPolicy
    reason: str
    timestamp: str
    old_key_status: str          # "retained" or "revoked"

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "old_kid": self.old_kid,
            "new_kid": self.new_kid,
            "policy": self.policy.value,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "old_key_status": self.old_key_status,
        }


class AutoRotationManager:
    """
    Manages automatic key rotation with lifecycle tracking.

    Usage:
        arm = AutoRotationManager(max_age_days=90)

        # Register a key
        arm.register_key("aib-abc123", created_at="2026-01-01T00:00:00+00:00")

        # Check if rotation is needed (call periodically, e.g. daily cron)
        if arm.check_rotation():
            event = arm.auto_rotate(key_generator=lambda: new_kid)
            # Log the event to audit trail

        # Emergency rotation (compromise detected)
        event = arm.emergency_rotate(
            key_generator=lambda: new_kid,
            revoke_old=True,
            reason="Private key exposed in log"
        )
    """

    def __init__(self, max_age_days: int = 90):
        self.max_age_days = max_age_days
        self._keys: dict[str, KeyLifecycle] = {}
        self._active_kid: Optional[str] = None
        self._events: list[RotationEvent] = []

    def register_key(self, kid: str, created_at: Optional[str] = None) -> KeyLifecycle:
        """Register a key for lifecycle tracking."""
        lifecycle = KeyLifecycle(
            kid=kid,
            created_at=created_at or datetime.now(timezone.utc).isoformat(),
            max_age_days=self.max_age_days,
        )
        self._keys[kid] = lifecycle
        self._active_kid = kid
        return lifecycle

    def check_rotation(self) -> bool:
        """Check if the active key needs rotation."""
        if not self._active_kid:
            return True  # No active key
        lifecycle = self._keys.get(self._active_kid)
        if not lifecycle:
            return True
        return lifecycle.needs_rotation

    def auto_rotate(self, new_kid: str) -> RotationEvent:
        """
        Perform a scheduled rotation.

        The old key is retained for verification (grace period).
        """
        old_kid = self._active_kid
        old_lifecycle = self._keys.get(old_kid) if old_kid else None

        # Mark old key as rotated
        if old_lifecycle:
            old_lifecycle.status = "rotated"
            old_lifecycle.rotated_at = datetime.now(timezone.utc).isoformat()
            old_lifecycle.rotation_reason = "scheduled"

        # Register new key
        self.register_key(new_kid)

        event = RotationEvent(
            event_id=f"rot_{uuid.uuid4().hex[:12]}",
            old_kid=old_kid,
            new_kid=new_kid,
            policy=RotationPolicy.SCHEDULED,
            reason=f"Key age exceeded {self.max_age_days} days",
            timestamp=datetime.now(timezone.utc).isoformat(),
            old_key_status="retained",
        )
        self._events.append(event)
        return event

    def emergency_rotate(
        self,
        new_kid: str,
        revoke_old: bool = True,
        reason: str = "Compromise detected",
    ) -> RotationEvent:
        """
        Emergency rotation — compromise detected.

        If revoke_old=True, the old key is immediately revoked
        (all passports signed with it become unverifiable).
        """
        old_kid = self._active_kid
        old_lifecycle = self._keys.get(old_kid) if old_kid else None

        if old_lifecycle:
            if revoke_old:
                old_lifecycle.status = "revoked"
                old_lifecycle.revoked_at = datetime.now(timezone.utc).isoformat()
            else:
                old_lifecycle.status = "rotated"
                old_lifecycle.rotated_at = datetime.now(timezone.utc).isoformat()
            old_lifecycle.rotation_reason = reason

        self.register_key(new_kid)

        event = RotationEvent(
            event_id=f"rot_{uuid.uuid4().hex[:12]}",
            old_kid=old_kid,
            new_kid=new_kid,
            policy=RotationPolicy.EMERGENCY,
            reason=reason,
            timestamp=datetime.now(timezone.utc).isoformat(),
            old_key_status="revoked" if revoke_old else "retained",
        )
        self._events.append(event)
        return event

    def record_signature(self, kid: str):
        """Increment the signature count for a key (for auditing)."""
        lifecycle = self._keys.get(kid)
        if lifecycle:
            lifecycle.signatures_count += 1

    def get_lifecycle(self, kid: str) -> Optional[KeyLifecycle]:
        return self._keys.get(kid)

    def get_active(self) -> Optional[KeyLifecycle]:
        if self._active_kid:
            return self._keys.get(self._active_kid)
        return None

    def is_key_valid(self, kid: str) -> tuple[bool, str]:
        """Check if a key is valid for verification."""
        lifecycle = self._keys.get(kid)
        if not lifecycle:
            return False, "Key not found"
        if lifecycle.status == "revoked":
            return False, f"Key revoked at {lifecycle.revoked_at}"
        return True, "Valid"

    def list_keys(self) -> list[dict]:
        return [lc.to_dict() for lc in self._keys.values()]

    def get_events(self) -> list[dict]:
        return [e.to_dict() for e in self._events]

    @property
    def active_kid(self) -> Optional[str]:
        return self._active_kid


# ═══════════════════════════════════════════════════════════════════
# 2. MULTI-SIGNATURE
# ═══════════════════════════════════════════════════════════════════

@dataclass
class SignatureSlot:
    """A single signature in a multi-sig passport."""
    signer_id: str               # Who signed (e.g. "gateway", "oidc", "admin")
    kid: str                     # Key ID used
    signature: bytes             # Raw RSA signature
    signed_at: str
    signer_role: str = ""        # "primary", "cosigner", "counter-signer"

    def to_dict(self) -> dict:
        import base64
        return {
            "signer_id": self.signer_id,
            "kid": self.kid,
            "signature": base64.urlsafe_b64encode(self.signature).decode(),
            "signed_at": self.signed_at,
            "signer_role": self.signer_role,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SignatureSlot":
        import base64
        return cls(
            signer_id=d["signer_id"],
            kid=d["kid"],
            signature=base64.urlsafe_b64decode(d["signature"]),
            signed_at=d["signed_at"],
            signer_role=d.get("signer_role", ""),
        )


@dataclass
class MultiSigPolicy:
    """
    Defines the multi-signature requirements for a passport.

    M-of-N: at least M valid signatures from N registered signers.
    """
    required_signatures: int     # M (minimum number of valid signatures)
    total_signers: int           # N (total registered signers)
    signer_ids: list[str]        # List of authorized signer IDs
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "required_signatures": self.required_signatures,
            "total_signers": self.total_signers,
            "signer_ids": self.signer_ids,
            "description": self.description,
        }


class MultiSigVerifier:
    """
    Multi-signature signing and verification for passports.

    Usage:
        # Setup: define a 2-of-3 policy
        policy = MultiSigPolicy(
            required_signatures=2,
            total_signers=3,
            signer_ids=["gateway", "oidc", "admin"],
        )
        verifier = MultiSigVerifier(policy)

        # Register signer keys
        verifier.register_signer("gateway", gateway_private_key, gateway_public_key)
        verifier.register_signer("oidc", oidc_private_key, oidc_public_key)
        verifier.register_signer("admin", admin_private_key, admin_public_key)

        # Sign (each signer signs independently)
        digest = verifier.compute_digest(passport_payload)
        sig1 = verifier.sign(digest, "gateway")
        sig2 = verifier.sign(digest, "oidc")

        # Verify (need 2 of 3)
        result = verifier.verify(digest, [sig1, sig2])
        assert result.valid  # True — 2 signatures meet the 2-of-3 policy
    """

    def __init__(self, policy: MultiSigPolicy):
        self.policy = policy
        self._private_keys: dict[str, Any] = {}
        self._public_keys: dict[str, Any] = {}

    def register_signer(self, signer_id: str, private_key=None, public_key=None):
        """Register a signer's keys."""
        if signer_id not in self.policy.signer_ids:
            raise ValueError(f"Signer '{signer_id}' not in policy: {self.policy.signer_ids}")
        if private_key:
            self._private_keys[signer_id] = private_key
        if public_key:
            self._public_keys[signer_id] = public_key
        elif private_key:
            self._public_keys[signer_id] = private_key.public_key()

    def compute_digest(self, payload: dict) -> bytes:
        """Compute the canonical digest of a passport payload."""
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).digest()

    def sign(self, digest: bytes, signer_id: str, kid: str = "") -> SignatureSlot:
        """
        Sign a digest with a specific signer's key.

        Each signer calls this independently.
        """
        if signer_id not in self._private_keys:
            raise ValueError(f"No private key registered for signer '{signer_id}'")

        private_key = self._private_keys[signer_id]
        signature = private_key.sign(
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            utils.Prehashed(hashes.SHA256()),
        )

        return SignatureSlot(
            signer_id=signer_id,
            kid=kid or f"key-{signer_id}",
            signature=signature,
            signed_at=datetime.now(timezone.utc).isoformat(),
            signer_role="primary" if signer_id == self.policy.signer_ids[0] else "cosigner",
        )

    def verify(self, digest: bytes, signatures: list[SignatureSlot]) -> "MultiSigResult":
        """
        Verify that enough valid signatures meet the policy.

        Returns a MultiSigResult with details on each signature.
        """
        valid_count = 0
        sig_results = []
        seen_signers = set()

        for sig in signatures:
            # Duplicate signer check
            if sig.signer_id in seen_signers:
                sig_results.append({
                    "signer_id": sig.signer_id,
                    "valid": False,
                    "reason": "Duplicate signer",
                })
                continue
            seen_signers.add(sig.signer_id)

            # Check signer is authorized
            if sig.signer_id not in self.policy.signer_ids:
                sig_results.append({
                    "signer_id": sig.signer_id,
                    "valid": False,
                    "reason": "Unauthorized signer",
                })
                continue

            # Check public key exists
            if sig.signer_id not in self._public_keys:
                sig_results.append({
                    "signer_id": sig.signer_id,
                    "valid": False,
                    "reason": "No public key registered",
                })
                continue

            # Verify cryptographic signature
            public_key = self._public_keys[sig.signer_id]
            try:
                public_key.verify(
                    sig.signature,
                    digest,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    utils.Prehashed(hashes.SHA256()),
                )
                valid_count += 1
                sig_results.append({
                    "signer_id": sig.signer_id,
                    "valid": True,
                    "reason": "Valid",
                })
            except Exception as e:
                sig_results.append({
                    "signer_id": sig.signer_id,
                    "valid": False,
                    "reason": f"Invalid signature: {e}",
                })

        meets_policy = valid_count >= self.policy.required_signatures

        return MultiSigResult(
            valid=meets_policy,
            valid_signatures=valid_count,
            required_signatures=self.policy.required_signatures,
            total_submitted=len(signatures),
            details=sig_results,
            reason=f"{valid_count}/{self.policy.required_signatures} valid signatures"
                   + (" — policy met" if meets_policy else " — INSUFFICIENT"),
        )


@dataclass
class MultiSigResult:
    """Result of multi-signature verification."""
    valid: bool
    valid_signatures: int
    required_signatures: int
    total_submitted: int
    details: list[dict]
    reason: str

    def __bool__(self):
        return self.valid

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "valid_signatures": self.valid_signatures,
            "required_signatures": self.required_signatures,
            "total_submitted": self.total_submitted,
            "details": self.details,
            "reason": self.reason,
        }
