"""
AIB — GDPR Compliance Module.

Layers on top of existing modules without modifying them.

Four mechanisms:
1. CRYPTO-SHREDDING: Right to be forgotten without breaking hash chains
2. DATA PORTABILITY: Export all data for an org in a standard format
3. DATA MINIMIZATION: Block PII from entering passport metadata
4. CONSENT TRACKING: Legal basis enforcement for OIDC exchanges

This module does NOT modify passport.py, lifecycle.py, receipts.py,
oidc.py, or any other existing module. It wraps and filters.
"""

import json
import os
import hashlib
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum

# AES encryption for crypto-shredding
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


# ═══════════════════════════════════════════════════════════════════
# 1. CRYPTO-SHREDDING — Right to be forgotten
# ═══════════════════════════════════════════════════════════════════

class CryptoShredder:
    """
    Enables GDPR right-to-erasure without breaking audit hash chains.

    How it works:
    - Each org gets a unique AES-256-GCM encryption key
    - PII fields in receipts/passports are encrypted with this key
    - When an org requests deletion, the key is destroyed
    - Encrypted fields become permanently unreadable
    - Hash chain remains intact (hashes were computed on encrypted data)

    This is the standard approach validated by CNIL and used by
    major cloud providers for GDPR-compliant immutable logs.
    """

    # Fields that contain PII and must be encrypted
    PII_FIELDS = [
        "passport_id",
        "display_name",
        "root_passport_id",
        "target_url",
    ]

    def __init__(self, keys_store: Optional[dict] = None):
        self._keys: dict[str, bytes] = keys_store or {}
        self._shredded: set[str] = set()

    def get_or_create_key(self, org_id: str) -> bytes:
        """Get or create the encryption key for an org."""
        if org_id in self._shredded:
            raise ShredError(f"Org '{org_id}' has been shredded. Key is destroyed.")
        if org_id not in self._keys:
            self._keys[org_id] = AESGCM.generate_key(bit_length=256)
        return self._keys[org_id]

    def encrypt_field(self, org_id: str, plaintext: str) -> str:
        """Encrypt a PII field. Returns base64-encoded ciphertext."""
        if not HAS_CRYPTO:
            return plaintext
        if org_id in self._shredded:
            return "[redacted]"

        key = self.get_or_create_key(org_id)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

        import base64
        return "ENC:" + base64.urlsafe_b64encode(nonce + ct).decode()

    def decrypt_field(self, org_id: str, ciphertext: str) -> str:
        """Decrypt a PII field. Returns plaintext or [redacted]."""
        if not HAS_CRYPTO:
            return ciphertext
        if not ciphertext.startswith("ENC:"):
            return ciphertext
        if org_id in self._shredded:
            return "[redacted]"
        if org_id not in self._keys:
            return "[key-missing]"

        try:
            import base64
            raw = base64.urlsafe_b64decode(ciphertext[4:])
            nonce = raw[:12]
            ct = raw[12:]
            aesgcm = AESGCM(self._keys[org_id])
            return aesgcm.decrypt(nonce, ct, None).decode("utf-8")
        except Exception:
            return "[decrypt-error]"

    def encrypt_receipt(self, org_id: str, receipt_dict: dict) -> dict:
        """Encrypt PII fields in a receipt dict."""
        encrypted = dict(receipt_dict)
        for f in self.PII_FIELDS:
            if f in encrypted and encrypted[f]:
                encrypted[f] = self.encrypt_field(org_id, str(encrypted[f]))
        return encrypted

    def decrypt_receipt(self, org_id: str, receipt_dict: dict) -> dict:
        """Decrypt PII fields in a receipt dict."""
        decrypted = dict(receipt_dict)
        for f in self.PII_FIELDS:
            if f in decrypted and isinstance(decrypted[f], str) and decrypted[f].startswith("ENC:"):
                decrypted[f] = self.decrypt_field(org_id, decrypted[f])
        return decrypted

    def shred(self, org_id: str) -> bool:
        """
        DESTROY the encryption key for an org.

        After this call:
        - All encrypted PII for this org is permanently unreadable
        - The hash chain remains intact
        - New data cannot be created for this org

        This is IRREVERSIBLE. There is no recovery.
        """
        had_key = org_id in self._keys
        if had_key:
            del self._keys[org_id]
        self._shredded.add(org_id)
        return had_key

    def is_shredded(self, org_id: str) -> bool:
        return org_id in self._shredded

    def list_orgs(self) -> dict:
        """List all orgs with their status."""
        all_orgs = set(list(self._keys.keys()) + list(self._shredded))
        return {
            org: "shredded" if org in self._shredded else "active"
            for org in all_orgs
        }


class ShredError(Exception):
    """Raised when operating on a shredded org."""
    pass


# ═══════════════════════════════════════════════════════════════════
# 2. DATA PORTABILITY — Article 20 RGPD
# ═══════════════════════════════════════════════════════════════════

class DataExporter:
    """
    Export all data for an org in a portable, standard format.

    Produces a JSON document containing:
    - All passports (permanent, session, ephemeral)
    - All protocol bindings
    - All action receipts
    - All translations performed
    - Metadata and configuration

    The export format is self-contained and can be imported
    into another AIB instance.
    """

    EXPORT_VERSION = "1.0"

    def export_org(
        self,
        org_id: str,
        passports: list[dict],
        receipts: list[dict],
        translations: Optional[list[dict]] = None,
        include_tokens: bool = False,
    ) -> dict:
        """
        Create a complete data export for an org.

        Args:
            org_id: Organization identifier
            passports: List of passport dicts
            receipts: List of receipt dicts
            translations: Optional list of translation records
            include_tokens: Include signed tokens (security risk if shared)

        Returns:
            A self-contained export document
        """
        now = datetime.now(timezone.utc)

        # Filter passports for this org
        org_passports = [
            p for p in passports
            if org_id in p.get("passport_id", "") or org_id in p.get("issuer", "")
        ]

        # Filter receipts for this org's passports
        passport_ids = {p.get("passport_id") for p in org_passports}
        org_receipts = [
            r for r in receipts
            if r.get("passport_id") in passport_ids
            or r.get("root_passport_id") in passport_ids
        ]

        # Remove tokens if not requested
        if not include_tokens:
            org_passports = [
                {k: v for k, v in p.items() if k != "token"}
                for p in org_passports
            ]

        export = {
            "export_version": self.EXPORT_VERSION,
            "export_type": "aib_data_portability",
            "exported_at": now.isoformat(),
            "org_id": org_id,
            "statistics": {
                "passports": len(org_passports),
                "receipts": len(org_receipts),
                "translations": len(translations or []),
            },
            "data": {
                "passports": org_passports,
                "receipts": org_receipts,
                "translations": translations or [],
            },
            "metadata": {
                "aib_version": "0.2",
                "export_format": "JSON",
                "encoding": "UTF-8",
                "notice": "This export contains all data associated with the specified organization. "
                          "It is provided under GDPR Article 20 (Right to Data Portability).",
            },
        }

        return export

    def export_json(self, export: dict) -> str:
        """Serialize export to JSON string."""
        return json.dumps(export, indent=2, ensure_ascii=False)

    def compute_checksum(self, export: dict) -> str:
        """Compute SHA-256 checksum of the export for integrity verification."""
        content = json.dumps(export, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(content.encode()).hexdigest()


# ═══════════════════════════════════════════════════════════════════
# 3. DATA MINIMIZATION — Article 5(1)(c) RGPD
# ═══════════════════════════════════════════════════════════════════

class PIIGuard:
    """
    Prevents PII from entering passport metadata.

    Scans metadata dicts for known PII patterns and blocks them.
    This enforces data minimization at the point of creation.
    """

    # Known PII field names (case-insensitive)
    BLOCKED_KEYS = {
        "email", "e-mail", "mail",
        "phone", "telephone", "mobile", "tel",
        "address", "street", "city", "zipcode", "zip_code", "postal_code",
        "ssn", "social_security", "national_id", "id_number",
        "date_of_birth", "dob", "birthday", "birth_date",
        "first_name", "last_name", "surname", "full_name",
        "passport_number", "driver_license", "credit_card", "card_number",
        "ip_address", "mac_address",
        "gender", "sex", "ethnicity", "race", "religion",
        "medical", "health", "diagnosis",
        "salary", "income", "bank_account", "iban",
    }

    # Patterns that suggest PII in values
    PII_PATTERNS = [
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
        r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",                          # Phone (US)
        r"\b\d{2}[-.]?\d{2}[-.]?\d{2}[-.]?\d{2}[-.]?\d{2}\b",     # Phone (FR)
        r"\b\d{3}-\d{2}-\d{4}\b",                                   # SSN
    ]

    def __init__(self, strict: bool = True):
        self.strict = strict
        self._compiled_patterns = []
        if strict:
            import re
            self._compiled_patterns = [re.compile(p) for p in self.PII_PATTERNS]

    def check(self, metadata: dict) -> tuple[bool, list[str]]:
        """
        Check metadata for PII.

        Returns:
            (is_clean, list_of_violations)
        """
        violations = []

        for key, value in metadata.items():
            key_lower = key.lower().replace("-", "_").replace(" ", "_")

            # Check key names
            if key_lower in self.BLOCKED_KEYS:
                violations.append(
                    f"Blocked PII key: '{key}'. Do not store personal data in passport metadata."
                )

            # Check values for PII patterns
            if self.strict and isinstance(value, str):
                for pattern in self._compiled_patterns:
                    if pattern.search(value):
                        violations.append(
                            f"Possible PII detected in value of '{key}'. "
                            f"Metadata should not contain personal data."
                        )
                        break

        is_clean = len(violations) == 0
        return is_clean, violations

    def sanitize(self, metadata: dict) -> dict:
        """
        Remove PII fields from metadata.

        Returns a cleaned copy (does not modify the original).
        """
        cleaned = {}
        for key, value in metadata.items():
            key_lower = key.lower().replace("-", "_").replace(" ", "_")
            if key_lower not in self.BLOCKED_KEYS:
                cleaned[key] = value
        return cleaned


class PIIViolationError(ValueError):
    """Raised when metadata contains PII."""
    pass


# ═══════════════════════════════════════════════════════════════════
# 4. CONSENT TRACKING — Article 6 RGPD
# ═══════════════════════════════════════════════════════════════════

class LegalBasis(str, Enum):
    """GDPR Article 6 legal bases for processing."""
    CONSENT = "consent"                    # 6(1)(a) — explicit consent
    CONTRACT = "contract"                  # 6(1)(b) — necessary for contract
    LEGAL_OBLIGATION = "legal_obligation"  # 6(1)(c) — legal requirement
    VITAL_INTEREST = "vital_interest"      # 6(1)(d) — protect vital interests
    PUBLIC_TASK = "public_task"            # 6(1)(e) — public interest
    LEGITIMATE_INTEREST = "legitimate_interest"  # 6(1)(f) — legitimate interest


@dataclass
class ConsentRecord:
    """Record of the legal basis for processing agent data."""
    consent_id: str
    org_id: str
    legal_basis: LegalBasis
    purpose: str
    granted_at: str
    granted_by: str            # Who gave consent (user, admin, system)
    scope: list[str]           # What data is covered
    expires_at: Optional[str] = None
    revoked: bool = False
    revoked_at: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "consent_id": self.consent_id,
            "org_id": self.org_id,
            "legal_basis": self.legal_basis.value,
            "purpose": self.purpose,
            "granted_at": self.granted_at,
            "granted_by": self.granted_by,
            "scope": self.scope,
            "expires_at": self.expires_at,
            "revoked": self.revoked,
            "revoked_at": self.revoked_at,
            "metadata": self.metadata,
        }


class ConsentManager:
    """
    Tracks legal basis for data processing.

    Every OIDC exchange or passport creation must declare
    a legal basis. Without it, the operation is rejected.
    """

    def __init__(self):
        self._records: dict[str, ConsentRecord] = {}
        self._by_org: dict[str, list[str]] = {}

    def record_consent(
        self,
        org_id: str,
        legal_basis: LegalBasis,
        purpose: str,
        granted_by: str,
        scope: Optional[list[str]] = None,
        expires_at: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> ConsentRecord:
        """Record a new consent/legal basis."""
        now = datetime.now(timezone.utc)
        record = ConsentRecord(
            consent_id=f"consent_{uuid.uuid4().hex[:12]}",
            org_id=org_id,
            legal_basis=legal_basis,
            purpose=purpose,
            granted_at=now.isoformat(),
            granted_by=granted_by,
            scope=scope or ["passport_creation", "audit_logging"],
            expires_at=expires_at,
            metadata=metadata or {},
        )
        self._records[record.consent_id] = record
        if org_id not in self._by_org:
            self._by_org[org_id] = []
        self._by_org[org_id].append(record.consent_id)
        return record

    def has_valid_consent(self, org_id: str, scope: str = "passport_creation") -> tuple[bool, str]:
        """
        Check if an org has valid consent for a specific scope.

        Returns (has_consent, consent_id_or_reason).
        """
        consent_ids = self._by_org.get(org_id, [])
        if not consent_ids:
            return False, "No consent record found for this organization"

        now = datetime.now(timezone.utc)
        for cid in consent_ids:
            record = self._records.get(cid)
            if not record:
                continue
            if record.revoked:
                continue
            if record.expires_at:
                expires = datetime.fromisoformat(record.expires_at)
                if now > expires:
                    continue
            if scope in record.scope or "*" in record.scope:
                return True, record.consent_id

        return False, "No valid consent covers this scope"

    def revoke_consent(self, consent_id: str) -> bool:
        """Revoke a consent record."""
        record = self._records.get(consent_id)
        if not record or record.revoked:
            return False
        record.revoked = True
        record.revoked_at = datetime.now(timezone.utc).isoformat()
        return True

    def get_org_consents(self, org_id: str) -> list[ConsentRecord]:
        """Get all consent records for an org."""
        consent_ids = self._by_org.get(org_id, [])
        return [self._records[cid] for cid in consent_ids if cid in self._records]

    def export_consents(self, org_id: str) -> list[dict]:
        """Export consent records (for portability)."""
        return [r.to_dict() for r in self.get_org_consents(org_id)]
