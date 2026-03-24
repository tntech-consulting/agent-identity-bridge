"""Tests for GDPR compliance module."""

import pytest
import json
from aib.gdpr import (
    CryptoShredder, ShredError,
    DataExporter,
    PIIGuard, PIIViolationError,
    ConsentManager, ConsentRecord, LegalBasis,
)


# ═══════════════════════════════════════════════════════════════════
# 1. Crypto-Shredding
# ═══════════════════════════════════════════════════════════════════

class TestCryptoShredding:

    @pytest.fixture
    def shredder(self):
        return CryptoShredder()

    def test_encrypt_decrypt_roundtrip(self, shredder):
        encrypted = shredder.encrypt_field("acme", "urn:aib:agent:acme:booking")
        assert encrypted.startswith("ENC:")
        assert encrypted != "urn:aib:agent:acme:booking"

        decrypted = shredder.decrypt_field("acme", encrypted)
        assert decrypted == "urn:aib:agent:acme:booking"

    def test_different_orgs_different_keys(self, shredder):
        e1 = shredder.encrypt_field("org-a", "same-data")
        e2 = shredder.encrypt_field("org-b", "same-data")
        assert e1 != e2  # Different keys produce different ciphertext

    def test_encrypt_receipt(self, shredder):
        receipt = {
            "receipt_id": "rcpt_abc123",
            "passport_id": "urn:aib:agent:acme:bot",
            "display_name": "acme/bot",
            "root_passport_id": "urn:aib:agent:acme:bot",
            "target_url": "https://partner.com/agent",
            "action": "proxy",
            "status": "success",
            "timestamp": "2026-03-24T12:00:00",
        }
        encrypted = shredder.encrypt_receipt("acme", receipt)

        # PII fields encrypted
        assert encrypted["passport_id"].startswith("ENC:")
        assert encrypted["display_name"].startswith("ENC:")
        assert encrypted["target_url"].startswith("ENC:")

        # Non-PII fields unchanged
        assert encrypted["receipt_id"] == "rcpt_abc123"
        assert encrypted["action"] == "proxy"
        assert encrypted["timestamp"] == "2026-03-24T12:00:00"

    def test_decrypt_receipt(self, shredder):
        receipt = {
            "passport_id": "urn:aib:agent:acme:bot",
            "display_name": "acme/bot",
            "root_passport_id": "urn:aib:agent:acme:bot",
            "target_url": "https://partner.com/agent",
            "action": "proxy",
        }
        encrypted = shredder.encrypt_receipt("acme", receipt)
        decrypted = shredder.decrypt_receipt("acme", encrypted)

        assert decrypted["passport_id"] == "urn:aib:agent:acme:bot"
        assert decrypted["display_name"] == "acme/bot"
        assert decrypted["action"] == "proxy"

    def test_shred_makes_data_unreadable(self, shredder):
        encrypted = shredder.encrypt_field("doomed-org", "sensitive-id")
        assert shredder.decrypt_field("doomed-org", encrypted) == "sensitive-id"

        # SHRED - destroy the key
        result = shredder.shred("doomed-org")
        assert result is True

        # Data is now permanently unreadable
        assert shredder.decrypt_field("doomed-org", encrypted) == "[redacted]"

    def test_shred_prevents_new_encryption(self, shredder):
        shredder.shred("dead-org")
        assert shredder.encrypt_field("dead-org", "anything") == "[redacted]"

    def test_shred_prevents_key_creation(self, shredder):
        shredder.shred("dead-org")
        with pytest.raises(ShredError, match="shredded"):
            shredder.get_or_create_key("dead-org")

    def test_shred_nonexistent_org(self, shredder):
        assert shredder.shred("never-existed") is False

    def test_is_shredded(self, shredder):
        assert shredder.is_shredded("acme") is False
        shredder.get_or_create_key("acme")
        shredder.shred("acme")
        assert shredder.is_shredded("acme") is True

    def test_list_orgs(self, shredder):
        shredder.get_or_create_key("active-org")
        shredder.get_or_create_key("doomed-org")
        shredder.shred("doomed-org")

        orgs = shredder.list_orgs()
        assert orgs["active-org"] == "active"
        assert orgs["doomed-org"] == "shredded"

    def test_plaintext_passthrough(self, shredder):
        """Non-encrypted fields pass through decrypt unchanged."""
        assert shredder.decrypt_field("any", "plain-text") == "plain-text"


# ═══════════════════════════════════════════════════════════════════
# 2. Data Portability
# ═══════════════════════════════════════════════════════════════════

class TestDataPortability:

    @pytest.fixture
    def exporter(self):
        return DataExporter()

    def test_export_basic(self, exporter):
        passports = [
            {"passport_id": "urn:aib:agent:acme:bot1", "issuer": "urn:aib:org:acme", "display_name": "acme/bot1"},
            {"passport_id": "urn:aib:agent:acme:bot2", "issuer": "urn:aib:org:acme", "display_name": "acme/bot2"},
            {"passport_id": "urn:aib:agent:other:x", "issuer": "urn:aib:org:other", "display_name": "other/x"},
        ]
        receipts = [
            {"passport_id": "urn:aib:agent:acme:bot1", "action": "proxy"},
            {"passport_id": "urn:aib:agent:acme:bot2", "action": "translate"},
            {"passport_id": "urn:aib:agent:other:x", "action": "proxy"},
        ]

        export = exporter.export_org("acme", passports, receipts)

        assert export["org_id"] == "acme"
        assert export["statistics"]["passports"] == 2
        assert export["statistics"]["receipts"] == 2
        assert len(export["data"]["passports"]) == 2
        assert len(export["data"]["receipts"]) == 2

    def test_export_excludes_other_orgs(self, exporter):
        passports = [
            {"passport_id": "urn:aib:agent:acme:bot1", "issuer": "urn:aib:org:acme"},
            {"passport_id": "urn:aib:agent:rival:bot", "issuer": "urn:aib:org:rival"},
        ]
        export = exporter.export_org("acme", passports, [])
        assert export["statistics"]["passports"] == 1

    def test_export_strips_tokens(self, exporter):
        passports = [{"passport_id": "urn:aib:agent:acme:bot", "issuer": "urn:aib:org:acme", "token": "eyJ...secret"}]
        export = exporter.export_org("acme", passports, [])
        assert "token" not in export["data"]["passports"][0]

    def test_export_includes_tokens_when_requested(self, exporter):
        passports = [{"passport_id": "urn:aib:agent:acme:bot", "issuer": "urn:aib:org:acme", "token": "eyJ...secret"}]
        export = exporter.export_org("acme", passports, [], include_tokens=True)
        assert export["data"]["passports"][0]["token"] == "eyJ...secret"

    def test_export_json(self, exporter):
        export = exporter.export_org("acme", [], [])
        json_str = exporter.export_json(export)
        parsed = json.loads(json_str)
        assert parsed["org_id"] == "acme"

    def test_export_checksum(self, exporter):
        export = exporter.export_org("acme", [], [])
        checksum = exporter.compute_checksum(export)
        assert len(checksum) == 64  # SHA-256 hex

        # Same export = same checksum
        checksum2 = exporter.compute_checksum(export)
        assert checksum == checksum2

    def test_export_has_metadata(self, exporter):
        export = exporter.export_org("test", [], [])
        assert "GDPR Article 20" in export["metadata"]["notice"]
        assert export["export_version"] == "1.0"

    def test_export_with_root_passport_receipts(self, exporter):
        passports = [{"passport_id": "urn:aib:agent:acme:root", "issuer": "urn:aib:org:acme"}]
        receipts = [
            {"passport_id": "urn:aib:agent:acme:child", "root_passport_id": "urn:aib:agent:acme:root", "action": "proxy"},
        ]
        export = exporter.export_org("acme", passports, receipts)
        assert export["statistics"]["receipts"] == 1


# ═══════════════════════════════════════════════════════════════════
# 3. Data Minimization (PII Guard)
# ═══════════════════════════════════════════════════════════════════

class TestPIIGuard:

    @pytest.fixture
    def guard(self):
        return PIIGuard(strict=True)

    @pytest.fixture
    def relaxed_guard(self):
        return PIIGuard(strict=False)

    def test_clean_metadata_passes(self, guard):
        metadata = {"environment": "production", "region": "eu-west-1", "version": "1.0"}
        is_clean, violations = guard.check(metadata)
        assert is_clean is True
        assert len(violations) == 0

    def test_blocked_key_email(self, guard):
        metadata = {"email": "thomas@example.com"}
        is_clean, violations = guard.check(metadata)
        assert is_clean is False
        assert any("email" in v.lower() for v in violations)

    def test_blocked_key_phone(self, guard):
        metadata = {"phone": "+33612345678"}
        is_clean, violations = guard.check(metadata)
        assert is_clean is False

    def test_blocked_key_ssn(self, guard):
        metadata = {"ssn": "123-45-6789"}
        is_clean, violations = guard.check(metadata)
        assert is_clean is False

    def test_blocked_key_address(self, guard):
        metadata = {"address": "123 Main St"}
        is_clean, violations = guard.check(metadata)
        assert is_clean is False

    def test_blocked_key_date_of_birth(self, guard):
        metadata = {"date_of_birth": "1990-01-01"}
        is_clean, violations = guard.check(metadata)
        assert is_clean is False

    def test_blocked_key_case_insensitive(self, guard):
        metadata = {"Email": "test@test.com"}
        is_clean, violations = guard.check(metadata)
        assert is_clean is False

    def test_blocked_key_with_dashes(self, guard):
        metadata = {"date-of-birth": "1990-01-01"}
        is_clean, violations = guard.check(metadata)
        assert is_clean is False

    def test_strict_detects_email_in_value(self, guard):
        metadata = {"contact": "thomas@example.com"}
        is_clean, violations = guard.check(metadata)
        assert is_clean is False
        assert any("PII detected" in v for v in violations)

    def test_relaxed_ignores_value_patterns(self, relaxed_guard):
        metadata = {"contact": "thomas@example.com"}
        is_clean, violations = relaxed_guard.check(metadata)
        # Relaxed mode only checks keys, not values
        assert is_clean is True

    def test_sanitize_removes_pii(self, guard):
        metadata = {
            "environment": "production",
            "email": "secret@example.com",
            "region": "eu-west-1",
            "phone": "+33612345678",
        }
        cleaned = guard.sanitize(metadata)
        assert "environment" in cleaned
        assert "region" in cleaned
        assert "email" not in cleaned
        assert "phone" not in cleaned

    def test_sanitize_does_not_modify_original(self, guard):
        metadata = {"email": "test@test.com", "ok": "fine"}
        cleaned = guard.sanitize(metadata)
        assert "email" in metadata  # Original unchanged
        assert "email" not in cleaned


# ═══════════════════════════════════════════════════════════════════
# 4. Consent Tracking
# ═══════════════════════════════════════════════════════════════════

class TestConsentTracking:

    @pytest.fixture
    def cm(self):
        return ConsentManager()

    def test_record_consent(self, cm):
        record = cm.record_consent(
            org_id="acme",
            legal_basis=LegalBasis.CONTRACT,
            purpose="Agent identity management for contracted services",
            granted_by="admin@acme.com",
        )
        assert record.consent_id.startswith("consent_")
        assert record.legal_basis == LegalBasis.CONTRACT
        assert record.revoked is False

    def test_has_valid_consent(self, cm):
        cm.record_consent(
            org_id="acme",
            legal_basis=LegalBasis.LEGITIMATE_INTEREST,
            purpose="Agent operations",
            granted_by="system",
        )
        has, cid = cm.has_valid_consent("acme")
        assert has is True

    def test_no_consent(self, cm):
        has, reason = cm.has_valid_consent("unknown-org")
        assert has is False
        assert "No consent" in reason

    def test_revoked_consent_invalid(self, cm):
        record = cm.record_consent(
            org_id="acme",
            legal_basis=LegalBasis.CONSENT,
            purpose="Test",
            granted_by="user",
        )
        cm.revoke_consent(record.consent_id)

        has, reason = cm.has_valid_consent("acme")
        assert has is False

    def test_scope_check(self, cm):
        cm.record_consent(
            org_id="acme",
            legal_basis=LegalBasis.CONTRACT,
            purpose="Only audit",
            granted_by="admin",
            scope=["audit_logging"],
        )
        has_audit, _ = cm.has_valid_consent("acme", scope="audit_logging")
        has_passport, _ = cm.has_valid_consent("acme", scope="passport_creation")
        assert has_audit is True
        assert has_passport is False

    def test_multiple_consents(self, cm):
        cm.record_consent(org_id="acme", legal_basis=LegalBasis.CONSENT, purpose="p1", granted_by="u1", scope=["passport_creation"])
        cm.record_consent(org_id="acme", legal_basis=LegalBasis.CONTRACT, purpose="p2", granted_by="u2", scope=["audit_logging"])

        has_p, _ = cm.has_valid_consent("acme", scope="passport_creation")
        has_a, _ = cm.has_valid_consent("acme", scope="audit_logging")
        assert has_p is True
        assert has_a is True

    def test_export_consents(self, cm):
        cm.record_consent(org_id="acme", legal_basis=LegalBasis.CONTRACT, purpose="Test", granted_by="admin")
        exported = cm.export_consents("acme")
        assert len(exported) == 1
        assert exported[0]["legal_basis"] == "contract"

    def test_get_org_consents(self, cm):
        cm.record_consent(org_id="acme", legal_basis=LegalBasis.CONTRACT, purpose="p1", granted_by="u1")
        cm.record_consent(org_id="acme", legal_basis=LegalBasis.CONSENT, purpose="p2", granted_by="u2")
        cm.record_consent(org_id="other", legal_basis=LegalBasis.CONTRACT, purpose="p3", granted_by="u3")

        acme_consents = cm.get_org_consents("acme")
        assert len(acme_consents) == 2

    def test_consent_record_to_dict(self, cm):
        record = cm.record_consent(org_id="acme", legal_basis=LegalBasis.LEGITIMATE_INTEREST, purpose="ops", granted_by="sys")
        d = record.to_dict()
        assert d["org_id"] == "acme"
        assert d["legal_basis"] == "legitimate_interest"
        assert d["revoked"] is False

    def test_revoke_nonexistent(self, cm):
        assert cm.revoke_consent("consent_doesnotexist") is False

    def test_revoke_sets_timestamp(self, cm):
        record = cm.record_consent(org_id="x", legal_basis=LegalBasis.CONSENT, purpose="t", granted_by="u")
        cm.revoke_consent(record.consent_id)
        assert record.revoked_at is not None
