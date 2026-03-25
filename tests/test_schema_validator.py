"""Tests for JSON Schema validation — all protocol formats."""

import pytest
from aib.schema_validator import (
    SchemaValidator, SchemaValidationError,
    A2A_AGENT_CARD_SCHEMA, MCP_SERVER_CARD_SCHEMA,
    DID_DOCUMENT_SCHEMA, AIB_PASSPORT_SCHEMA,
    AIB_DISCOVERY_SCHEMA,
)
from aib.translator import CredentialTranslator


@pytest.fixture
def v():
    return SchemaValidator()


@pytest.fixture
def strict_v():
    return SchemaValidator(strict=True)


# ═══════════════════════════════════════════════════════════════════
# A2A Agent Card
# ═══════════════════════════════════════════════════════════════════

class TestA2ASchema:

    def test_valid_minimal(self, v):
        card = {"name": "Booking Agent"}
        assert v.is_valid("a2a_agent_card", card)

    def test_valid_full(self, v):
        card = {
            "name": "Booking Agent",
            "description": "Handles hotel bookings",
            "url": "https://booking.example.com/agent",
            "version": "1.0.0",
            "skills": [
                {"id": "book_hotel", "name": "Book Hotel", "description": "Books a hotel room"},
                {"id": "cancel", "name": "Cancel Booking"},
            ],
            "authentication": {"schemes": ["bearer"]},
            "capabilities": {"streaming": True, "pushNotifications": False},
        }
        assert v.is_valid("a2a_agent_card", card)

    def test_missing_name(self, v):
        errors = v.validate("a2a_agent_card", {"description": "no name"})
        assert len(errors) > 0
        assert any("name" in e for e in errors)

    def test_empty_name(self, v):
        errors = v.validate("a2a_agent_card", {"name": ""})
        assert len(errors) > 0

    def test_name_too_long(self, v):
        errors = v.validate("a2a_agent_card", {"name": "x" * 201})
        assert len(errors) > 0

    def test_too_many_skills(self, v):
        card = {"name": "Agent", "skills": [{"id": f"s{i}", "name": f"Skill {i}"} for i in range(51)]}
        errors = v.validate("a2a_agent_card", card)
        assert len(errors) > 0

    def test_skill_missing_id(self, v):
        card = {"name": "Agent", "skills": [{"name": "Booking"}]}
        errors = v.validate("a2a_agent_card", card)
        assert len(errors) > 0

    def test_extra_fields_allowed(self, v):
        card = {"name": "Agent", "custom_field": "value", "x_extra": 42}
        assert v.is_valid("a2a_agent_card", card)

    def test_alias(self, v):
        card = {"name": "Agent"}
        assert v.is_valid("a2a", card)


# ═══════════════════════════════════════════════════════════════════
# MCP Server Card
# ═══════════════════════════════════════════════════════════════════

class TestMCPSchema:

    def test_valid_minimal(self, v):
        card = {"name": "Calendar MCP"}
        assert v.is_valid("mcp_server_card", card)

    def test_valid_full(self, v):
        card = {
            "name": "Calendar MCP",
            "description": "Calendar tools",
            "server_url": "https://calendar.example.com/mcp",
            "version": "2.1.0",
            "tools": [
                {"name": "create_event", "description": "Creates a calendar event", "inputSchema": {"type": "object"}},
            ],
            "auth": {"type": "oauth2"},
            "transport": "streamable-http",
            "_aib_source": "a2a",
            "_aib_translated_at": "2026-03-25T00:00:00Z",
        }
        assert v.is_valid("mcp_server_card", card)

    def test_invalid_auth_type(self, v):
        card = {"name": "MCP", "auth": {"type": "kerberos"}}
        errors = v.validate("mcp_server_card", card)
        assert len(errors) > 0

    def test_invalid_transport(self, v):
        card = {"name": "MCP", "transport": "websocket"}
        errors = v.validate("mcp_server_card", card)
        assert len(errors) > 0

    def test_tool_missing_name(self, v):
        card = {"name": "MCP", "tools": [{"description": "no name"}]}
        errors = v.validate("mcp_server_card", card)
        assert len(errors) > 0

    def test_alias(self, v):
        card = {"name": "MCP"}
        assert v.is_valid("mcp", card)


# ═══════════════════════════════════════════════════════════════════
# DID Document
# ═══════════════════════════════════════════════════════════════════

class TestDIDSchema:

    def test_valid_minimal(self, v):
        doc = {"id": "did:web:example.com:agents:bot"}
        assert v.is_valid("did_document", doc)

    def test_valid_full(self, v):
        doc = {
            "id": "did:web:example.com:agents:bot",
            "@context": ["https://www.w3.org/ns/did/v1"],
            "verificationMethod": [
                {"id": "did:web:example.com#key-1", "type": "Ed25519VerificationKey2020", "controller": "did:web:example.com"},
            ],
            "service": [
                {"id": "#a2a", "type": "AgentService", "serviceEndpoint": "https://example.com/agent"},
            ],
            "_aib_passport_id": "urn:aib:agent:example:bot",
        }
        assert v.is_valid("did_document", doc)

    def test_invalid_did_format(self, v):
        doc = {"id": "not-a-did"}
        errors = v.validate("did_document", doc)
        assert len(errors) > 0

    def test_missing_id(self, v):
        errors = v.validate("did_document", {"service": []})
        assert len(errors) > 0

    def test_service_missing_endpoint(self, v):
        doc = {
            "id": "did:web:example.com",
            "service": [{"id": "#svc", "type": "Agent"}],
        }
        errors = v.validate("did_document", doc)
        assert len(errors) > 0

    def test_alias(self, v):
        doc = {"id": "did:web:example.com"}
        assert v.is_valid("did", doc)


# ═══════════════════════════════════════════════════════════════════
# AIB Passport
# ═══════════════════════════════════════════════════════════════════

class TestPassportSchema:

    def test_valid_minimal(self, v):
        passport = {
            "passport_id": "urn:aib:agent:acme:booking",
            "issuer": "urn:aib:org:acme",
            "capabilities": ["booking"],
            "protocol_bindings": {
                "mcp": {"auth_method": "oauth2"},
            },
        }
        assert v.is_valid("aib_passport", passport)

    def test_valid_full(self, v):
        passport = {
            "aib_version": "1.5",
            "passport_id": "urn:aib:agent:acme:booking",
            "display_name": "Booking Agent",
            "issuer": "urn:aib:org:acme",
            "capabilities": ["booking", "scheduling"],
            "protocol_bindings": {
                "mcp": {"auth_method": "oauth2", "server_card_url": "https://..."},
                "a2a": {"auth_method": "bearer"},
            },
            "tier": "permanent",
            "issued_at": "2026-03-25T00:00:00Z",
            "expires_at": "2027-03-25T00:00:00Z",
            "jti": "abc-123",
            "delegation": None,
            "metadata": {"env": "production"},
        }
        assert v.is_valid("aib_passport", passport)

    def test_invalid_passport_id_format(self, v):
        passport = {
            "passport_id": "invalid-format",
            "issuer": "urn:aib:org:acme",
            "capabilities": [],
            "protocol_bindings": {},
        }
        errors = v.validate("aib_passport", passport)
        assert len(errors) > 0

    def test_invalid_issuer_format(self, v):
        passport = {
            "passport_id": "urn:aib:agent:acme:bot",
            "issuer": "not-a-urn",
            "capabilities": [],
            "protocol_bindings": {},
        }
        errors = v.validate("aib_passport", passport)
        assert len(errors) > 0

    def test_invalid_tier(self, v):
        passport = {
            "passport_id": "urn:aib:agent:acme:bot",
            "issuer": "urn:aib:org:acme",
            "capabilities": [],
            "protocol_bindings": {},
            "tier": "super_permanent",
        }
        errors = v.validate("aib_passport", passport)
        assert len(errors) > 0

    def test_unknown_protocol_binding(self, v):
        passport = {
            "passport_id": "urn:aib:agent:acme:bot",
            "issuer": "urn:aib:org:acme",
            "capabilities": [],
            "protocol_bindings": {
                "unknown_proto": {"auth_method": "magic"},
            },
        }
        errors = v.validate("aib_passport", passport)
        assert len(errors) > 0

    def test_missing_required_fields(self, v):
        errors = v.validate("aib_passport", {"display_name": "Agent"})
        assert len(errors) >= 3  # passport_id, issuer, capabilities, protocol_bindings

    def test_alias(self, v):
        passport = {
            "passport_id": "urn:aib:agent:acme:bot",
            "issuer": "urn:aib:org:acme",
            "capabilities": [],
            "protocol_bindings": {},
        }
        assert v.is_valid("passport", passport)


# ═══════════════════════════════════════════════════════════════════
# Discovery Document
# ═══════════════════════════════════════════════════════════════════

class TestDiscoverySchema:

    def test_valid(self, v):
        doc = {
            "aib_version": "1.5",
            "issuer": "urn:aib:org:acme",
            "domain": "acme.com",
        }
        assert v.is_valid("aib_discovery", doc)

    def test_missing_required(self, v):
        errors = v.validate("aib_discovery", {"domain": "acme.com"})
        assert len(errors) > 0


# ═══════════════════════════════════════════════════════════════════
# Error Collection
# ═══════════════════════════════════════════════════════════════════

class TestErrorCollection:

    def test_multiple_errors_collected(self, v):
        """Verify ALL errors are returned, not just the first one."""
        passport = {
            "passport_id": "bad-format",
            "issuer": "bad-format",
            "capabilities": "not-a-list",
            # missing protocol_bindings
        }
        errors = v.validate("aib_passport", passport)
        assert len(errors) >= 3

    def test_error_paths_included(self, v):
        card = {"name": "Agent", "skills": [{"name": "X"}]}  # missing id
        errors = v.validate("a2a_agent_card", card)
        assert any("skills" in e for e in errors)

    def test_validate_or_raise(self, v):
        with pytest.raises(SchemaValidationError) as exc:
            v.validate_or_raise("a2a_agent_card", {})
        assert exc.value.format_name == "a2a_agent_card"
        assert len(exc.value.errors) > 0

    def test_validate_or_raise_valid(self, v):
        v.validate_or_raise("a2a_agent_card", {"name": "Agent"})  # No exception


# ═══════════════════════════════════════════════════════════════════
# Strict Mode
# ═══════════════════════════════════════════════════════════════════

class TestStrictMode:

    def test_unknown_format_permissive(self, v):
        errors = v.validate("unknown_format", {"anything": True})
        assert errors == []

    def test_unknown_format_strict(self, strict_v):
        errors = strict_v.validate("unknown_format", {"anything": True})
        assert len(errors) > 0
        assert "Unknown format" in errors[0]


# ═══════════════════════════════════════════════════════════════════
# Custom Schema Registration
# ═══════════════════════════════════════════════════════════════════

class TestCustomSchema:

    def test_register_and_validate(self, v):
        v.register_schema("custom_proto", {
            "type": "object",
            "required": ["endpoint"],
            "properties": {
                "endpoint": {"type": "string"},
            },
        })
        assert v.is_valid("custom_proto", {"endpoint": "https://..."})
        assert not v.is_valid("custom_proto", {"wrong": "field"})

    def test_list_formats(self, v):
        formats = v.list_formats()
        assert "a2a" in formats
        assert "mcp" in formats
        assert "did" in formats
        assert "passport" in formats
        assert "discovery" in formats


# ═══════════════════════════════════════════════════════════════════
# Translation Validation (input + output)
# ═══════════════════════════════════════════════════════════════════

class TestTranslationValidation:

    def test_validate_a2a_to_mcp_translation(self, v):
        source = {
            "name": "Booking Agent",
            "url": "https://booking.example.com",
            "skills": [
                {"id": "book", "name": "Book Hotel", "description": "Books hotels"},
            ],
        }
        result = CredentialTranslator.a2a_to_mcp(source)

        report = v.validate_translation(source, "a2a", result, "mcp")
        assert report["source_valid"] is True
        assert report["result_valid"] is True
        assert report["valid"] is True

    def test_validate_mcp_to_a2a_translation(self, v):
        source = {
            "name": "Calendar MCP",
            "server_url": "https://calendar.example.com",
            "tools": [
                {"name": "create_event", "description": "Creates event"},
            ],
            "auth": {"type": "bearer"},
        }
        result = CredentialTranslator.mcp_to_a2a(source)

        report = v.validate_translation(source, "mcp", result, "a2a")
        assert report["valid"] is True

    def test_invalid_source_detected(self, v):
        source = {}  # Missing name
        result = {"name": "Valid"}

        report = v.validate_translation(source, "a2a", result, "mcp")
        assert report["source_valid"] is False
        assert report["result_valid"] is True
        assert report["valid"] is False

    def test_invalid_result_detected(self, v):
        source = {"name": "Valid A2A"}
        result = {}  # Missing name

        report = v.validate_translation(source, "a2a", result, "mcp")
        assert report["source_valid"] is True
        assert report["result_valid"] is False
        assert report["valid"] is False

    def test_did_translation_valid(self, v):
        source = {
            "name": "Agent",
            "url": "https://example.com",
            "skills": [{"id": "s1", "name": "Skill"}],
        }
        result = CredentialTranslator.to_did_document(
            source, "a2a_agent_card", "example.com", "bot"
        )

        report = v.validate_translation(source, "a2a", result, "did")
        assert report["valid"] is True
