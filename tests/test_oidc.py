"""Tests for OIDC Binding — enterprise IdP integration."""

import pytest
import json
import time
import jwt as pyjwt
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from aib.oidc import (
    OIDCProvider, OIDCTokenValidator, ClaimMapper, OIDCBridge,
    ExchangeResult, ValidatedToken,
    ENTRA_PRESET, OKTA_PRESET, AUTH0_PRESET, KEYCLOAK_PRESET,
)


# ── Fixtures ──────────────────────────────────────────────────────

@pytest.fixture
def rsa_key():
    """Generate RSA key pair for test token signing."""
    private = rsa.generate_private_key(65537, 2048, default_backend())
    return private


@pytest.fixture
def entra_provider():
    return OIDCProvider(
        name="entra",
        issuer_url="https://login.microsoftonline.com/test-tenant/v2.0",
        client_id="aib-test-app",
        allowed_audiences=["aib-test-app"],
        claim_mapping=ENTRA_PRESET["claim_mapping"],
    )


@pytest.fixture
def okta_provider():
    return OIDCProvider(
        name="okta",
        issuer_url="https://dev-123456.okta.com",
        client_id="aib-okta-app",
        claim_mapping=OKTA_PRESET["claim_mapping"],
    )


@pytest.fixture
def auth0_provider():
    return OIDCProvider(
        name="auth0",
        issuer_url="https://myapp.auth0.com",
        client_id="aib-auth0-app",
        claim_mapping=AUTH0_PRESET["claim_mapping"],
    )


def make_token(claims: dict, key=None) -> str:
    """Create a test JWT token."""
    defaults = {
        "iss": "https://login.microsoftonline.com/test-tenant/v2.0",
        "sub": "agent-001",
        "aud": "aib-test-app",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    merged = {**defaults, **claims}
    if key:
        return pyjwt.encode(merged, key, algorithm="RS256", headers={"kid": "test-key-1"})
    return pyjwt.encode(merged, "test-secret", algorithm="HS256")


# ═══════════════════════════════════════════════════════════════════
# Token Validation
# ═══════════════════════════════════════════════════════════════════

class TestTokenValidation:

    def test_validate_unverified(self, entra_provider):
        token = make_token({"name": "Test Agent", "roles": ["Agent.Booking"]})
        validator = OIDCTokenValidator(entra_provider)
        result = validator.validate(token, verify_signature=False)
        assert result.valid is True
        assert result.subject == "agent-001"
        assert "roles" in result.claims

    def test_expired_token(self, entra_provider):
        token = make_token({"exp": int(time.time()) - 3600})
        validator = OIDCTokenValidator(entra_provider)
        result = validator.validate(token, verify_signature=False)
        assert result.valid is False
        assert "expired" in result.error.lower()

    def test_extract_expiry(self, entra_provider):
        future = int(time.time()) + 7200
        token = make_token({"exp": future})
        validator = OIDCTokenValidator(entra_provider)
        result = validator.validate(token, verify_signature=False)
        assert result.valid is True
        assert result.expires_at is not None
        assert result.expires_at > datetime.now(timezone.utc)


# ═══════════════════════════════════════════════════════════════════
# Claim Mapping — Entra
# ═══════════════════════════════════════════════════════════════════

class TestEntraClaimMapping:

    def test_extract_agent_id(self, entra_provider):
        mapper = ClaimMapper(entra_provider)
        claims = {"sub": "agent-booking-001", "name": "Booking Bot"}
        assert mapper.extract_agent_id(claims) == "agent-booking-001"

    def test_extract_display_name(self, entra_provider):
        mapper = ClaimMapper(entra_provider)
        claims = {"sub": "x", "name": "Booking Bot"}
        assert mapper.extract_display_name(claims) == "Booking Bot"

    def test_extract_capabilities_from_roles(self, entra_provider):
        mapper = ClaimMapper(entra_provider)
        claims = {"roles": ["Agent.Booking", "Agent.Search", "Agent.Analytics"]}
        caps = mapper.extract_capabilities(claims)
        assert "booking" in caps
        assert "search" in caps
        assert "analytics" in caps

    def test_extract_capabilities_default(self, entra_provider):
        mapper = ClaimMapper(entra_provider)
        claims = {}  # No roles
        caps = mapper.extract_capabilities(claims)
        assert caps == ["default"]

    def test_derive_org_from_tenant(self):
        provider = OIDCProvider(name="entra", issuer_url="https://login.microsoftonline.com/abc123/v2.0", client_id="x", claim_mapping=ENTRA_PRESET["claim_mapping"])
        bridge = OIDCBridge(provider)
        org = bridge._derive_org({"tid": "abc12345-def6-7890"})
        assert org == "tenant-abc12345"


# ═══════════════════════════════════════════════════════════════════
# Claim Mapping — Okta
# ═══════════════════════════════════════════════════════════════════

class TestOktaClaimMapping:

    def test_extract_capabilities_from_groups(self, okta_provider):
        mapper = ClaimMapper(okta_provider)
        claims = {"groups": ["booking-agents", "search-agents"]}
        caps = mapper.extract_capabilities(claims)
        assert "booking-agents" in caps
        assert "search-agents" in caps

    def test_extract_protocols_from_groups(self, okta_provider):
        mapper = ClaimMapper(okta_provider)
        claims = {"groups": ["mcp-agents", "a2a-agents"]}
        protocols = mapper.extract_protocols(claims)
        assert "mcp" in protocols
        assert "a2a" in protocols

    def test_extract_protocols_from_scopes(self, okta_provider):
        mapper = ClaimMapper(okta_provider)
        claims = {"scp": "openid profile mcp:read a2a:write"}
        protocols = mapper.extract_protocols(claims)
        assert "mcp" in protocols
        assert "a2a" in protocols


# ═══════════════════════════════════════════════════════════════════
# Claim Mapping — Auth0
# ═══════════════════════════════════════════════════════════════════

class TestAuth0ClaimMapping:

    def test_extract_capabilities_from_permissions(self, auth0_provider):
        mapper = ClaimMapper(auth0_provider)
        claims = {"permissions": ["read:calendar", "write:booking", "admin:analytics"]}
        caps = mapper.extract_capabilities(claims)
        assert "read:calendar" in caps
        assert "write:booking" in caps
        assert "admin:analytics" in caps


# ═══════════════════════════════════════════════════════════════════
# Full Exchange Flow
# ═══════════════════════════════════════════════════════════════════

class TestExchangeFlow:

    def test_successful_exchange(self, entra_provider):
        token = make_token({
            "name": "Booking Agent",
            "roles": ["Agent.Booking", "Agent.Search"],
        })
        bridge = OIDCBridge(entra_provider)
        result = bridge.exchange(token, verify_signature=False)

        assert result.success is True
        assert result.display_name == "Booking Agent"
        assert "booking" in result.capabilities
        assert "search" in result.capabilities
        assert result.oidc_subject == "agent-001"
        assert result.metadata["oidc_provider"] == "entra"
        assert result.metadata["created_by"] == "oidc_exchange"

    def test_exchange_sets_protocols(self, entra_provider):
        token = make_token({"roles": ["Agent.Booking"]})
        bridge = OIDCBridge(entra_provider)
        result = bridge.exchange(token, verify_signature=False)
        assert "mcp" in result.protocols
        assert "a2a" in result.protocols

    def test_exchange_sets_protocol_bindings(self, entra_provider):
        token = make_token({})
        bridge = OIDCBridge(entra_provider)
        result = bridge.exchange(token, verify_signature=False)
        assert "mcp" in result.protocol_bindings
        assert result.protocol_bindings["mcp"]["oidc_source"] == "entra"

    def test_exchange_expired_token(self, entra_provider):
        token = make_token({"exp": int(time.time()) - 3600})
        bridge = OIDCBridge(entra_provider)
        result = bridge.exchange(token, verify_signature=False)
        assert result.success is False
        assert "expired" in result.error.lower()

    def test_exchange_ttl_clamped(self, entra_provider):
        # Token expires in 2 hours
        token = make_token({"exp": int(time.time()) + 7200})
        bridge = OIDCBridge(entra_provider)
        result = bridge.exchange(token, verify_signature=False)
        assert result.success is True
        assert result.ttl_seconds is not None
        assert result.ttl_seconds <= 7200
        assert result.ttl_seconds > 0

    def test_exchange_custom_org(self, entra_provider):
        token = make_token({})
        bridge = OIDCBridge(entra_provider)
        result = bridge.exchange(token, verify_signature=False, org_slug="acme")
        assert result.org == "acme"

    def test_exchange_custom_tier(self, entra_provider):
        token = make_token({})
        bridge = OIDCBridge(entra_provider)
        result = bridge.exchange(token, verify_signature=False, tier="ephemeral")
        assert result.tier == "ephemeral"

    def test_exchange_result_bool(self, entra_provider):
        token = make_token({})
        bridge = OIDCBridge(entra_provider)
        result = bridge.exchange(token, verify_signature=False)
        assert bool(result) is True

        bad = ExchangeResult(success=False, error="test")
        assert bool(bad) is False

    def test_exchange_with_metadata(self, entra_provider):
        token = make_token({})
        bridge = OIDCBridge(entra_provider)
        result = bridge.exchange(
            token, verify_signature=False,
            extra_metadata={"workflow": "test-42", "environment": "staging"},
        )
        assert result.metadata["workflow"] == "test-42"
        assert result.metadata["environment"] == "staging"
        assert result.metadata["oidc_provider"] == "entra"


# ═══════════════════════════════════════════════════════════════════
# Full claim mapping output
# ═══════════════════════════════════════════════════════════════════

class TestFullMapping:

    def test_map_entra_claims(self, entra_provider):
        mapper = ClaimMapper(entra_provider)
        claims = {
            "sub": "agent-123",
            "name": "My Agent",
            "roles": ["Agent.Booking", "Agent.Analytics"],
            "tid": "tenant-abc",
            "iss": "https://login.microsoftonline.com/test/v2.0",
        }
        mapped = mapper.map_to_passport_fields(claims)
        assert mapped["agent_id"] == "agent-123"
        assert mapped["display_name"] == "My Agent"
        assert "booking" in mapped["capabilities"]
        assert "analytics" in mapped["capabilities"]
        assert mapped["oidc_issuer"] == "https://login.microsoftonline.com/test/v2.0"

    def test_map_okta_claims(self, okta_provider):
        mapper = ClaimMapper(okta_provider)
        claims = {
            "sub": "okta-agent-x",
            "name": "Okta Bot",
            "groups": ["mcp-readers", "a2a-writers"],
            "scp": "openid mcp:tools",
        }
        mapped = mapper.map_to_passport_fields(claims)
        assert mapped["agent_id"] == "okta-agent-x"
        assert "mcp" in mapped["protocols"]

    def test_map_auth0_claims(self, auth0_provider):
        mapper = ClaimMapper(auth0_provider)
        claims = {
            "sub": "auth0|agent-456",
            "name": "Auth0 Agent",
            "permissions": ["read:data", "write:booking"],
        }
        mapped = mapper.map_to_passport_fields(claims)
        assert "read:data" in mapped["capabilities"]
        assert "write:booking" in mapped["capabilities"]
