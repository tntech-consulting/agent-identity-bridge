"""Tests for discovery & federation — .well-known endpoints."""

import pytest
from aib.discovery import (
    AIBDiscoveryDocument, PublicAgentEntry, AgentRegistry,
    FederationTrust, FederationDocument, DiscoveryService,
)


# ═══════════════════════════════════════════════════════════════════
# Discovery Document
# ═══════════════════════════════════════════════════════════════════

class TestDiscoveryDocument:

    def test_defaults(self):
        doc = AIBDiscoveryDocument(
            issuer="urn:aib:org:acme",
            domain="acme.com",
            organization="Acme Corp",
        )
        d = doc.to_dict()
        assert d["aib_version"] == "1.3"
        assert d["issuer"] == "urn:aib:org:acme"
        assert d["domain"] == "acme.com"
        assert "mcp" in d["supported_protocols"]
        assert "a2a" in d["supported_protocols"]
        assert d["discovery"]["jwks_uri"] == "/.well-known/aib-keys.json"

    def test_features_listed(self):
        doc = AIBDiscoveryDocument(issuer="x", domain="x.com")
        d = doc.to_dict()
        assert "passport_lifecycle" in d["features"]
        assert "merkle_audit" in d["features"]
        assert "gdpr_compliance" in d["features"]
        assert "protocol_migration" in d["features"]

    def test_security_section(self):
        doc = AIBDiscoveryDocument(issuer="x", domain="x.com", multi_sig_policy="2-of-3")
        d = doc.to_dict()
        assert d["security"]["signing_algorithms"] == ["RS256"]
        assert d["security"]["key_rotation_days"] == 90
        assert d["security"]["multi_sig_policy"] == "2-of-3"
        assert "permanent" in d["security"]["passport_tiers"]

    def test_with_oidc_providers(self):
        doc = AIBDiscoveryDocument(
            issuer="x", domain="x.com",
            oidc_providers=["entra", "okta"],
        )
        d = doc.to_dict()
        assert d["oidc_providers"] == ["entra", "okta"]

    def test_without_oidc(self):
        doc = AIBDiscoveryDocument(issuer="x", domain="x.com")
        d = doc.to_dict()
        assert "oidc_providers" not in d

    def test_published_at(self):
        doc = AIBDiscoveryDocument(issuer="x", domain="x.com")
        d = doc.to_dict()
        assert "published_at" in d
        assert len(d["published_at"]) > 10  # ISO timestamp


# ═══════════════════════════════════════════════════════════════════
# Agent Registry
# ═══════════════════════════════════════════════════════════════════

class TestAgentRegistry:

    @pytest.fixture
    def registry(self):
        r = AgentRegistry(issuer="urn:aib:org:acme")
        r.add(PublicAgentEntry(
            passport_id="urn:aib:agent:acme:booking",
            display_name="Booking Agent",
            capabilities=["booking", "scheduling"],
            protocols=["mcp", "a2a"],
        ))
        r.add(PublicAgentEntry(
            passport_id="urn:aib:agent:acme:support",
            display_name="Support Agent",
            capabilities=["support", "faq"],
            protocols=["a2a"],
        ))
        return r

    def test_add_and_list(self, registry):
        d = registry.to_dict()
        assert d["total_agents"] == 2
        assert len(d["agents"]) == 2

    def test_get(self, registry):
        agent = registry.get("urn:aib:agent:acme:booking")
        assert agent is not None
        assert agent.display_name == "Booking Agent"

    def test_get_nonexistent(self, registry):
        assert registry.get("urn:aib:agent:acme:ghost") is None

    def test_remove(self, registry):
        assert registry.remove("urn:aib:agent:acme:booking") is True
        assert registry.get("urn:aib:agent:acme:booking") is None
        assert len(registry.agents) == 1

    def test_remove_nonexistent(self, registry):
        assert registry.remove("urn:aib:agent:acme:ghost") is False

    def test_search_by_capability(self, registry):
        results = registry.search(capability="booking")
        assert len(results) == 1
        assert results[0].passport_id == "urn:aib:agent:acme:booking"

    def test_search_by_protocol(self, registry):
        results = registry.search(protocol="a2a")
        assert len(results) == 2

        results = registry.search(protocol="mcp")
        assert len(results) == 1

    def test_search_no_match(self, registry):
        results = registry.search(capability="finance")
        assert len(results) == 0

    def test_private_agents_hidden(self, registry):
        registry.add(PublicAgentEntry(
            passport_id="urn:aib:agent:acme:internal",
            display_name="Internal Agent",
            capabilities=["admin"],
            protocols=["mcp"],
            public=False,
        ))
        d = registry.to_dict()
        assert d["total_agents"] == 2  # Internal not counted

        results = registry.search(capability="admin")
        assert len(results) == 0  # Internal not searchable

    def test_replace_on_duplicate_add(self, registry):
        registry.add(PublicAgentEntry(
            passport_id="urn:aib:agent:acme:booking",
            display_name="Booking Agent v2",
            capabilities=["booking", "scheduling", "cancellation"],
            protocols=["mcp", "a2a", "anp"],
        ))
        agent = registry.get("urn:aib:agent:acme:booking")
        assert agent.display_name == "Booking Agent v2"
        assert "cancellation" in agent.capabilities
        assert len(registry.agents) == 2  # No duplicate

    def test_agent_entry_to_dict(self):
        a = PublicAgentEntry(
            passport_id="urn:aib:agent:acme:bot",
            display_name="Bot",
            capabilities=["search"],
            protocols=["mcp"],
            rate_limit="1000/hour",
        )
        d = a.to_dict()
        assert d["rate_limit"] == "1000/hour"
        assert d["status"] == "active"


# ═══════════════════════════════════════════════════════════════════
# Federation
# ═══════════════════════════════════════════════════════════════════

class TestFederation:

    @pytest.fixture
    def federation(self):
        f = FederationDocument(
            issuer="urn:aib:org:acme",
            domain="acme.com",
        )
        f.add_trust(FederationTrust(
            domain="partner.com",
            issuer="urn:aib:org:partner",
            jwks_uri="https://partner.com/.well-known/aib-keys.json",
            trust_level="verify",
            protocols=["mcp", "a2a"],
        ))
        return f

    def test_is_trusted(self, federation):
        trusted, trust = federation.is_trusted("urn:aib:org:partner")
        assert trusted is True
        assert trust.domain == "partner.com"

    def test_not_trusted(self, federation):
        trusted, trust = federation.is_trusted("urn:aib:org:stranger")
        assert trusted is False
        assert trust is None

    def test_open_policy_trusts_everyone(self):
        f = FederationDocument(
            issuer="urn:aib:org:acme",
            domain="acme.com",
            federation_policy="open",
        )
        trusted, _ = f.is_trusted("urn:aib:org:anyone")
        assert trusted is True

    def test_get_jwks_uri(self, federation):
        uri = federation.get_jwks_uri("urn:aib:org:partner")
        assert uri == "https://partner.com/.well-known/aib-keys.json"

    def test_get_jwks_uri_unknown(self, federation):
        assert federation.get_jwks_uri("urn:aib:org:unknown") is None

    def test_remove_trust(self, federation):
        assert federation.remove_trust("partner.com") is True
        trusted, _ = federation.is_trusted("urn:aib:org:partner")
        assert trusted is False

    def test_remove_trust_nonexistent(self, federation):
        assert federation.remove_trust("ghost.com") is False

    def test_add_trust_replaces(self, federation):
        federation.add_trust(FederationTrust(
            domain="partner.com",
            issuer="urn:aib:org:partner",
            jwks_uri="https://partner.com/.well-known/aib-keys-v2.json",
            trust_level="full",
        ))
        uri = federation.get_jwks_uri("urn:aib:org:partner")
        assert "v2" in uri
        assert len(federation.trusted_issuers) == 1  # No duplicate

    def test_to_dict(self, federation):
        d = federation.to_dict()
        assert d["issuer"] == "urn:aib:org:acme"
        assert d["federation_policy"] == "explicit"
        assert d["total_trusted"] == 1
        assert d["trusted_issuers"][0]["domain"] == "partner.com"


# ═══════════════════════════════════════════════════════════════════
# Discovery Service (wires everything together)
# ═══════════════════════════════════════════════════════════════════

class TestDiscoveryService:

    @pytest.fixture
    def svc(self):
        return DiscoveryService(
            domain="acme.com",
            org_slug="acme",
            org_name="Acme Corp",
            gateway_url="https://aib.acme.com",
            contact="admin@acme.com",
            documentation="https://docs.acme.com/aib",
        )

    def test_get_discovery(self, svc):
        d = svc.get_discovery()
        assert d["domain"] == "acme.com"
        assert d["issuer"] == "urn:aib:org:acme"
        assert d["organization"] == "Acme Corp"
        assert d["gateway_url"] == "https://aib.acme.com"

    def test_get_jwks_no_manager(self, svc):
        d = svc.get_jwks()
        assert d["keys"] == []

    def test_get_jwks_with_manager(self, svc):
        class MockKeyManager:
            def jwks(self):
                return {"keys": [{"kty": "RSA", "kid": "test-1"}]}

        d = svc.get_jwks(MockKeyManager())
        assert len(d["keys"]) == 1
        assert d["keys"][0]["kid"] == "test-1"

    def test_register_agent(self, svc):
        svc.register_agent(PublicAgentEntry(
            passport_id="urn:aib:agent:acme:booking",
            display_name="Booking Agent",
            capabilities=["booking"],
            protocols=["mcp"],
        ))
        d = svc.get_agents()
        assert d["total_agents"] == 1

    def test_unregister_agent(self, svc):
        svc.register_agent(PublicAgentEntry(
            passport_id="urn:aib:agent:acme:booking",
            display_name="Booking",
            capabilities=["booking"],
            protocols=["mcp"],
        ))
        assert svc.unregister_agent("urn:aib:agent:acme:booking") is True
        assert svc.get_agents()["total_agents"] == 0

    def test_search_agents(self, svc):
        svc.register_agent(PublicAgentEntry(
            passport_id="urn:aib:agent:acme:a",
            display_name="A", capabilities=["booking"], protocols=["mcp"],
        ))
        svc.register_agent(PublicAgentEntry(
            passport_id="urn:aib:agent:acme:b",
            display_name="B", capabilities=["support"], protocols=["a2a"],
        ))
        results = svc.search_agents(protocol="mcp")
        assert len(results) == 1

    def test_add_federation_trust(self, svc):
        svc.add_federation_trust(FederationTrust(
            domain="partner.com",
            issuer="urn:aib:org:partner",
            jwks_uri="https://partner.com/.well-known/aib-keys.json",
        ))
        trusted, _ = svc.is_issuer_trusted("urn:aib:org:partner")
        assert trusted is True

    def test_get_federation(self, svc):
        svc.add_federation_trust(FederationTrust(
            domain="partner.com",
            issuer="urn:aib:org:partner",
            jwks_uri="https://partner.com/.well-known/aib-keys.json",
        ))
        d = svc.get_federation()
        assert d["total_trusted"] == 1

    def test_get_all_documents(self, svc):
        docs = svc.get_all_documents()
        assert "aib.json" in docs
        assert "aib-keys.json" in docs
        assert "aib-agents.json" in docs
        assert "aib-federation.json" in docs


# ═══════════════════════════════════════════════════════════════════
# End-to-End Federation Scenario
# ═══════════════════════════════════════════════════════════════════

class TestFederationScenario:

    def test_cross_org_federation(self):
        """
        Simulate two organizations federating:
        1. Acme publishes agents and discovery docs
        2. Partner adds Acme as trusted issuer
        3. Partner can verify Acme's passports via JWKS
        4. Partner searches Acme's public agents
        """
        # Acme setup
        acme = DiscoveryService(
            domain="acme.com", org_slug="acme", org_name="Acme Corp",
            gateway_url="https://aib.acme.com",
        )
        acme.register_agent(PublicAgentEntry(
            passport_id="urn:aib:agent:acme:booking",
            display_name="Booking Agent",
            capabilities=["booking", "scheduling"],
            protocols=["mcp", "a2a"],
        ))
        acme.register_agent(PublicAgentEntry(
            passport_id="urn:aib:agent:acme:analytics",
            display_name="Analytics Agent",
            capabilities=["analytics", "reporting"],
            protocols=["mcp"],
        ))

        # Partner setup
        partner = DiscoveryService(
            domain="partner.com", org_slug="partner", org_name="Partner Inc",
            gateway_url="https://aib.partner.com",
        )

        # Partner trusts Acme
        partner.add_federation_trust(FederationTrust(
            domain="acme.com",
            issuer="urn:aib:org:acme",
            jwks_uri="https://acme.com/.well-known/aib-keys.json",
            trust_level="verify",
            protocols=["mcp", "a2a"],
        ))

        # Verify trust
        trusted, trust = partner.is_issuer_trusted("urn:aib:org:acme")
        assert trusted is True
        assert trust.trust_level == "verify"

        # Get Acme's JWKS URI for verification
        jwks_uri = partner.get_jwks_uri_for_issuer("urn:aib:org:acme")
        assert jwks_uri == "https://acme.com/.well-known/aib-keys.json"

        # Acme's public agent registry
        acme_agents = acme.get_agents()
        assert acme_agents["total_agents"] == 2

        # Search Acme's agents by capability
        booking_agents = acme.search_agents(capability="booking")
        assert len(booking_agents) == 1
        assert booking_agents[0]["passport_id"] == "urn:aib:agent:acme:booking"

        # Search by protocol
        mcp_agents = acme.search_agents(protocol="mcp")
        assert len(mcp_agents) == 2

        # Acme's discovery document
        acme_discovery = acme.get_discovery()
        assert acme_discovery["domain"] == "acme.com"
        assert "mcp" in acme_discovery["supported_protocols"]

        # Partner's federation document
        partner_fed = partner.get_federation()
        assert partner_fed["total_trusted"] == 1
