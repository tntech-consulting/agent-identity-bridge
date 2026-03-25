"""
AIB — Discovery & Federation.

Production-grade .well-known endpoints for cross-organization federation.

Three documents:
1. /.well-known/aib.json         — Organization discovery (who we are, what we support)
2. /.well-known/aib-keys.json    — JWKS (public keys for passport verification)
3. /.well-known/aib-agents.json  — Agent registry (public capabilities of our agents)

Federation flow:
  1. Enterprise B wants to verify a passport signed by Enterprise A
  2. B resolves A's domain → fetches https://a.com/.well-known/aib-keys.json
  3. B verifies the passport signature against A's JWKS
  4. B fetches https://a.com/.well-known/aib.json to check supported protocols
  5. B fetches https://a.com/.well-known/aib-agents.json (optional) for agent details
  → No central authority. Trust is cryptographic.

This module is the foundation for the OAuth-for-agents vision.
"""

import os
import json
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional, Any


# ═══════════════════════════════════════════════════════════════════
# 1. ORGANIZATION DISCOVERY — /.well-known/aib.json
# ═══════════════════════════════════════════════════════════════════

@dataclass
class AIBDiscoveryDocument:
    """
    The main discovery document for an AIB-enabled organization.

    Published at: https://{domain}/.well-known/aib.json

    Analogous to:
    - OpenID Connect Discovery (/.well-known/openid-configuration)
    - MCP Server Card (/.well-known/mcp.json)
    - A2A Agent Card (/.well-known/agent.json)

    But for the identity bridge layer, not a single protocol.
    """
    # Required fields
    aib_version: str = "1.3"
    issuer: str = ""                     # urn:aib:org:{slug}
    domain: str = ""                     # The domain publishing this document
    organization: str = ""               # Human-readable org name

    # Protocol support
    supported_protocols: list[str] = field(default_factory=lambda: ["mcp", "a2a", "anp", "ag-ui"])
    protocol_versions: dict[str, str] = field(default_factory=dict)  # {"mcp": "2.1", "a2a": "1.0"}

    # Endpoints (relative to domain)
    gateway_url: str = ""                # Full URL to AIB gateway
    passports_endpoint: str = "/passports"
    translate_endpoint: str = "/translate"
    proxy_endpoint: str = "/gateway/proxy"
    audit_endpoint: str = "/audit"
    revocation_endpoint: str = "/revoke"

    # Discovery URLs (absolute, relative to domain)
    jwks_uri: str = "/.well-known/aib-keys.json"
    agents_uri: str = "/.well-known/aib-agents.json"
    federation_uri: str = "/.well-known/aib-federation.json"

    # Capabilities
    capabilities: list[str] = field(default_factory=list)
    features: list[str] = field(default_factory=lambda: [
        "passport_lifecycle",
        "credential_translation",
        "action_receipts",
        "merkle_audit",
        "multi_signature",
        "auto_key_rotation",
        "gdpr_compliance",
        "protocol_migration",
        "oidc_binding",
        "plugin_system",
    ])

    # Security
    signing_algorithms: list[str] = field(default_factory=lambda: ["RS256"])
    key_rotation_days: int = 90
    multi_sig_policy: Optional[str] = None  # e.g. "2-of-3"

    # Passport tiers
    passport_tiers: list[str] = field(default_factory=lambda: [
        "permanent", "session", "ephemeral"
    ])

    # OIDC providers (for federation)
    oidc_providers: list[str] = field(default_factory=list)  # ["entra", "okta"]

    # Contact
    contact: str = ""
    documentation: str = ""

    # Metadata
    published_at: str = ""

    def to_dict(self) -> dict:
        d = {
            "aib_version": self.aib_version,
            "issuer": self.issuer,
            "domain": self.domain,
            "organization": self.organization,
            "supported_protocols": self.supported_protocols,
            "gateway_url": self.gateway_url,
            "endpoints": {
                "passports": self.passports_endpoint,
                "translate": self.translate_endpoint,
                "proxy": self.proxy_endpoint,
                "audit": self.audit_endpoint,
                "revocation": self.revocation_endpoint,
            },
            "discovery": {
                "jwks_uri": self.jwks_uri,
                "agents_uri": self.agents_uri,
                "federation_uri": self.federation_uri,
            },
            "features": self.features,
            "security": {
                "signing_algorithms": self.signing_algorithms,
                "key_rotation_days": self.key_rotation_days,
                "multi_sig_policy": self.multi_sig_policy,
                "passport_tiers": self.passport_tiers,
            },
            "documentation": self.documentation,
            "contact": self.contact,
            "published_at": self.published_at or datetime.now(timezone.utc).isoformat(),
        }
        if self.protocol_versions:
            d["protocol_versions"] = self.protocol_versions
        if self.oidc_providers:
            d["oidc_providers"] = self.oidc_providers
        if self.capabilities:
            d["capabilities"] = self.capabilities
        return d


# ═══════════════════════════════════════════════════════════════════
# 2. AGENT REGISTRY — /.well-known/aib-agents.json
# ═══════════════════════════════════════════════════════════════════

@dataclass
class PublicAgentEntry:
    """
    A public entry in an organization's agent registry.

    This is what other organizations see when they look up
    your agents. It does NOT expose credentials or internal
    details — only capabilities and protocols.
    """
    passport_id: str
    display_name: str
    description: str = ""
    capabilities: list[str] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    status: str = "active"               # active, deprecated, retired
    tier: str = "permanent"
    public: bool = True                  # False = not listed in registry
    contact: str = ""
    terms_of_service: str = ""
    rate_limit: Optional[str] = None     # e.g. "1000/hour"

    def to_dict(self) -> dict:
        d = {
            "passport_id": self.passport_id,
            "display_name": self.display_name,
            "capabilities": self.capabilities,
            "protocols": self.protocols,
            "status": self.status,
            "tier": self.tier,
        }
        if self.description:
            d["description"] = self.description
        if self.contact:
            d["contact"] = self.contact
        if self.terms_of_service:
            d["terms_of_service"] = self.terms_of_service
        if self.rate_limit:
            d["rate_limit"] = self.rate_limit
        return d


@dataclass
class AgentRegistry:
    """
    The public agent registry for an organization.

    Published at: https://{domain}/.well-known/aib-agents.json
    """
    issuer: str
    agents: list[PublicAgentEntry] = field(default_factory=list)
    updated_at: str = ""

    def add(self, agent: PublicAgentEntry):
        # Replace if same passport_id exists
        self.agents = [a for a in self.agents if a.passport_id != agent.passport_id]
        self.agents.append(agent)
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def remove(self, passport_id: str) -> bool:
        before = len(self.agents)
        self.agents = [a for a in self.agents if a.passport_id != passport_id]
        if len(self.agents) < before:
            self.updated_at = datetime.now(timezone.utc).isoformat()
            return True
        return False

    def get(self, passport_id: str) -> Optional[PublicAgentEntry]:
        for a in self.agents:
            if a.passport_id == passport_id:
                return a
        return None

    def search(
        self,
        capability: Optional[str] = None,
        protocol: Optional[str] = None,
        status: str = "active",
    ) -> list[PublicAgentEntry]:
        """Search agents by capability, protocol, or status."""
        results = []
        for a in self.agents:
            if not a.public:
                continue
            if status and a.status != status:
                continue
            if capability and capability not in a.capabilities:
                continue
            if protocol and protocol not in a.protocols:
                continue
            results.append(a)
        return results

    def to_dict(self) -> dict:
        return {
            "issuer": self.issuer,
            "agents": [a.to_dict() for a in self.agents if a.public],
            "total_agents": len([a for a in self.agents if a.public]),
            "updated_at": self.updated_at or datetime.now(timezone.utc).isoformat(),
        }


# ═══════════════════════════════════════════════════════════════════
# 3. FEDERATION — /.well-known/aib-federation.json
# ═══════════════════════════════════════════════════════════════════

@dataclass
class FederationTrust:
    """
    A trust relationship with another AIB-enabled organization.

    Trust is directional: "we trust org X to sign passports"
    means we will verify passports signed by X's keys.
    """
    domain: str
    issuer: str                          # urn:aib:org:{slug}
    jwks_uri: str                        # Where to fetch their public keys
    trusted_since: str = ""
    trust_level: str = "verify"          # verify, delegate, full
    protocols: list[str] = field(default_factory=list)  # Protocols we accept from them
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "issuer": self.issuer,
            "jwks_uri": self.jwks_uri,
            "trusted_since": self.trusted_since,
            "trust_level": self.trust_level,
            "protocols": self.protocols,
        }


@dataclass
class FederationDocument:
    """
    Federation configuration for cross-organization trust.

    Published at: https://{domain}/.well-known/aib-federation.json
    """
    issuer: str
    domain: str
    trusted_issuers: list[FederationTrust] = field(default_factory=list)
    federation_policy: str = "explicit"  # explicit (allowlist) or open
    updated_at: str = ""

    def add_trust(self, trust: FederationTrust):
        self.trusted_issuers = [
            t for t in self.trusted_issuers if t.domain != trust.domain
        ]
        self.trusted_issuers.append(trust)
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def remove_trust(self, domain: str) -> bool:
        before = len(self.trusted_issuers)
        self.trusted_issuers = [
            t for t in self.trusted_issuers if t.domain != domain
        ]
        if len(self.trusted_issuers) < before:
            self.updated_at = datetime.now(timezone.utc).isoformat()
            return True
        return False

    def is_trusted(self, issuer: str) -> tuple[bool, Optional[FederationTrust]]:
        """Check if an issuer is trusted."""
        if self.federation_policy == "open":
            return True, None
        for t in self.trusted_issuers:
            if t.issuer == issuer:
                return True, t
        return False, None

    def get_jwks_uri(self, issuer: str) -> Optional[str]:
        """Get the JWKS URI for a trusted issuer."""
        for t in self.trusted_issuers:
            if t.issuer == issuer:
                return t.jwks_uri
        return None

    def to_dict(self) -> dict:
        return {
            "issuer": self.issuer,
            "domain": self.domain,
            "federation_policy": self.federation_policy,
            "trusted_issuers": [t.to_dict() for t in self.trusted_issuers],
            "total_trusted": len(self.trusted_issuers),
            "updated_at": self.updated_at or datetime.now(timezone.utc).isoformat(),
        }


# ═══════════════════════════════════════════════════════════════════
# 4. DISCOVERY SERVICE — Wires everything together
# ═══════════════════════════════════════════════════════════════════

class DiscoveryService:
    """
    Manages all .well-known documents for an AIB gateway.

    Usage:
        svc = DiscoveryService(
            domain="mycompany.com",
            org_slug="mycompany",
            org_name="My Company Inc.",
            gateway_url="https://aib.mycompany.com",
        )

        # Get discovery docs (serve at .well-known/ endpoints)
        aib_json = svc.get_discovery()
        keys_json = svc.get_jwks(key_manager)
        agents_json = svc.get_agents()
        federation_json = svc.get_federation()

        # Register a public agent
        svc.register_agent(PublicAgentEntry(
            passport_id="urn:aib:agent:mycompany:booking",
            display_name="Booking Agent",
            capabilities=["booking", "scheduling"],
            protocols=["mcp", "a2a"],
        ))

        # Add a federation trust
        svc.add_federation_trust(FederationTrust(
            domain="partner.com",
            issuer="urn:aib:org:partner",
            jwks_uri="https://partner.com/.well-known/aib-keys.json",
        ))

        # Verify a foreign passport
        trusted, trust = svc.is_issuer_trusted("urn:aib:org:partner")
    """

    def __init__(
        self,
        domain: str,
        org_slug: str,
        org_name: str = "",
        gateway_url: str = "",
        contact: str = "",
        documentation: str = "",
        supported_protocols: Optional[list[str]] = None,
    ):
        self.domain = domain
        self.org_slug = org_slug
        self.issuer = f"urn:aib:org:{org_slug}"

        self._discovery = AIBDiscoveryDocument(
            issuer=self.issuer,
            domain=domain,
            organization=org_name or org_slug,
            gateway_url=gateway_url or f"https://{domain}",
            contact=contact,
            documentation=documentation,
            supported_protocols=supported_protocols or ["mcp", "a2a", "anp", "ag-ui"],
        )

        self._registry = AgentRegistry(issuer=self.issuer)

        self._federation = FederationDocument(
            issuer=self.issuer,
            domain=domain,
        )

    # ── Discovery document ────────────────────────────────────

    def get_discovery(self) -> dict:
        """Returns /.well-known/aib.json content."""
        return self._discovery.to_dict()

    # ── JWKS ──────────────────────────────────────────────────

    def get_jwks(self, key_manager=None) -> dict:
        """
        Returns /.well-known/aib-keys.json content.

        If key_manager is provided, returns real RSA public keys.
        Otherwise returns a placeholder.
        """
        if key_manager and hasattr(key_manager, 'jwks'):
            return key_manager.jwks()
        return {
            "keys": [],
            "note": "No key manager configured",
        }

    # ── Agent registry ────────────────────────────────────────

    def register_agent(self, agent: PublicAgentEntry):
        self._registry.add(agent)

    def unregister_agent(self, passport_id: str) -> bool:
        return self._registry.remove(passport_id)

    def get_agents(self) -> dict:
        """Returns /.well-known/aib-agents.json content."""
        return self._registry.to_dict()

    def search_agents(self, **kwargs) -> list[dict]:
        return [a.to_dict() for a in self._registry.search(**kwargs)]

    # ── Federation ────────────────────────────────────────────

    def add_federation_trust(self, trust: FederationTrust):
        if not trust.trusted_since:
            trust.trusted_since = datetime.now(timezone.utc).isoformat()
        self._federation.add_trust(trust)

    def remove_federation_trust(self, domain: str) -> bool:
        return self._federation.remove_trust(domain)

    def is_issuer_trusted(self, issuer: str) -> tuple[bool, Optional[FederationTrust]]:
        return self._federation.is_trusted(issuer)

    def get_jwks_uri_for_issuer(self, issuer: str) -> Optional[str]:
        return self._federation.get_jwks_uri(issuer)

    def get_federation(self) -> dict:
        """Returns /.well-known/aib-federation.json content."""
        return self._federation.to_dict()

    # ── All documents ─────────────────────────────────────────

    def get_all_documents(self, key_manager=None) -> dict:
        """Returns all .well-known documents in one call (for debugging)."""
        return {
            "aib.json": self.get_discovery(),
            "aib-keys.json": self.get_jwks(key_manager),
            "aib-agents.json": self.get_agents(),
            "aib-federation.json": self.get_federation(),
        }
