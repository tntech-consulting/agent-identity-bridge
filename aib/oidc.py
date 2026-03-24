"""
AIB — OIDC Binding.

Integrates AIB with enterprise Identity Providers via OpenID Connect.

This answers the #1 question from CISOs: "Does it work with our Active Directory?"
Answer: Yes. Configure your IdP once, and AIB auto-creates passports from OIDC tokens.

Supported flows:
1. TOKEN EXCHANGE: Agent presents an OIDC token from the enterprise IdP →
   AIB validates it → creates/returns an AIB passport with the agent's
   identity and permissions derived from OIDC claims.

2. CLIENT CREDENTIALS: Machine-to-machine flow for automated agent creation.
   The agent authenticates directly with the IdP using client_id/client_secret,
   gets an OIDC token, and exchanges it for an AIB passport.

3. CLAIM MAPPING: OIDC claims (roles, groups, scopes) map to AIB capabilities
   and protocol bindings. Configurable per IdP.

Supported IdPs:
- Microsoft Entra ID (Azure AD)
- Okta
- Auth0
- Keycloak
- Any OIDC-compliant provider

The enterprise doesn't need to manage a new identity system.
AIB plugs into what they already have.
"""

import json
import time
import hashlib
from dataclasses import dataclass, field
from typing import Optional, Any
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin

# For token validation
try:
    import jwt as pyjwt
    HAS_JWT = True
except ImportError:
    HAS_JWT = False

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


# ── IdP Configuration ─────────────────────────────────────────────

@dataclass
class OIDCProvider:
    """Configuration for an OIDC Identity Provider."""

    name: str                          # "entra", "okta", "auth0", "keycloak"
    issuer_url: str                    # https://login.microsoftonline.com/{tenant}/v2.0
    client_id: str                     # AIB's client_id registered in the IdP
    client_secret: Optional[str] = None  # For client_credentials flow

    # Discovery (auto-populated from .well-known/openid-configuration)
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    jwks_uri: str = ""
    userinfo_endpoint: str = ""

    # Claim mapping: OIDC claim → AIB field
    claim_mapping: dict = field(default_factory=lambda: {
        "sub": "agent_id",             # OIDC subject → passport agent identifier
        "name": "display_name",        # Display name
        "roles": "capabilities",       # Entra roles → AIB capabilities
        "groups": "capabilities",      # Okta groups → AIB capabilities
        "scope": "scopes",             # Scopes → protocol permissions
    })

    # Default protocol bindings for passports created via this IdP
    default_protocols: list[str] = field(default_factory=lambda: ["mcp", "a2a"])

    # Passport tier for OIDC-created passports
    default_tier: str = "session"      # session by default (4h, matching OIDC token lifetime)

    # Maximum passport TTL (clamped to OIDC token expiry)
    max_ttl_hours: int = 24

    # Audience validation
    allowed_audiences: list[str] = field(default_factory=list)

    # Metadata
    metadata: dict = field(default_factory=dict)


# Presets for common IdPs
ENTRA_PRESET = {
    "name": "entra",
    "claim_mapping": {
        "sub": "agent_id",
        "name": "display_name",
        "roles": "capabilities",       # App roles in Entra
        "wids": "admin_roles",         # Directory roles
        "tid": "tenant_id",
        "azp": "client_app",
    },
}

OKTA_PRESET = {
    "name": "okta",
    "claim_mapping": {
        "sub": "agent_id",
        "name": "display_name",
        "groups": "capabilities",      # Okta groups
        "scp": "scopes",              # Okta scopes
    },
}

AUTH0_PRESET = {
    "name": "auth0",
    "claim_mapping": {
        "sub": "agent_id",
        "name": "display_name",
        "permissions": "capabilities",  # Auth0 permissions
        "scope": "scopes",
    },
}

KEYCLOAK_PRESET = {
    "name": "keycloak",
    "claim_mapping": {
        "sub": "agent_id",
        "preferred_username": "display_name",
        "realm_access.roles": "capabilities",  # Keycloak realm roles
        "resource_access": "protocol_bindings",
    },
}


# ── OIDC Token Validator ──────────────────────────────────────────

@dataclass
class ValidatedToken:
    """Result of OIDC token validation."""
    valid: bool
    claims: dict = field(default_factory=dict)
    error: str = ""
    issuer: str = ""
    subject: str = ""
    audience: str = ""
    expires_at: Optional[datetime] = None


class OIDCTokenValidator:
    """
    Validates OIDC tokens from enterprise IdPs.

    In production, this:
    1. Fetches the IdP's JWKS (public keys) from jwks_uri
    2. Validates the JWT signature
    3. Checks issuer, audience, expiration
    4. Returns the validated claims

    For MVP/testing, supports a "trust" mode that decodes without
    signature verification (for local development only).
    """

    def __init__(self, provider: OIDCProvider):
        self.provider = provider
        self._jwks_cache: Optional[dict] = None
        self._jwks_fetched_at: float = 0
        self._jwks_ttl: int = 3600  # Re-fetch JWKS every hour

    def validate(self, token: str, verify_signature: bool = True) -> ValidatedToken:
        """
        Validate an OIDC token.

        Args:
            token: The JWT access token or id_token
            verify_signature: Set False only for local dev/testing

        Returns:
            ValidatedToken with claims if valid
        """
        if not HAS_JWT:
            return ValidatedToken(valid=False, error="PyJWT not installed. Run: pip install PyJWT")

        try:
            if verify_signature:
                # Production: verify with IdP's public keys
                jwks = self._get_jwks()
                if not jwks:
                    return ValidatedToken(valid=False, error=f"Cannot fetch JWKS from {self.provider.jwks_uri}")

                # Decode header to get kid
                header = pyjwt.get_unverified_header(token)
                kid = header.get("kid")

                # Find the matching key
                signing_key = None
                for key in jwks.get("keys", []):
                    if key.get("kid") == kid:
                        signing_key = key
                        break

                if not signing_key:
                    return ValidatedToken(valid=False, error=f"No matching key found for kid={kid}")

                # Build public key from JWK
                from jwt.algorithms import RSAAlgorithm
                public_key = RSAAlgorithm.from_jwk(signing_key)

                claims = pyjwt.decode(
                    token,
                    public_key,
                    algorithms=["RS256"],
                    audience=self.provider.allowed_audiences or None,
                    issuer=self.provider.issuer_url,
                    options={"verify_aud": bool(self.provider.allowed_audiences)},
                )
            else:
                # Dev mode: decode without verification
                claims = pyjwt.decode(
                    token,
                    options={
                        "verify_signature": False,
                        "verify_exp": True,
                        "verify_iss": False,
                        "verify_aud": False,
                    },
                )

            # Extract standard claims
            exp = claims.get("exp")
            expires_at = datetime.fromtimestamp(exp, tz=timezone.utc) if exp else None

            return ValidatedToken(
                valid=True,
                claims=claims,
                issuer=claims.get("iss", ""),
                subject=claims.get("sub", ""),
                audience=claims.get("aud", ""),
                expires_at=expires_at,
            )

        except pyjwt.ExpiredSignatureError:
            return ValidatedToken(valid=False, error="Token expired")
        except pyjwt.InvalidAudienceError:
            return ValidatedToken(valid=False, error="Invalid audience")
        except pyjwt.InvalidIssuerError:
            return ValidatedToken(valid=False, error="Invalid issuer")
        except pyjwt.DecodeError as e:
            return ValidatedToken(valid=False, error=f"Token decode error: {e}")
        except Exception as e:
            return ValidatedToken(valid=False, error=f"Validation error: {e}")

    def _get_jwks(self) -> Optional[dict]:
        """Fetch and cache the IdP's JWKS."""
        if not HAS_HTTPX:
            return None

        now = time.time()
        if self._jwks_cache and (now - self._jwks_fetched_at) < self._jwks_ttl:
            return self._jwks_cache

        try:
            jwks_uri = self.provider.jwks_uri
            if not jwks_uri:
                # Try discovery
                jwks_uri = self._discover_jwks_uri()
            if not jwks_uri:
                return None

            resp = httpx.get(jwks_uri, timeout=10)
            resp.raise_for_status()
            self._jwks_cache = resp.json()
            self._jwks_fetched_at = now
            return self._jwks_cache
        except Exception:
            return self._jwks_cache  # Return stale cache on error

    def _discover_jwks_uri(self) -> Optional[str]:
        """Auto-discover JWKS URI from .well-known/openid-configuration."""
        try:
            discovery_url = f"{self.provider.issuer_url.rstrip('/')}/.well-known/openid-configuration"
            resp = httpx.get(discovery_url, timeout=10)
            resp.raise_for_status()
            config = resp.json()
            self.provider.jwks_uri = config.get("jwks_uri", "")
            self.provider.token_endpoint = config.get("token_endpoint", "")
            self.provider.authorization_endpoint = config.get("authorization_endpoint", "")
            self.provider.userinfo_endpoint = config.get("userinfo_endpoint", "")
            return self.provider.jwks_uri
        except Exception:
            return None


# ── Claim Mapper ──────────────────────────────────────────────────

class ClaimMapper:
    """
    Maps OIDC claims to AIB passport fields.

    Examples:
        Entra "roles": ["Agent.Booking", "Agent.Search"]
        → AIB capabilities: ["booking", "search"]

        Okta "groups": ["mcp-agents", "a2a-agents"]
        → AIB protocols: ["mcp", "a2a"]

        Auth0 "permissions": ["read:calendar", "write:booking"]
        → AIB capabilities: ["read:calendar", "write:booking"]
    """

    def __init__(self, provider: OIDCProvider):
        self.provider = provider
        self.mapping = provider.claim_mapping

    def extract_agent_id(self, claims: dict) -> str:
        """Extract the agent identifier from OIDC claims."""
        claim_key = self.mapping.get("sub", "sub")
        return str(claims.get(claim_key, claims.get("sub", "unknown")))

    def extract_display_name(self, claims: dict) -> str:
        """Extract display name."""
        # Check common display name claims directly
        for key in ["name", "preferred_username", "display_name", "nickname"]:
            if key in claims and claims[key]:
                return str(claims[key])
        # Fallback to mapped keys
        for key, target in self.mapping.items():
            if target == "display_name" and key in claims and claims[key]:
                return str(claims[key])
        return self.extract_agent_id(claims)

    def extract_capabilities(self, claims: dict) -> list[str]:
        """
        Extract capabilities from roles/groups/permissions claims.

        Handles different IdP formats:
        - Entra: "roles": ["Agent.Booking"] → ["booking"]
        - Okta: "groups": ["booking-agents"] → ["booking"]
        - Auth0: "permissions": ["read:calendar"] → ["read:calendar"]
        """
        capabilities = []

        # Check each claim that maps to capabilities
        for claim_key, target in self.mapping.items():
            if target != "capabilities":
                continue
            value = claims.get(claim_key, [])
            if isinstance(value, str):
                value = value.split()
            if isinstance(value, list):
                for item in value:
                    # Normalize: "Agent.Booking" → "booking"
                    normalized = str(item).split(".")[-1].lower().strip()
                    if normalized and normalized not in capabilities:
                        capabilities.append(normalized)

        return capabilities or ["default"]

    def extract_protocols(self, claims: dict) -> list[str]:
        """
        Determine which protocols the agent should get based on claims.

        Uses group membership or explicit scope claims.
        """
        protocols = []

        # Check for explicit protocol claims
        scopes_key = None
        for claim_key, target in self.mapping.items():
            if target == "scopes":
                scopes_key = claim_key
                break

        if scopes_key and scopes_key in claims:
            scopes = claims[scopes_key]
            if isinstance(scopes, str):
                scopes = scopes.split()
            for scope in scopes:
                scope_lower = scope.lower()
                if "mcp" in scope_lower:
                    protocols.append("mcp")
                elif "a2a" in scope_lower:
                    protocols.append("a2a")
                elif "anp" in scope_lower:
                    protocols.append("anp")

        # Check group-based protocol assignment
        groups = claims.get("groups", [])
        if isinstance(groups, list):
            for group in groups:
                group_lower = str(group).lower()
                if "mcp" in group_lower and "mcp" not in protocols:
                    protocols.append("mcp")
                if "a2a" in group_lower and "a2a" not in protocols:
                    protocols.append("a2a")
                if "anp" in group_lower and "anp" not in protocols:
                    protocols.append("anp")

        return protocols or self.provider.default_protocols

    def map_to_passport_fields(self, claims: dict) -> dict:
        """
        Map all OIDC claims to AIB passport creation fields.

        Returns a dict ready to pass to PassportLifecycleManager.create_permanent()
        or create_session().
        """
        return {
            "agent_id": self.extract_agent_id(claims),
            "display_name": self.extract_display_name(claims),
            "capabilities": self.extract_capabilities(claims),
            "protocols": self.extract_protocols(claims),
            "oidc_issuer": claims.get("iss", ""),
            "oidc_subject": claims.get("sub", ""),
            "oidc_audience": claims.get("aud", ""),
            "oidc_expires": claims.get("exp", 0),
        }


# ── OIDC-to-AIB Bridge ───────────────────────────────────────────

class OIDCBridge:
    """
    The main integration point: exchange an OIDC token for an AIB passport.

    Usage:
        provider = OIDCProvider(
            name="entra",
            issuer_url="https://login.microsoftonline.com/{tenant}/v2.0",
            client_id="your-aib-app-id",
        )
        bridge = OIDCBridge(provider)

        # Agent presents its Entra token → gets an AIB passport
        result = bridge.exchange("eyJ...")
        if result.success:
            print(result.passport_id)
            print(result.capabilities)
    """

    def __init__(self, provider: OIDCProvider):
        self.provider = provider
        self.validator = OIDCTokenValidator(provider)
        self.mapper = ClaimMapper(provider)

    def exchange(
        self,
        oidc_token: str,
        verify_signature: bool = True,
        org_slug: Optional[str] = None,
        tier: str = "session",
        extra_metadata: Optional[dict] = None,
    ) -> "ExchangeResult":
        """
        Exchange an OIDC token for AIB passport creation fields.

        Steps:
        1. Validate the OIDC token (signature, expiry, issuer)
        2. Extract claims
        3. Map claims to AIB passport fields
        4. Return fields ready for passport creation

        The caller (gateway API) handles actual passport creation
        via PassportLifecycleManager.
        """
        # Step 1: Validate
        validated = self.validator.validate(oidc_token, verify_signature=verify_signature)
        if not validated.valid:
            return ExchangeResult(
                success=False,
                error=f"OIDC validation failed: {validated.error}",
            )

        # Step 2-3: Map claims
        mapped = self.mapper.map_to_passport_fields(validated.claims)

        # Determine org
        org = org_slug or self._derive_org(validated.claims)

        # Determine TTL (clamped to OIDC token expiry)
        ttl_seconds = None
        if validated.expires_at:
            remaining = (validated.expires_at - datetime.now(timezone.utc)).total_seconds()
            max_ttl = self.provider.max_ttl_hours * 3600
            ttl_seconds = min(remaining, max_ttl)
            if ttl_seconds <= 0:
                return ExchangeResult(
                    success=False,
                    error="OIDC token has expired or has insufficient remaining TTL",
                )

        # Build protocol bindings
        protocol_bindings = {}
        for proto in mapped["protocols"]:
            if proto == "mcp":
                protocol_bindings["mcp"] = {"auth_method": "oauth2", "oidc_source": self.provider.name}
            elif proto == "a2a":
                protocol_bindings["a2a"] = {"auth_method": "bearer", "oidc_source": self.provider.name}
            elif proto == "anp":
                protocol_bindings["anp"] = {"auth_method": "did-auth", "oidc_source": self.provider.name}

        return ExchangeResult(
            success=True,
            org=org,
            agent_id=mapped["agent_id"],
            display_name=mapped["display_name"],
            capabilities=mapped["capabilities"],
            protocols=mapped["protocols"],
            protocol_bindings=protocol_bindings,
            tier=tier,
            ttl_seconds=ttl_seconds,
            oidc_claims=validated.claims,
            oidc_issuer=validated.issuer,
            oidc_subject=validated.subject,
            metadata={
                **(extra_metadata or {}),
                "oidc_provider": self.provider.name,
                "oidc_issuer": validated.issuer,
                "oidc_subject": validated.subject,
                "created_by": "oidc_exchange",
            },
        )

    def _derive_org(self, claims: dict) -> str:
        """Derive org slug from OIDC claims."""
        # Try tenant ID (Entra)
        tid = claims.get("tid", "")
        if tid:
            return f"tenant-{tid[:8]}"

        # Try issuer domain
        iss = claims.get("iss", "")
        if iss:
            from urllib.parse import urlparse
            domain = urlparse(iss).hostname or ""
            parts = domain.split(".")
            if len(parts) >= 2:
                return parts[-2]

        return "default"


@dataclass
class ExchangeResult:
    """Result of an OIDC → AIB passport exchange."""
    success: bool
    error: str = ""

    # Passport creation fields (when success=True)
    org: str = ""
    agent_id: str = ""
    display_name: str = ""
    capabilities: list[str] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    protocol_bindings: dict = field(default_factory=dict)
    tier: str = "session"
    ttl_seconds: Optional[float] = None

    # OIDC context
    oidc_claims: dict = field(default_factory=dict)
    oidc_issuer: str = ""
    oidc_subject: str = ""
    metadata: dict = field(default_factory=dict)

    def __bool__(self):
        return self.success
