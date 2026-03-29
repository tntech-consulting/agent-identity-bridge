"""
AIB - Agent Identity Bridge
translator.py — Credential Translator between protocol identity formats.

Converts between:
  - A2A Agent Card (Google) ↔ MCP Server Card (Anthropic)
  - Agent Card / Server Card → DID Document (W3C)
  - DID Document → Agent Card

This is the core interoperability engine of AIB.
"""

import json
from datetime import datetime, timezone
from typing import Optional


# Base58btc alphabet (Bitcoin variant) for W3C DID publicKeyMultibase encoding
_B58_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def _base58btc_encode(data: bytes) -> str:
    """Encode bytes to base58btc string (used for W3C DID publicKeyMultibase)."""
    n = int.from_bytes(data, 'big')
    result = []
    while n > 0:
        n, r = divmod(n, 58)
        result.append(_B58_ALPHABET[r:r+1])
    # Handle leading zero bytes
    for byte in data:
        if byte == 0:
            result.append(b'1')
        else:
            break
    return b''.join(reversed(result)).decode('ascii')


def _base58btc_decode(s: str) -> bytes:
    """Decode base58btc string to bytes."""
    n = 0
    for char in s.encode('ascii'):
        n = n * 58 + _B58_ALPHABET.index(char)
    # Count leading '1's (zero bytes)
    leading_zeros = 0
    for char in s.encode('ascii'):
        if char == ord('1'):
            leading_zeros += 1
        else:
            break
    # Convert to bytes
    byte_length = (n.bit_length() + 7) // 8
    result = n.to_bytes(byte_length, 'big') if byte_length > 0 else b''
    return b'\x00' * leading_zeros + result


# ── did:key utilities ─────────────────────────────────────────
# Ed25519 multicodec prefix: 0xed01
_ED25519_MULTICODEC = b'\xed\x01'


def public_key_to_did_key(public_key_hex: str) -> str:
    """
    Convert an Ed25519 public key (hex) to a did:key identifier.

    Format: did:key:z6Mk... (z + base58btc(0xed01 + 32 bytes raw key))

    Args:
        public_key_hex: 64-char hex string (32 bytes Ed25519 public key)

    Returns:
        did:key string, e.g. "did:key:z6MkhmjtYcAiNcBH6siwrMfEGxAytkMMEa48QjPhEEgcn2AM"

    Raises:
        ValueError: if hex string is invalid or wrong length
    """
    if not public_key_hex or len(public_key_hex) < 64:
        raise ValueError(f"Ed25519 public key must be 64 hex chars (32 bytes), got {len(public_key_hex or '')}")
    raw_bytes = bytes.fromhex(public_key_hex[:64])
    multicodec_bytes = _ED25519_MULTICODEC + raw_bytes
    multibase_key = "z" + _base58btc_encode(multicodec_bytes)
    return f"did:key:{multibase_key}"


def did_key_to_public_key_hex(did_key: str) -> str:
    """
    Extract the Ed25519 public key (hex) from a did:key identifier.

    Args:
        did_key: did:key string, e.g. "did:key:z6MkhmjtYcAiNcBH6siwrMfEGxAytkMMEa48QjPhEEgcn2AM"

    Returns:
        64-char hex string (32 bytes Ed25519 public key)

    Raises:
        ValueError: if did:key is invalid or not Ed25519
    """
    if not did_key.startswith("did:key:z"):
        raise ValueError(f"Invalid did:key format: must start with 'did:key:z', got '{did_key[:20]}'")
    multibase_str = did_key[8:]  # strip "did:key:"
    b58_str = multibase_str[1:]  # strip "z" (multibase prefix)
    decoded = _base58btc_decode(b58_str)
    if len(decoded) < 2 or decoded[0:2] != _ED25519_MULTICODEC:
        raise ValueError(f"Not an Ed25519 did:key (expected multicodec 0xed01, got {decoded[:2].hex()})")
    raw_key = decoded[2:]
    if len(raw_key) != 32:
        raise ValueError(f"Ed25519 key must be 32 bytes, got {len(raw_key)}")
    return raw_key.hex()


def did_key_to_did_document(did_key: str) -> dict:
    """
    Generate a minimal W3C DID Document from a did:key identifier.

    did:key is self-resolving: the DID Document is derived entirely
    from the key material encoded in the identifier itself.
    No network resolution needed.

    Args:
        did_key: did:key string

    Returns:
        W3C DID v1.1 compliant DID Document
    """
    public_key_hex = did_key_to_public_key_hex(did_key)
    raw_bytes = bytes.fromhex(public_key_hex)
    multicodec_bytes = _ED25519_MULTICODEC + raw_bytes
    multibase_key = "z" + _base58btc_encode(multicodec_bytes)

    key_id = f"{did_key}#{did_key.split(':')[2]}"

    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": did_key,
        "verificationMethod": [
            {
                "id": key_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did_key,
                "publicKeyMultibase": multibase_key,
            }
        ],
        "authentication": [key_id],
        "assertionMethod": [key_id],
    }


class CredentialTranslator:
    """
    Translates identity/capability documents between AI protocols.

    Each protocol has its own format for describing an agent:
    - MCP: Server Card (proposed .well-known/mcp.json)
    - A2A: Agent Card (.well-known/agent.json)
    - ANP: DID Document (did:web resolution)

    This translator maps fields between them so an agent registered
    in one protocol can be discovered in another.
    """

    # ── A2A Agent Card → MCP Server Card ──────────────────────────

    @staticmethod
    def a2a_to_mcp(agent_card: dict) -> dict:
        """
        Convert an A2A Agent Card to an MCP Server Card.

        A2A Agent Card structure:
          { name, description, url, version, skills: [{id, name, description}],
            authentication: {schemes: [...]}, capabilities: {streaming, pushNotifications} }

        MCP Server Card structure (proposed):
          { name, description, server_url, version, tools: [{name, description, inputSchema}],
            auth: {type, ...}, transport: "streamable-http" }
        """
        tools = []
        for skill in agent_card.get("skills", []):
            tools.append({
                "name": skill.get("id", skill.get("name", "")).replace(" ", "_").lower(),
                "description": skill.get("description", skill.get("name", "")),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "task_description": {
                            "type": "string",
                            "description": f"Description of the task for {skill.get('name', 'this skill')}"
                        }
                    },
                    "required": ["task_description"]
                }
            })

        # Map A2A auth schemes to MCP auth
        auth = {"type": "none"}
        a2a_auth = agent_card.get("authentication", {})
        schemes = a2a_auth.get("schemes", [])
        if schemes:
            first_scheme = schemes[0] if isinstance(schemes[0], str) else schemes[0].get("scheme", "bearer")
            if "oauth" in first_scheme.lower():
                auth = {"type": "oauth2", "flows": a2a_auth.get("flows", {})}
            elif "bearer" in first_scheme.lower():
                auth = {"type": "bearer"}
            elif "apikey" in first_scheme.lower() or "api_key" in first_scheme.lower():
                auth = {"type": "api_key", "header": "Authorization"}

        mcp_card = {
            "_aib_source": "a2a",
            "_aib_translated_at": datetime.now(timezone.utc).isoformat(),
            "name": agent_card.get("name", "Unknown Agent"),
            "description": agent_card.get("description", ""),
            "server_url": agent_card.get("url", ""),
            "version": agent_card.get("version", "1.0.0"),
            "tools": tools,
            "auth": auth,
            "transport": "streamable-http",
        }

        # Preserve A2A capabilities as MCP metadata
        caps = agent_card.get("capabilities", {})
        if caps:
            mcp_card["metadata"] = {
                "a2a_streaming": str(caps.get("streaming", False)).lower(),
                "a2a_push_notifications": str(caps.get("pushNotifications", False)).lower(),
            }

        return mcp_card

    # ── MCP Server Card → A2A Agent Card ──────────────────────────

    @staticmethod
    def mcp_to_a2a(server_card: dict) -> dict:
        """
        Convert an MCP Server Card to an A2A Agent Card.

        Inverse of a2a_to_mcp. Maps tools → skills, server_url → url.
        """
        skills = []
        for tool in server_card.get("tools", []):
            skills.append({
                "id": tool.get("name", "unknown"),
                "name": tool.get("name", "Unknown").replace("_", " ").title(),
                "description": tool.get("description", ""),
            })

        # Map MCP auth to A2A authentication
        auth_config = server_card.get("auth", {})
        auth_type = auth_config.get("type", "none")
        authentication = {"schemes": []}
        if auth_type == "oauth2":
            authentication["schemes"] = ["oauth2"]
            if "flows" in auth_config:
                authentication["flows"] = auth_config["flows"]
        elif auth_type == "bearer":
            authentication["schemes"] = ["bearer"]
        elif auth_type == "api_key":
            authentication["schemes"] = ["apiKey"]

        agent_card = {
            "_aib_source": "mcp",
            "_aib_translated_at": datetime.now(timezone.utc).isoformat(),
            "name": server_card.get("name", "Unknown Server"),
            "description": server_card.get("description", ""),
            "url": server_card.get("server_url", ""),
            "version": server_card.get("version", "1.0.0"),
            "skills": skills,
            "authentication": authentication,
            "capabilities": {
                "streaming": True,
                "pushNotifications": False,
            },
        }

        return agent_card

    # ── Agent Card / Server Card → DID Document ───────────────────

    @staticmethod
    def to_did_document(
        card: dict,
        source_protocol: str,
        domain: str,
        agent_slug: str,
        public_key_hex: str = "",
    ) -> dict:
        """
        Generate a W3C DID Document (did:web method) from any agent card.
        Compliant with W3C DID v1.1 (Candidate Recommendation 2026-03-05)
        and did:web method specification.

        Resolution paths:
          did:web:{domain}              → https://{domain}/.well-known/did.json
          did:web:{domain}:agents:{slug} → https://{domain}/agents/{slug}/did.json

        Args:
            card: Agent Card (A2A) or Server Card (MCP)
            source_protocol: "a2a" or "mcp"
            domain: e.g. "aib-tech.fr"
            agent_slug: e.g. "booking"
            public_key_hex: Ed25519 public key as hex string (64 chars / 32 bytes).
                           If empty, verificationMethod is omitted.
        """
        did = f"did:web:{domain}:agents:{agent_slug}"

        # Extract endpoint URL
        if source_protocol == "a2a":
            service_url = card.get("url", f"https://{domain}")
            service_type = "A2AAgent"
        else:
            service_url = card.get("server_url", f"https://{domain}")
            service_type = "MCPServer"

        did_doc = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
            ],
            "id": did,
            "controller": did,
            "authentication": [],
            "assertionMethod": [],
            "service": [
                {
                    "id": f"{did}#agent-service",
                    "type": service_type,
                    "serviceEndpoint": service_url,
                    "description": card.get("description", ""),
                }
            ],
            "_aib_source": source_protocol,
            "_aib_translated_at": datetime.now(timezone.utc).isoformat(),
        }

        # Add Ed25519 verification method if public key provided
        if public_key_hex and len(public_key_hex) >= 64:
            # Convert hex to multibase (z + base58btc of multicodec ed25519-pub + raw key)
            # Multicodec prefix for Ed25519 public key: 0xed01
            try:
                raw_bytes = bytes.fromhex(public_key_hex[:64])
                # multicodec ed25519-pub prefix
                multicodec_bytes = b'\xed\x01' + raw_bytes
                # base58btc encode
                import base64
                multibase_key = "z" + _base58btc_encode(multicodec_bytes)
            except (ValueError, Exception):
                multibase_key = ""

            if multibase_key:
                did_doc["verificationMethod"] = [
                    {
                        "id": f"{did}#key-1",
                        "type": "Ed25519VerificationKey2020",
                        "controller": did,
                        "publicKeyMultibase": multibase_key,
                    }
                ]
                did_doc["authentication"] = [f"{did}#key-1"]
                did_doc["assertionMethod"] = [f"{did}#key-1"]

        # Add capabilities as metadata
        capabilities = []
        if source_protocol == "a2a":
            capabilities = [s.get("name", s.get("id", "")) for s in card.get("skills", [])]
        else:
            capabilities = [t.get("name", "") for t in card.get("tools", [])]

        if capabilities:
            did_doc["service"][0]["capabilities"] = capabilities

        return did_doc

    # ── DID Document → A2A Agent Card ─────────────────────────────

    @staticmethod
    def did_to_a2a(did_doc: dict) -> dict:
        """
        Extract an A2A Agent Card from a DID Document.

        Maps service endpoints → url, capabilities → skills.
        """
        services = did_doc.get("service", [])
        primary_service = services[0] if services else {}

        skills = []
        for cap in primary_service.get("capabilities", []):
            skills.append({
                "id": cap.replace(" ", "_").lower(),
                "name": cap,
                "description": f"Capability: {cap}",
            })

        # Determine auth from verification methods
        auth_schemes = []
        if did_doc.get("authentication"):
            auth_schemes = ["did-auth"]

        return {
            "_aib_source": "did",
            "_aib_translated_at": datetime.now(timezone.utc).isoformat(),
            "name": did_doc.get("id", "Unknown DID Agent").split(":")[-1].replace("-", " ").title(),
            "description": primary_service.get("description", ""),
            "url": primary_service.get("serviceEndpoint", ""),
            "version": "1.0.0",
            "skills": skills,
            "authentication": {"schemes": auth_schemes},
            "capabilities": {"streaming": False, "pushNotifications": False},
        }

    # ── Universal translate method ────────────────────────────────

    def translate(
        self,
        source: dict,
        from_format: str,
        to_format: str,
        domain: Optional[str] = None,
        agent_slug: Optional[str] = None,
        public_key_hex: Optional[str] = None,
    ) -> dict:
        """
        Universal translation dispatcher.

        Args:
            source: The source document
            from_format: "a2a_agent_card" | "mcp_server_card" | "did_document" | "ag_ui_descriptor"
            to_format: Same options as from_format
            domain: Required for DID generation
            agent_slug: Required for DID generation
            public_key_hex: Ed25519 public key (hex) for DID Document verificationMethod
        """
        # Import AG-UI translations
        from .ag_ui_binding import (
            ag_ui_to_a2a, a2a_to_ag_ui,
            ag_ui_to_mcp, mcp_to_ag_ui,
        )

        key = f"{from_format}->{to_format}"
        pk = public_key_hex or ""

        translations = {
            # Original 5 paths
            "a2a_agent_card->mcp_server_card": lambda: self.a2a_to_mcp(source),
            "mcp_server_card->a2a_agent_card": lambda: self.mcp_to_a2a(source),
            "a2a_agent_card->did_document": lambda: self.to_did_document(
                source, "a2a", domain or "example.com", agent_slug or "agent", pk
            ),
            "mcp_server_card->did_document": lambda: self.to_did_document(
                source, "mcp", domain or "example.com", agent_slug or "agent", pk
            ),
            "did_document->a2a_agent_card": lambda: self.did_to_a2a(source),

            # AG-UI ↔ A2A (2 paths)
            "ag_ui_descriptor->a2a_agent_card": lambda: ag_ui_to_a2a(source),
            "a2a_agent_card->ag_ui_descriptor": lambda: a2a_to_ag_ui(source),

            # AG-UI ↔ MCP (2 paths)
            "ag_ui_descriptor->mcp_server_card": lambda: ag_ui_to_mcp(source),
            "mcp_server_card->ag_ui_descriptor": lambda: mcp_to_ag_ui(source),

            # AG-UI ↔ DID (2 paths — via A2A intermediate)
            "ag_ui_descriptor->did_document": lambda: self.to_did_document(
                ag_ui_to_a2a(source), "a2a", domain or "example.com", agent_slug or "agent", pk
            ),
            "did_document->ag_ui_descriptor": lambda: a2a_to_ag_ui(self.did_to_a2a(source)),
        }

        if key not in translations:
            raise ValueError(
                f"Unsupported translation: {key}. "
                f"Supported: {list(translations.keys())}"
            )

        return translations[key]()


# ── CLI demo ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  AIB — Credential Translator Demo")
    print("=" * 60)

    translator = CredentialTranslator()

    # Sample A2A Agent Card
    sample_a2a = {
        "name": "DomUp Booking Agent",
        "description": "Books home services in French overseas territories",
        "url": "https://domup-sap.fr/agents/booking",
        "version": "1.2.0",
        "skills": [
            {"id": "book_service", "name": "Book Service", "description": "Schedule a home service appointment"},
            {"id": "check_availability", "name": "Check Availability", "description": "Check provider availability"},
            {"id": "send_notification", "name": "Send Notification", "description": "Notify clients and providers"},
        ],
        "authentication": {"schemes": ["oauth2"]},
        "capabilities": {"streaming": True, "pushNotifications": True},
    }

    print("\n📄 Source: A2A Agent Card")
    print(f"   Name: {sample_a2a['name']}")
    print(f"   Skills: {[s['id'] for s in sample_a2a['skills']]}")

    # A2A → MCP
    mcp_card = translator.translate(sample_a2a, "a2a_agent_card", "mcp_server_card")
    print(f"\n🔄 Translated to MCP Server Card:")
    print(f"   Name: {mcp_card['name']}")
    print(f"   Tools: {[t['name'] for t in mcp_card['tools']]}")
    print(f"   Auth: {mcp_card['auth']}")
    print(f"   Transport: {mcp_card['transport']}")

    # A2A → DID
    did_doc = translator.translate(
        sample_a2a, "a2a_agent_card", "did_document",
        domain="domup-sap.fr", agent_slug="booking"
    )
    print(f"\n🔄 Translated to DID Document:")
    print(f"   DID: {did_doc['id']}")
    print(f"   Service: {did_doc['service'][0]['type']} → {did_doc['service'][0]['serviceEndpoint']}")

    # MCP → A2A (round-trip test)
    back_to_a2a = translator.translate(mcp_card, "mcp_server_card", "a2a_agent_card")
    print(f"\n🔄 Round-trip MCP → A2A:")
    print(f"   Name: {back_to_a2a['name']}")
    print(f"   Skills: {[s['id'] for s in back_to_a2a['skills']]}")

    # Full JSON output
    print(f"\n{'─' * 60}")
    print("Full MCP Server Card (translated):")
    print(json.dumps(mcp_card, indent=2))

    print(f"\n{'=' * 60}")
    print("  Demo complete.")
    print("=" * 60)
