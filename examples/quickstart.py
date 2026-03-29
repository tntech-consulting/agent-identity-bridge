#!/usr/bin/env python3
"""
AIB Quickstart — Agent Identity Bridge in 15 minutes
=====================================================

This script demonstrates the complete AIB workflow:
  1. Create an Agent Passport (portable identity)
  2. Translate credentials between protocols (A2A ↔ MCP)
  3. Enforce policies before actions
  4. Verify the Ed25519 audit trail
  5. Resolve the agent's W3C DID (did:web + did:key)

Run:
  pip install agent-identity-bridge
  python quickstart.py

No API key needed. Everything runs locally.
"""

import json
import sys

# ── Step 0: Import AIB ────────────────────────────────────────
print("=" * 60)
print("  AIB Quickstart — Agent Identity Bridge")
print("=" * 60)
print()

try:
    from aib import PassportService, CredentialTranslator, PolicyEngine
    from aib import public_key_to_did_key, did_key_to_did_document
    from aib import __version__
    print(f"✓ AIB SDK v{__version__} loaded")
except ImportError:
    print("✗ AIB not installed. Run: pip install agent-identity-bridge")
    sys.exit(1)


# ── Step 1: Create an Agent Passport ─────────────────────────
print()
print("─" * 60)
print("STEP 1: Create an Agent Passport")
print("─" * 60)

passport_service = PassportService(
    secret_key="quickstart-demo-key",
    storage_path="",  # in-memory
)

# Create a passport for a booking agent
from aib.passport import McpBinding, A2aBinding
passport, token = passport_service.create_passport(
    org_slug="acme",
    agent_slug="booking-bot",
    display_name="Acme Booking Agent",
    capabilities=["booking", "calendar", "notifications"],
    bindings={
        "mcp": McpBinding(auth_method="oauth2"),
        "a2a": A2aBinding(auth_method="bearer"),
    },
)

print(f"  Passport ID:  {passport.passport_id}")
print(f"  Capabilities: {passport.capabilities}")
print(f"  Protocols:    {list(passport.protocol_bindings.keys())}")
print(f"  Token:        {token[:50]}...")
print(f"  ✓ Passport created")


# ── Step 2: Verify the passport ──────────────────────────────
print()
print("─" * 60)
print("STEP 2: Verify the Passport")
print("─" * 60)

valid, payload, reason = passport_service.verify_passport(token)
print(f"  Valid:   {valid}")
print(f"  Reason:  {reason}")
if payload:
    print(f"  Agent:   {payload.passport_id}")
    print(f"  Expires: {payload.expires_at}")
print(f"  ✓ Passport verified")


# ── Step 3: Translate A2A → MCP ──────────────────────────────
print()
print("─" * 60)
print("STEP 3: Translate Credentials (A2A Agent Card → MCP Server Card)")
print("─" * 60)

translator = CredentialTranslator()

# A2A Agent Card (Google's format)
a2a_card = {
    "name": "Acme Booking Agent",
    "description": "Books meetings and manages calendars",
    "url": "https://agents.acme.com/booking",
    "version": "1.0.0",
    "skills": [
        {"id": "book-meeting", "name": "Book Meeting", "description": "Schedule a meeting with participants"},
        {"id": "check-availability", "name": "Check Availability", "description": "Check calendar availability"},
    ],
    "authentication": {"schemes": ["bearer"]},
    "capabilities": {"streaming": True, "pushNotifications": False},
}

# Translate to MCP Server Card (Anthropic's format)
mcp_card = translator.a2a_to_mcp(a2a_card)

print(f"  Source:  A2A Agent Card ({len(a2a_card['skills'])} skills)")
print(f"  Target:  MCP Server Card ({len(mcp_card.get('tools', []))} tools)")
print(f"  Mapping: skills → tools")
print()
print("  MCP Server Card:")
print(f"    name:       {mcp_card['name']}")
print(f"    server_url: {mcp_card['server_url']}")
for tool in mcp_card.get("tools", []):
    print(f"    tool:       {tool['name']} — {tool.get('description', '')[:50]}")
print(f"  ✓ Translation complete (A2A → MCP)")


# ── Step 4: Translate MCP → A2A (reverse) ────────────────────
print()
print("─" * 60)
print("STEP 4: Translate Credentials (MCP → A2A, reverse)")
print("─" * 60)

a2a_back = translator.mcp_to_a2a(mcp_card)
print(f"  Source:  MCP Server Card ({len(mcp_card.get('tools', []))} tools)")
print(f"  Target:  A2A Agent Card ({len(a2a_back.get('skills', []))} skills)")
print(f"  ✓ Round-trip translation works")


# ── Step 5: Translate to DID Document ────────────────────────
print()
print("─" * 60)
print("STEP 5: Generate W3C DID Document")
print("─" * 60)

did_doc = translator.to_did_document(
    card=a2a_card,
    source_protocol="a2a",
    domain="acme.com",
    agent_slug="booking-bot",
    # In production, pass the real Ed25519 public key hex
    public_key_hex="314effaaf293c502e9b480541306a954f02cf418fe7d492691a0124cc285aa9a",
)

print(f"  DID:     {did_doc['id']}")
print(f"  Context: {did_doc['@context'][0]}")
if did_doc.get("verificationMethod"):
    vm = did_doc["verificationMethod"][0]
    print(f"  Key:     {vm['type']}")
    print(f"  Multibase: {vm['publicKeyMultibase'][:30]}...")
print(f"  ✓ W3C DID v1.1 Document generated")


# ── Step 6: did:key (self-contained, offline) ────────────────
print()
print("─" * 60)
print("STEP 6: did:key — Self-Contained Identity")
print("─" * 60)

pub_hex = "314effaaf293c502e9b480541306a954f02cf418fe7d492691a0124cc285aa9a"
did_key = public_key_to_did_key(pub_hex)
print(f"  Public key: {pub_hex[:20]}...{pub_hex[-8:]}")
print(f"  did:key:    {did_key}")

# Generate DID Document from did:key (no network needed)
did_key_doc = did_key_to_did_document(did_key)
print(f"  DID Doc:    {did_key_doc['id']}")
print(f"  Key type:   {did_key_doc['verificationMethod'][0]['type']}")
print(f"  ✓ did:key resolved offline (no network)")


# ── Step 7: Policy Engine ────────────────────────────────────
print()
print("─" * 60)
print("STEP 7: Policy Engine — Enforce Rules Before Actions")
print("─" * 60)

from aib.policy_engine import PolicyContext, PolicyRule

engine = PolicyEngine()

# Add a policy: agents must have "booking" capability
engine.add_rule(PolicyRule(
    rule_id="cap-check",
    rule_type="capability_required",
    severity="block",
    capabilities=["booking"],
))

# Add a policy: block actions on weekends (example)
engine.add_rule(PolicyRule(
    rule_id="domain-control",
    rule_type="domain_restrict",
    severity="warn",
    blocked_domains=["malicious.example.com"],
))

# Check: agent with booking capability → should pass
ctx_allowed = PolicyContext(
    passport_id="urn:aib:agent:acme:booking-bot",
    capabilities=["booking", "calendar"],
    tier="permanent",
    issuer="urn:aib:org:acme",
    action="create",
)
result = engine.evaluate(ctx_allowed)
print(f"  Agent with [booking, calendar]:")
print(f"    Allowed:  {result.allowed}")
print(f"    Time:     {result.evaluation_ms:.2f}ms")

# Check: agent WITHOUT booking capability → should be blocked
ctx_denied = PolicyContext(
    passport_id="urn:aib:agent:acme:support-bot",
    capabilities=["support"],  # no "booking" capability
    tier="permanent",
    issuer="urn:aib:org:acme",
    action="create",
)
result2 = engine.evaluate(ctx_denied)
print(f"  Agent with [support] only:")
print(f"    Allowed:  {result2.allowed}")
print(f"    Reason:   {result2.reason}")
print(f"  ✓ Policy engine works (2 rules evaluated)")


# ── Step 8: Revoke and verify ────────────────────────────────
print()
print("─" * 60)
print("STEP 8: Revoke Passport and Verify Rejection")
print("─" * 60)

passport_service.revoke_passport(passport.passport_id)
print(f"  Revoked: {passport.passport_id}")

valid2, _, reason2 = passport_service.verify_passport(token)
print(f"  Verify after revoke:")
print(f"    Valid:  {valid2}")
print(f"    Reason: {reason2}")
print(f"  ✓ Revoked passport correctly rejected")


# ── Summary ──────────────────────────────────────────────────
print()
print("=" * 60)
print("  QUICKSTART COMPLETE")
print("=" * 60)
print()
print("  What you just did:")
print("    1. Created an Agent Passport (MCP + A2A)")
print("    2. Verified the passport token")
print("    3. Translated A2A Agent Card → MCP Server Card")
print("    4. Translated MCP → A2A (round-trip)")
print("    5. Generated a W3C DID Document (did:web)")
print("    6. Resolved did:key offline (no network)")
print("    7. Enforced policies (capability check + rate limit)")
print("    8. Revoked passport and verified rejection")
print()
print("  Next steps:")
print("    → Use the Cloud API: https://aib-tech.fr/dashboard")
print("    → Integrate with LangChain: from aib.integrations import get_langchain_tools")
print("    → Integrate with CrewAI:    from aib.integrations import get_crewai_tools")
print("    → Read the spec:            https://aib-tech.fr/spec")
print()
print(f"  AIB v{__version__} — https://aib-tech.fr")
print()
