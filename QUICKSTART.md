# AIB — Quickstart (15 minutes)

## Install

```bash
pip install agent-identity-bridge
```

## Run the interactive demo

```bash
curl -sO https://raw.githubusercontent.com/tntech-consulting/agent-identity-bridge/main/examples/quickstart.py
python quickstart.py
```

This runs 8 steps locally (no API key needed):

1. **Create** an Agent Passport (Ed25519-signed, multi-protocol)
2. **Verify** the passport token cryptographically
3. **Translate** A2A Agent Card → MCP Server Card (basic format conversion)
4. **Translate** MCP → A2A (reverse)
5. **Generate** a W3C DID Document (did:web)
6. **Resolve** did:key offline (no network)
7. **Enforce** policies (capability check + rate limit)
8. **Revoke** passport and verify rejection

## Quick examples

### Create and verify a passport

```python
from aib import PassportService
from aib.passport import McpBinding, A2aBinding

svc = PassportService(secret_key="my-key")
passport, token = svc.create_passport(
    org_slug="myorg",
    agent_slug="booking-bot",
    capabilities=["booking", "calendar"],
    bindings={
        "mcp": McpBinding(auth_method="oauth2"),
        "a2a": A2aBinding(auth_method="bearer"),
    },
)
print(passport.passport_id)  # urn:aib:agent:myorg:booking-bot

# Verify — works regardless of protocol context
valid, _, reason = svc.verify_passport(token)

# Revoke — instant, targeted, does not affect other agents
svc.revoke_passport(passport.passport_id)
```

### Enforce policies before execution

```python
from aib import PolicyEngine

engine = PolicyEngine()
engine.add_rule("capability_required", {"required": ["booking"]})
engine.add_rule("rate_limit", {"max_per_minute": 100})

result = engine.evaluate(passport)
if not result.allowed:
    print(f"Blocked: {result.reason}")
```

### Resolve DID

```python
from aib import public_key_to_did_key, did_key_to_did_document

did = public_key_to_did_key("314eff...your-key-hex...")
doc = did_key_to_did_document(did)
# W3C DID v1.1 Document, no network needed
```

### Translate credentials (basic format conversion)

```python
from aib import CredentialTranslator

translator = CredentialTranslator()
mcp_card = translator.a2a_to_mcp({
    "name": "My Agent",
    "skills": [{"id": "booking", "name": "Booking"}],
    "url": "https://example.com",
})
# skills → tools — useful for metadata interoperability
# Note: this is format conversion, not full protocol bridging
```

### Integrate with LangChain

```python
from aib.integrations import get_langchain_tools
tools = get_langchain_tools(secret_key="your-key")

from langchain.agents import create_react_agent
agent = create_react_agent(llm, tools, prompt)
```

### Integrate with CrewAI

```python
from aib.integrations import get_crewai_tools
tools = get_crewai_tools(secret_key="your-key")

from crewai import Agent
agent = Agent(role="Identity Manager", tools=tools)
```

## Cloud API

```bash
# Create passport via hosted API
curl -X POST https://aib-tech.fr/api/passport-create \
  -H "x-api-key: aib_sk_live_..." \
  -d '{"agent_slug":"booking","protocols":["mcp","a2a"]}'

# Query audit trail
curl https://aib-tech.fr/api/audit-trail \
  -H "x-api-key: aib_sk_live_..." \
  -G -d "passport_id=urn:aib:agent:myorg:booking"

# Resolve DID
curl https://aib-tech.fr/agents/booking/did.json
```

> The Cloud API is available during the open beta. Sign up at [aib-tech.fr/dashboard](https://aib-tech.fr/dashboard).

## Links

- [Dashboard](https://aib-tech.fr/dashboard) · [Spec](https://aib-tech.fr/spec) · [GitHub](https://github.com/tntech-consulting/agent-identity-bridge) · [PyPI](https://pypi.org/project/agent-identity-bridge/)
