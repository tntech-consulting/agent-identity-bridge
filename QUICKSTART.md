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

1. **Create** an Agent Passport (MCP + A2A)
2. **Verify** the passport token
3. **Translate** A2A Agent Card → MCP Server Card
4. **Translate** MCP → A2A (round-trip)
5. **Generate** a W3C DID Document (did:web)
6. **Resolve** did:key offline (no network)
7. **Enforce** policies (capability check)
8. **Revoke** passport and verify rejection

## Quick examples

### Create a passport

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
```

### Translate credentials

```python
from aib import CredentialTranslator

translator = CredentialTranslator()
mcp_card = translator.a2a_to_mcp({
    "name": "My Agent",
    "skills": [{"id": "booking", "name": "Booking"}],
    "url": "https://example.com",
})
# skills → tools, A2A format → MCP format
```

### Resolve DID

```python
from aib import public_key_to_did_key, did_key_to_did_document

did = public_key_to_did_key("314eff...your-key-hex...")
doc = did_key_to_did_document(did)
# W3C DID v1.1 Document, no network needed
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

# Resolve DID
curl https://aib-tech.fr/agents/booking/did.json
```

> The Cloud API is available during the open beta. Sign up at [aib-tech.fr/dashboard](https://aib-tech.fr/dashboard).

## Links

- [Dashboard](https://aib-tech.fr/dashboard) · [Spec](https://aib-tech.fr/spec) · [GitHub](https://github.com/tntech-consulting/agent-identity-bridge) · [PyPI](https://pypi.org/project/agent-identity-bridge/)
