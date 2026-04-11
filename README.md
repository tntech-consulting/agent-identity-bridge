# Agent Identity Bridge (AIB)

**One identity. Every protocol. Full audit trail.**

[![Tests](https://img.shields.io/github/actions/workflow/status/tntech-consulting/agent-identity-bridge/ci.yml?label=tests)](https://github.com/tntech-consulting/agent-identity-bridge/actions)
[![PyPI](https://img.shields.io/pypi/v/agent-identity-bridge)](https://pypi.org/project/agent-identity-bridge/)
[![Python](https://img.shields.io/pypi/pyversions/agent-identity-bridge)](https://pypi.org/project/agent-identity-bridge/)
[![License](https://img.shields.io/pypi/l/agent-identity-bridge)](LICENSE)

AIB is an open-source protocol that gives AI agents a **single portable identity** across MCP (Anthropic) and A2A (Google) — with Ed25519 cryptographic signing, W3C DID and Verifiable Credentials support (in development), and EU AI Act compliance built in.

## The problem

Each AI protocol invented its own identity system. An agent operating across MCP and A2A has separate identities with zero link between them. Cross-protocol auditing is impossible, credential management is painful, and EU AI Act compliance is a nightmare.

## Quick start

```bash
pip install agent-identity-bridge
python -c "from aib import PassportService; print('AIB ready')"
```

### Run the interactive demo (15 seconds, zero config)

```bash
curl -sO https://raw.githubusercontent.com/tntech-consulting/agent-identity-bridge/main/examples/quickstart.py
python quickstart.py
```

### AIB Cloud (managed SaaS)

```python
from aib.cloud import AIBCloud

client = AIBCloud("aib_sk_live_...")

passport = client.create_passport("my-bot", protocols=["mcp", "a2a"])
mcp_card = client.translate(a2a_card, "a2a_agent_card", "mcp_server_card")
client.create_policy("deliverable_gate", {"required_capabilities": ["tests_passed"]})
client.create_webhook("https://your-app.com/hooks", events=["passport.created"])
```

### Local protocol (self-hosted)

```python
from aib.passport import PassportService, McpBinding, A2aBinding

svc = PassportService(secret_key="your-secret")
passport, token = svc.create_passport(
    org_slug="mycompany", agent_slug="booking-agent",
    capabilities=["booking", "scheduling"],
    bindings={"mcp": McpBinding(auth_method="oauth2"), "a2a": A2aBinding(auth_method="bearer")},
)
```

### Framework integrations

```python
from aib.integrations import get_langchain_tools    # LangChain
from aib.integrations import get_crewai_tools        # CrewAI
from aib.integrations import get_openai_agents_tools # OpenAI Agents SDK
```

## Key features

- **Portable identity**: One passport, valid on MCP and A2A
- **Credential translation**: Cross-protocol format conversion (MCP ↔ A2A)
- **Ed25519 signing**: Cryptographic signatures on passports and receipts
- **W3C DID support**: DID resolution (did:key offline, did:web via API)
- **W3C Verifiable Credentials**: VC issuance (in development)
- **EU AI Act compliance**: Structured fields (intent, risk_level, human_oversight) in every signed receipt — covers Art. 12, 13, 14, 16
- **Policy engine**: capability_required, deliverable_gate, attestation_required, domain_block, protocol_restrict, rate_limit
- **Signed audit trail**: Ed25519-signed receipts with SHA-256 hash chaining
- **OIDC federation**: Bring your own IdP (Google, Microsoft Entra, Okta, Auth0)
- **Webhooks**: HMAC-SHA256 signed payloads
- **Framework integrations**: LangChain, CrewAI, OpenAI Agents SDK

## AIB Cloud — Managed SaaS

> AIB Cloud is currently in **open beta** — free access to all features. Sign up at [aib-tech.fr/dashboard](https://aib-tech.fr/dashboard).

15 API endpoints, 40+ tables with RLS, 15 autonomous agents.

**Dashboard**: [aib-tech.fr/dashboard](https://aib-tech.fr/dashboard) · **API**: `https://aib-tech.fr/api/` · **Status**: [aib-tech.fr/status](https://aib-tech.fr/status)

## How AIB relates to existing solutions

AIB is a **standard, not a product**. It bridges protocols, it doesn't compete with IAM vendors.

- **MCP** connects agents to tools. AIB gives agents a portable identity usable across protocols.
- **A2A** coordinates agents. AIB provides the cryptographic identity layer each agent carries.
- **Okta/Entra** authenticates humans. AIB bridges their tokens to agent passports via OIDC federation.
- **SailPoint** discovers and governs agents. AIB gives them portable identities across protocols.

See [aib-tech.fr/why](https://aib-tech.fr/why) for full positioning.

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

The test suite covers passport CRUD, credential translation, audit trail, policy engine, and DID resolution.

## Contributing

Apache 2.0 licensed. Contributions welcome.

```bash
git clone https://github.com/tntech-consulting/agent-identity-bridge.git
cd agent-identity-bridge
pip install -e ".[dev]"
pytest
```

## Author

**Thomas Nirennold** — [TNTECH CONSULTING SAS](https://tntech.fr) (SIREN 993811157), Paris, France

[Protocol](https://aib-tech.fr) · [Why AIB](https://aib-tech.fr/why) · [Compliance Kit](https://aib-tech.fr/compliance) · [Blog](https://aib-tech.fr/blog) · [PyPI](https://pypi.org/project/agent-identity-bridge/)

## License

Apache 2.0 — see [LICENSE](LICENSE)
