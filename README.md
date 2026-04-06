# Agent Identity Bridge (AIB)

**One identity. Every protocol. Full audit trail.**

[![Tests](https://img.shields.io/github/actions/workflow/status/tntech-consulting/agent-identity-bridge/ci.yml?label=tests)](https://github.com/tntech-consulting/agent-identity-bridge/actions)
[![Python](https://img.shields.io/pypi/pyversions/agent-identity-bridge)](https://pypi.org/project/agent-identity-bridge/)
[![License](https://img.shields.io/pypi/l/agent-identity-bridge)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/agent-identity-bridge)](https://pypi.org/project/agent-identity-bridge/)
[![Edge Functions](https://img.shields.io/badge/edge%20functions-35%20deployed-green)]()
[![Version](https://img.shields.io/pypi/v/agent-identity-bridge?label=version)](https://pypi.org/project/agent-identity-bridge/)

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
- **W3C DID support**: DID resolution in development
- **W3C Verifiable Credentials**: VC issuance in development
- **EU AI Act compliance**: Structured fields (intent, risk_level, human_oversight, etc.) in every signed receipt — covers Art. 12, 13, 14, 16
- **Policy engine**: capability_required, deliverable_gate, attestation_required, domain_block, protocol_restrict, rate_limit
- **Ed25519 audit trail**: Signed receipts with SHA-256 hash chaining, AES-256 encrypted keys
- **OIDC federation**: Bring your own IdP (Google, Microsoft Entra, Okta, Auth0)
- **Webhooks**: HMAC-SHA256 signed payloads
- **ISO/IEC 42001:2023 alignment**: Designed in alignment with the AI Management System standard
- **Framework integrations**: LangChain, CrewAI, OpenAI Agents SDK

## AIB Cloud — Managed SaaS

35 Edge Functions, 13 API endpoints, 40+ tables with RLS.

| Feature | Community | Pro (990€/mo) | Enterprise |
|---------|:-:|:-:|:-:|
| Passports | 10 | 500 | Unlimited |
| Transactions/mo | 1,000 | 100,000 | Custom |
| Policy rules | 3 | 50 | Custom |
| OIDC federation | — | ✓ | ✓ |
| Webhooks | 1 | 20 | Custom |
| Intent inference | — | ✓ | ✓ |
| VCs | — | ✓ | ✓ |

**Dashboard**: [aib-tech.fr/dashboard](https://aib-tech.fr/dashboard)
**EU AI Act Compliance Kit**: [aib-tech.fr/compliance](https://aib-tech.fr/compliance)

## How AIB relates to existing solutions

AIB is a **standard, not a product**. It bridges protocols, it doesn't compete with IAM vendors.

- **MCP** connects agents to tools. AIB gives agents a portable identity usable across protocols.
- **A2A** coordinates agents. AIB provides the cryptographic identity layer each agent carries.
- **Okta/Entra** authenticates humans. AIB bridges their tokens to agent passports via OIDC federation.
- **SailPoint** discovers and governs agents. AIB gives them portable identities across protocols.

See [aib-tech.fr/why](https://aib-tech.fr/why) for full positioning.

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
