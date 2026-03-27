# Agent Identity Bridge (AIB)

**One identity. Every protocol. Full audit trail.**

[![Tests](https://img.shields.io/badge/tests-1081%20passed-brightgreen)]()
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)]()
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/agent-identity-bridge)](https://pypi.org/project/agent-identity-bridge/)
[![Edge Functions](https://img.shields.io/badge/edge%20functions-12%20active-green)]()

AIB is an open-source protocol that gives AI agents a **single portable identity** across MCP (Anthropic), A2A (Google), ANP (W3C DID), and AG-UI (CopilotKit).

## The problem

Each AI protocol invented its own identity system. An agent operating across MCP + A2A + AG-UI has three separate identities with zero link between them. Cross-protocol auditing is impossible, credential management is painful, and compliance is a nightmare.

## Quick start

```bash
pip install agent-identity-bridge
```

### AIB Cloud (managed SaaS)

```python
from aib.cloud import AIBCloud

client = AIBCloud("aib_sk_live_...")

passport = client.create_passport("my-bot", protocols=["mcp", "a2a", "ag_ui"])
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
from aib.integrations import get_langchain_tools   # LangChain
from aib.integrations import get_crewai_tools       # CrewAI
from aib.integrations import get_openai_agents_tools # OpenAI Agents SDK
```

## Key features

- **Portable identity**: One passport, valid on MCP, A2A, ANP, AG-UI
- **Credential translation**: 11 paths across 4 formats (< 1ms)
- **Policy engine**: 12 rule types — deliverable gates, separation of duties, capability enforcement
- **Ed25519 audit trail**: Signed receipts with SHA-256 hash chaining
- **OIDC federation**: Google, Microsoft Entra, Okta, Auth0 — bring your own IdP
- **Webhooks**: passport.created, passport.revoked, policy.violation — HMAC-SHA256 signed
- **Framework integrations**: LangChain, CrewAI, OpenAI Agents SDK
- **Delegation chains**: Parent → child with capability subset enforcement
- **GDPR compliance**: Crypto-shredding, PII guard, consent tracking

## AIB Cloud — Managed SaaS

12 Edge Functions, dashboard with 6 tabs, auto-onboarding, analytics.

| Feature | Community | Pro ($49/mo) | Enterprise |
|---------|:-:|:-:|:-:|
| Passports | 10 | 500 | Unlimited |
| Transactions/mo | 1,000 | 100,000 | Custom |
| Policy rules | 3 | 50 | Custom |
| OIDC federation | — | ✓ | ✓ |
| Webhooks | 1 | 20 | Custom |

**Dashboard**: [aib-cloud.netlify.app/dashboard.html](https://aib-cloud.netlify.app/dashboard.html)

## Comparison with funded startups

| | t54 Labs ($5M) | Defakto ($50M) | AIB |
|---|:-:|:-:|:-:|
| Cross-protocol (MCP/A2A/AG-UI) | — | — | ✓ |
| Policy engine | — | ✓ | ✓ (12 types) |
| OIDC federation | — | SPIFFE | ✓ (Google+Entra) |
| Ed25519 audit | Risk engine | Audit trails | ✓ Signed receipts |
| Framework integrations | — | — | ✓ 3 frameworks |
| Open source | Partial | — | ✓ Full |
| Tests | — | — | 1,081 |

## How AIB relates to existing protocols

AIB doesn't compete with MCP, A2A, or AG-UI — it **bridges** them.

- **MCP** connects agents to tools. AIB connects agents to *all protocols*.
- **A2A** coordinates agents. AIB gives each agent an identity usable everywhere.
- **Okta/Entra** authenticates humans. AIB bridges their tokens to agent passports.

## Contributing

Apache 2.0 licensed. Contributions welcome.

```bash
git clone https://github.com/tntech-consulting/agent-identity-bridge.git
cd agent-identity-bridge
pip install -e ".[dev]"
pytest  # 1,081 tests
```

## Author

**Thomas Nirennold** — [TNTECH CONSULTING SAS](https://tntech.fr) (SIREN 993811157)

[Protocol](https://aib-tech.fr) · [Cloud](https://aib-cloud.netlify.app) · [Blog](https://aib-tech.fr/blog.html) · [PyPI](https://pypi.org/project/agent-identity-bridge/)

## License

Apache 2.0 — see [LICENSE](LICENSE)
