# Agent Identity Bridge (AIB)

**Cryptographic identity for AI agents. Portable. Revocable. Auditable.**

[![Tests](https://img.shields.io/github/actions/workflow/status/tntech-consulting/agent-identity-bridge/ci.yml?label=tests)](https://github.com/tntech-consulting/agent-identity-bridge/actions)
[![PyPI](https://img.shields.io/pypi/v/agent-identity-bridge)](https://pypi.org/project/agent-identity-bridge/)
[![Python](https://img.shields.io/pypi/pyversions/agent-identity-bridge)](https://pypi.org/project/agent-identity-bridge/)
[![License](https://img.shields.io/pypi/l/agent-identity-bridge)](LICENSE)

AIB is an open-source identity protocol that gives every AI agent its own **cryptographic passport** — Ed25519-signed, capability-scoped, individually revocable, with a signed audit trail for every operation. It works within MCP and A2A environments, with EU AI Act compliance built in.

## The problem

AI agents are production infrastructure. They access databases, call APIs, execute workflows — with your credentials.

But they have no identity of their own.

**88% of organizations** have already experienced an AI agent security incident. **46%** still authenticate agents with shared API keys. **78%** have no policy for agent identity lifecycle. ([Gravitee, 2026](https://www.gravitee.io/state-of-ai-agent-security))

The result: when something goes wrong, no one knows which agent did what, no one can revoke a single agent without breaking everything, and no one has an audit trail.

## What AIB does

AIB gives each agent a **portable cryptographic passport**:

- **Identity**: Ed25519-signed passport with unique URN, declared capabilities, and protocol bindings
- **Audit trail**: Every operation generates a signed, hash-chained receipt — non-repudiable by design
- **Revocation**: Individual passport revocation without affecting other agents
- **Policy engine**: Capability checks, rate limits, domain restrictions, time windows — enforced before execution
- **Quality gates**: Deliverable contracts with verifiable criteria (test coverage thresholds, review requirements, acceptance criteria). Agents cannot mark tasks complete until contracts are met
- **Spending limits**: Per-capability amount caps (e.g., max 50€ per refund) evaluated at the policy layer
- **EU AI Act compliance**: Intent analysis, risk classification, and human oversight fields in every receipt (Art. 12, 13, 14, 16)
- **DID support**: W3C DID resolution (did:key offline, did:web via API)
- **OIDC federation**: Bring your own IdP (Google, Microsoft Entra, Okta, Auth0)
- **Credential translation**: Basic format conversion between MCP tools and A2A skills for interoperability scenarios

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
client.create_policy("deliverable_gate", {"required_capabilities": ["tests_passed"]})
trail = client.audit_trail(passport_id="urn:aib:agent:myorg:my-bot")
client.create_policy("capability_limit", {"capability": "payment.refund", "max_amount": 50})
client.revoke_passport("urn:aib:agent:myorg:my-bot", reason="suspicious_activity")
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

# Same passport_id works in both MCP and A2A contexts
valid, _, reason = svc.verify_passport(token)
svc.revoke_passport(passport.passport_id)  # Instant, targeted revocation
```

### Framework integrations

```python
from aib.integrations import get_langchain_tools    # LangChain
from aib.integrations import get_crewai_tools        # CrewAI
from aib.integrations import get_openai_agents_tools # OpenAI Agents SDK
```

## AIB Cloud — Managed SaaS

> AIB Cloud is currently in **open beta** — free access to all features. Sign up at [aib-tech.fr/dashboard](https://aib-tech.fr/dashboard).

15 API endpoints, 40+ tables with RLS, 15 autonomous agents.

**Dashboard**: [aib-tech.fr/dashboard](https://aib-tech.fr/dashboard) · **API**: `https://aib-tech.fr/api/` · **Status**: [aib-tech.fr/status](https://aib-tech.fr/status)

## How AIB relates to existing solutions

AIB provides the **identity layer** that other solutions need but don't include.

- **MCP** connects agents to tools. AIB gives each agent a verifiable identity within MCP environments.
- **A2A** coordinates agents. AIB provides the cryptographic passport each agent carries into A2A interactions.
- **Okta/Entra** authenticates humans. AIB bridges their tokens to agent passports via OIDC federation.
- **Microsoft Agent Governance Toolkit** governs agent behavior. AIB focuses specifically on portable identity and signed audit trails.

MCP and A2A are complementary protocols designed for different layers (tools vs coordination). AIB does not attempt full bidirectional translation between them — instead, it provides a **single identity that is valid in both contexts**, with basic format conversion for interoperability scenarios.

See [aib-tech.fr/why](https://aib-tech.fr/why) for full positioning.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full module map, infrastructure diagram, and extension reference.

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
