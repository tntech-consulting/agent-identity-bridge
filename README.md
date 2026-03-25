# Agent Identity Bridge (AIB)

**One identity. Every protocol. Full audit trail.**

[![Tests](https://img.shields.io/badge/tests-732%20passed-brightgreen)]()
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)]()
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/agent-identity-bridge)](https://pypi.org/project/agent-identity-bridge/)

AIB is an open-source protocol that gives AI agents a **single portable identity** across MCP (Anthropic), A2A (Google), ANP (W3C DID), and AG-UI — the four layers of the 2026 AI communication stack.

```
Your Agent ──→ AIB Gateway ──→ MCP Server  (OAuth injected)
                           ──→ A2A Agent   (Agent Card matched)
                           ──→ ANP Peer    (DID resolved)
```

## The problem

Each AI protocol invented its own identity system. An agent operating across MCP + A2A + ANP has three separate identities with zero link between them. This makes cross-protocol auditing impossible, credential management painful, and compliance (GDPR, SOC2) a nightmare.

## Quick start

```bash
pip install agent-identity-bridge
```

### Create your first Agent Passport

```python
from aib.passport import PassportService, McpBinding, A2aBinding

svc = PassportService(secret_key="your-secret")

passport, token = svc.create_passport(
    org_slug="mycompany",
    agent_slug="booking-agent",
    display_name="Booking Agent",
    capabilities=["booking", "scheduling"],
    bindings={
        "mcp": McpBinding(auth_method="oauth2", server_card_url="https://..."),
        "a2a": A2aBinding(auth_method="bearer", agent_card_url="https://..."),
    },
)

# Verify anytime
valid, payload, reason = svc.verify_passport(token)
```

### Translate between formats

```python
from aib.translator import CredentialTranslator

t = CredentialTranslator()

# A2A Agent Card → MCP Server Card
mcp_card = t.translate(
    source=agent_card,
    from_format="a2a_agent_card",
    to_format="mcp_server_card",
)

# Also: mcp → a2a, a2a → did, did → a2a
```

### Run the gateway

```bash
# With Python
uvicorn aib.main:app --port 8420

# With Docker
docker compose up

# API docs at http://localhost:8420/docs
```

### CLI

```bash
aib create --org mycompany --agent booking --protocols mcp,a2a
aib verify <token>
aib translate --from a2a --to mcp --source agent-card.json
aib list
aib inspect <passport_id>
aib revoke <passport_id>
aib keygen
aib serve --port 8420
```

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌──────────────┐
│  Your Agent  │────►│   AIB Gateway    │────►│  MCP Server  │
│              │     │                  │────►│  A2A Agent   │
│  1 passport  │     │  Translates IDs  │────►│  ANP Peer    │
│              │     │  Logs everything │     │              │
└─────────────┘     └──────────────────┘     └──────────────┘
```

### Agent Passport format

```json
{
  "aib_version": "2.2",
  "passport_id": "urn:aib:agent:myorg:booking",
  "issuer": "urn:aib:org:myorg",
  "capabilities": ["booking", "scheduling"],
  "protocol_bindings": {
    "mcp": { "auth_method": "oauth2", "server_card_url": "https://..." },
    "a2a": { "auth_method": "bearer", "agent_card_url": "https://..." },
    "anp": { "did": "did:web:example.com:agents:booking" }
  },
  "tier": "permanent",
  "issued_at": "2026-03-25T10:00:00Z",
  "expires_at": "2027-03-25T10:00:00Z"
}
```

## Key features

- **Portable identity**: One passport per agent, valid on MCP, A2A, ANP, AG-UI
- **Credential translation**: A2A Agent Cards ↔ MCP Server Cards ↔ DID Documents
- **Passport lifecycle**: Permanent (365d), session (1-24h), ephemeral (5min)
- **Delegation chains**: Parent → child with capability subset enforcement
- **Merkle audit trail**: SHA-256 hash chaining + O(log N) proofs
- **Multi-signature**: M-of-N RSA-PSS with auto key rotation (90 days)
- **OIDC binding**: Microsoft Entra, Okta, Auth0, Keycloak
- **GDPR compliance**: Crypto-shredding (AES-256-GCM), PII guard, Art.17/18/20/21
- **Federation**: Cross-org trust via .well-known + JWKS exchange
- **Rate limiting**: Sliding window per passport_id, tier-based
- **JSON Schema validation**: All protocol formats validated in + out
- **Prometheus metrics**: Latency p50/p95/p99, error rates, rate limit hits
- **Structured logging**: JSON lines with trace_id correlation
- **27 error codes**: AIB-001 to AIB-903, no internal detail leakage

## API endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Health check |
| `GET` | `/health/ready` | Deep health with component checks |
| `POST` | `/passports` | Create agent passport |
| `GET` | `/passports` | List all passports |
| `GET` | `/passports/{id}` | Get + verify passport |
| `DELETE` | `/passports/{id}` | Revoke passport |
| `POST` | `/translate` | Translate between formats |
| `POST` | `/gateway/proxy` | Proxy with credential injection |
| `GET` | `/audit/{id}` | Query audit trail |
| `GET` | `/audit` | Global audit stats |
| `GET` | `/metrics` | Prometheus metrics |
| `GET` | `/.well-known/aib.json` | Discovery document |
| `GET` | `/.well-known/aib-keys.json` | JWKS (public keys) |
| `GET` | `/.well-known/aib-agents.json` | Agent registry |
| `GET` | `/.well-known/aib-federation.json` | Federation config |

## Docker

```bash
# Quick start
docker compose up

# With custom secret
AIB_SECRET_KEY=my-production-secret docker compose up -d

# The gateway is at http://localhost:8420
# API docs at http://localhost:8420/docs
```

## 29 modules

| Module | Purpose |
|--------|---------|
| `passport.py` | Agent Passport CRUD + RS256 signing |
| `translator.py` | A2A ↔ MCP ↔ DID translation |
| `gateway.py` | Protocol-aware reverse proxy |
| `crypto.py` | RS256 key management + JWKS |
| `security.py` | SSRF protection + input validation |
| `cli.py` | 8-command CLI tool |
| `client.py` | AIBClient SDK |
| `lifecycle.py` | Passport tiers + delegation chains |
| `receipts.py` | Action Receipts + hash chaining |
| `oidc.py` | OIDC binding (Entra, Okta, Auth0, Keycloak) |
| `plugins.py` | Plugin system + auto-discovery |
| `gdpr.py` | GDPR crypto-shredding + PII guard |
| `merkle.py` | Merkle Tree + O(log N) proofs |
| `discovery.py` | .well-known endpoints + federation |
| `rate_limiter.py` | Sliding window rate limiter |
| `schema_validator.py` | JSON Schema for all formats |
| `gateway_integration.py` | Production gateway stack |

## How AIB relates to existing protocols

AIB doesn't compete with MCP, A2A, or ANP — it **bridges** them.

- **MCP** connects agents to tools. AIB connects agents to *all protocols*.
- **A2A** coordinates agents. AIB gives each agent an identity usable in A2A *and* MCP *and* ANP.
- **ANP** provides decentralized identity (DID). AIB uses DID as one of its supported formats, not the only one.

## Standards alignment

- **NIST**: Submitted to NCCoE "AI Agent Identity and Authorization" initiative
- **W3C**: Contributing to AI Agent Protocol Community Group
- **NGI Zero**: Applied to Commons Fund (€35K)
- **AAIF**: Compatible with Agentic AI Foundation (MCP + A2A governance)

## Contributing

Apache 2.0 licensed. Contributions welcome — especially:

- Additional protocol bindings (AG-UI, LMOS)
- Enterprise features (ES256/EdDSA, circuit breaker, OpenTelemetry)
- Language SDKs (TypeScript, Go, Java)
- Documentation and tutorials

```bash
git clone https://github.com/tntech-consulting/agent-identity-bridge.git
cd agent-identity-bridge
pip install -e ".[dev]"
pytest  # 732 tests
```

## Author

**Thomas Nirennold** — [TNTECH CONSULTING SAS](https://tntech.fr) (SIREN 993811157)

Building the identity layer the AI agent ecosystem is missing.

## License

Apache 2.0 — see [LICENSE](LICENSE)
