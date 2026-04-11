# Architecture

## SDK modules

### Core (imported by default)

| Module | Description |
|--------|-------------|
| `passport` | Agent passport creation, verification, revocation. Ed25519-signed identity tokens. |
| `translator` | Credential translation between MCP, A2A, ANP, and AG-UI formats. |
| `policy_engine` | Policy evaluation: capability_required, deliverable_gate, rate_limit, domain_block. |
| `crypto` | Ed25519 key generation, signing, verification. AES-256 key encryption. |
| `cloud` | AIB Cloud API client (managed SaaS). |
| `integrations` | Framework bindings: LangChain, CrewAI, OpenAI Agents SDK. |

### Extended (opt-in)

| Module | Description |
|--------|-------------|
| `audit` | Audit trail with receipt logging, trace context, and query filters. |
| `receipts` | Signed receipt generation with SHA-256 hash chaining. |
| `merkle` | Incremental Merkle tree for tamper-evident receipt chains. |
| `gateway` | Protocol detection and request adaptation (MCP/A2A/ANP auto-detect). |
| `schemas` | JSON Schema validation for passports and receipts. |
| `oidc` | OIDC federation bridge (Google, Microsoft Entra, Okta, Auth0). |
| `lifecycle` | Passport lifecycle management (expiry, renewal, delegation). |
| `renewal` | Automated passport renewal with grace periods. |
| `webhooks` | HMAC-SHA256 signed webhook delivery and verification. |
| `discovery` | Protocol-aware service discovery. |
| `rate_limiter` | Token bucket rate limiter for policy enforcement. |
| `gdpr` | GDPR compliance: consent management, PII encryption (AES-256-GCM), crypto-shredding. |
| `diagnostics` | Health checks and connectivity diagnostics. |

### Security hardening (opt-in)

Advanced security features from the protocol security audit.

| Module | Description |
|--------|-------------|
| `security` | Input validation, injection prevention, safe defaults. |
| `security_hardening` | Ed25519 key auto-rotation (90-day default) and M-of-N multi-signature verification. |
| `security_patches` | Output validation for translation injection and OIDC dev-mode guard. |

### Enterprise extensions (opt-in)

Production-grade features for large-scale deployments.

| Module | Description |
|--------|-------------|
| `sprint4a` | RFC 8785 JSON Canonicalization, GDPR Art.18/21 (restriction + objection), time-based crypto-shredding. |
| `sprint4b` | Multi-signature timeout, signature audit trail, federated JWKS cache with TTL. |
| `sprint5_enterprise` | Circuit breaker pattern, multi-algorithm support (ES256 + EdDSA), signed Certificate Revocation Lists. |
| `sprint6_final` | JWS-signed discovery documents, PKCE support, OpenTelemetry propagation, Shamir Secret Sharing key ceremony. |
| `hardening_sprint1` | Audience claim validation, clock skew tolerance, double DNS resolution, delegation depth limits, structured error codes. |
| `hardening_sprint2` | Pluggable receipt storage (memory/SQLite/PostgreSQL), encrypted key storage (PBKDF2), Prometheus metrics, structured logging with trace_id. |
| `hardening_sprint3` | Async receipt pipeline, incremental Merkle tree, JWKS warm cache, JTI replay protection, PII access audit. |

> **Note**: Enterprise extension modules follow the naming convention from the internal security audit program (45 recommendations, all implemented). A future major version will consolidate these into thematic modules.

## Cloud infrastructure

```
┌─────────────────────────────────────────────────────┐
│                   aib-tech.fr                       │
│                  (Netlify CDN)                      │
│  ┌───────────┐  ┌───────────┐  ┌──────────────┐    │
│  │  Landing   │  │ Dashboard │  │  /api/* proxy │    │
│  │  Pages     │  │  (SaaS)   │  │  → Supabase  │    │
│  └───────────┘  └───────────┘  └──────────────┘    │
└─────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│              Supabase (eu-west-1)                   │
│  ┌──────────────────────────────────────────────┐   │
│  │  15 API Edge Functions (Deno)                │   │
│  │  passport-create, translate, audit-trail,    │   │
│  │  vc-issue, did-resolve, intent-analyze ...   │   │
│  └──────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────┐   │
│  │  15 Autonomous Agent Functions               │   │
│  │  monitoring, security-scanner, seo-agent,    │   │
│  │  blog-content, waitlist-agent, cicd-guardian  │   │
│  │  ... (18 cron jobs)                          │   │
│  └──────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────┐   │
│  │  PostgreSQL (40+ tables, RLS)                │   │
│  │  passports, receipts, policies, api_keys,    │   │
│  │  organizations, usage, webhooks ...          │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│  Python SDK (PyPI: agent-identity-bridge)           │
│  Local mode: passport, translate, DID, policies     │
│  Cloud mode: AIBCloud client → aib-tech.fr/api      │
└─────────────────────────────────────────────────────┘
```

## Testing

```bash
pytest tests/ -v
```

The test suite (`tests/test_core.py`, 25+ tests) covers:
- Passport CRUD (create, verify, revoke, list)
- Credential translation (A2A ↔ MCP round-trip)
- Audit trail (logging, tracing, query filters)
- Gateway (protocol detection, request adaptation)
- Schema validation
- Policy engine

## License

Apache 2.0
