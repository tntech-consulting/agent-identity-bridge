# AIB Protocol Specification

**Version**: 2.15.0
**Status**: Draft
**Author**: Thomas Nirennold, TNTECH CONSULTING SAS
**Date**: 2026-03-28
**License**: Apache 2.0

---

## 1. Overview

The Agent Identity Bridge (AIB) protocol defines a portable identity format for AI agents operating across multiple communication protocols. It provides a single credential — the **Agent Passport** — that is valid across MCP (Model Context Protocol), A2A (Agent-to-Agent), ANP (Agent Network Protocol), and AG-UI (Agent-User Interaction).

### 1.1 Design goals

- **Portability**: One identity, all protocols.
- **Verifiability**: Every action produces a cryptographically signed receipt.
- **Policy enforcement**: Declarative rules evaluated before every action.
- **Federation**: Bring your own identity provider (OIDC).
- **Minimal footprint**: Zero external dependencies in the SDK.

### 1.2 Terminology

| Term | Definition |
|------|-----------|
| **Passport** | A structured credential identifying an AI agent across protocols. |
| **Receipt** | A signed record of an action (create, revoke, translate, etc.). |
| **Binding** | Protocol-specific authentication configuration within a passport. |
| **Capability** | A declared ability of an agent (e.g., `booking`, `support`). |
| **Policy rule** | A declarative constraint evaluated before an action is permitted. |
| **Tier** | The lifetime class of a passport: `permanent`, `session`, or `ephemeral`. |

---

## 2. Agent Passport Format

### 2.1 URN scheme

Agent passports use a hierarchical URN scheme:

```
urn:aib:agent:{org_slug}:{agent_slug}
```

- `org_slug`: lowercase alphanumeric organization identifier (2-64 chars, hyphens allowed).
- `agent_slug`: lowercase alphanumeric agent identifier (1-64 chars, hyphens and underscores allowed).

Organization issuers follow:

```
urn:aib:org:{org_slug}
```

### 2.2 Passport object

```json
{
  "passport_id": "urn:aib:agent:myorg:booking-bot",
  "display_name": "myorg/booking-bot",
  "issuer": "urn:aib:org:myorg",
  "capabilities": ["booking", "scheduling"],
  "protocols": ["mcp", "a2a"],
  "protocol_bindings": {
    "mcp": { "auth_method": "oauth2" },
    "a2a": { "auth_method": "bearer" }
  },
  "tier": "permanent",
  "status": "active",
  "version": 1,
  "issued_at": "2026-03-28T10:00:00Z",
  "expires_at": "2027-03-28T10:00:00Z",
  "metadata": {}
}
```

### 2.3 Required fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `passport_id` | string (URN) | Yes | Unique identifier following the URN scheme. |
| `display_name` | string | Yes | Human-readable name. |
| `issuer` | string (URN) | Yes | The issuing organization. |
| `capabilities` | string[] | Yes | Declared agent capabilities. |
| `protocols` | string[] | Yes | Supported protocols. Valid values: `mcp`, `a2a`, `anp`, `ag-ui`. |
| `protocol_bindings` | object | Yes | Per-protocol authentication configuration. |
| `tier` | string | Yes | `permanent` (up to 3650d), `session` (1-24h), `ephemeral` (≤5min). |
| `status` | string | Yes | `active`, `revoked`, or `expired`. |
| `version` | integer | Yes | Monotonically increasing version number. |
| `issued_at` | ISO 8601 | Yes | Creation timestamp. |
| `expires_at` | ISO 8601 | Yes | Expiration timestamp. |

### 2.4 Protocol bindings

Each entry in `protocol_bindings` maps a protocol name to its authentication configuration:

| Protocol | Auth methods | Binding fields |
|----------|-------------|----------------|
| `mcp` | `oauth2` | `auth_method` |
| `a2a` | `bearer` | `auth_method` |
| `anp` | `did-auth` | `auth_method`, `did` (DID Web URI) |
| `ag-ui` | `none` | `auth_method` |

### 2.5 Tiers

| Tier | Default TTL | Max TTL | Use case |
|------|-------------|---------|----------|
| `permanent` | 365 days | 3650 days | Long-lived service agents. |
| `session` | 1 hour | 24 hours | Task-scoped agents. |
| `ephemeral` | 5 minutes | 5 minutes | One-shot delegated actions. |

---

## 3. Credential Translation

AIB translates credentials between protocol formats in under 1ms.

### 3.1 Supported translation paths

| From | To | Supported |
|------|----|-----------|
| A2A Agent Card | MCP Server Card | Yes |
| MCP Server Card | A2A Agent Card | Yes |
| A2A Agent Card | AG-UI Descriptor | Yes |
| MCP Server Card | AG-UI Descriptor | Yes |
| AG-UI Descriptor | A2A Agent Card | Yes |
| AG-UI Descriptor | MCP Server Card | Yes |

### 3.2 Translation semantics

- `skills` (A2A) → `tools` (MCP): Each skill becomes a tool with an auto-generated `inputSchema`.
- `tools` (MCP) → `skills` (A2A): Each tool becomes a skill with `id` = tool name.
- `capabilities` (AG-UI) → `skills`/`tools`: Each capability string becomes a skill or tool.
- Metadata fields (`_aib_source`, `_aib_translated_at`) are added to mark translated credentials.

---

## 4. Audit Trail

### 4.1 Receipt format

Every action produces a receipt:

```json
{
  "passport_id": "urn:aib:agent:myorg:bot",
  "action": "create",
  "status": "success",
  "receipt_hash": "sha256hex...",
  "signature": "ed25519hex...",
  "signed_by": "publickeyhex...",
  "created_at": "2026-03-28T10:00:00Z"
}
```

### 4.2 Hash chain

Each receipt's `receipt_hash` is computed as:

```
SHA-256("{action}|{passport_id}|{timestamp}")
```

This creates a tamper-evident chain — modifying any receipt invalidates all subsequent hashes.

### 4.3 Ed25519 signatures

Receipts are signed using Ed25519 (RFC 8032). The signing key is generated per Edge Function instance. The public key is stored in `signed_by` for verification.

### 4.4 Denied actions

Policy violations also generate signed receipts with `status: "denied"`, `error_code: "POLICY_VIOLATION"`, and the violation details in `metadata.violations`.

---

## 5. Policy Engine

### 5.1 Rule types (12)

| # | Type | Description | Config example |
|---|------|-------------|----------------|
| 1 | `deliverable_gate` | Require capabilities before action. | `{"required_capabilities": ["tests_passed"], "action": "create"}` |
| 2 | `capability_required` | Agent must have specific capabilities. | `{"required": ["deploy"]}` |
| 3 | `separation_of_duties` | Block self-actions on resources you created. | `{"blocked_self_actions": ["revoke"], "strict": true}` |
| 4 | `protocol_restrict` | Block specific protocols. | `{"blocked_protocols": ["anp"]}` |
| 5 | `domain_block` | Block specific domains. | `{"blocked_domains": ["untrusted.com"]}` |
| 6 | `domain_allow` | Allow only specific domains. | `{"allowed_domains": ["trusted.com"]}` |
| 7 | `tier_restrict` | Restrict by passport tier. | `{"allowed_tiers": ["permanent"]}` |
| 8 | `time_restrict` | Time-based access control (UTC). | `{"allowed_hours": {"start": 8, "end": 18}}` |
| 9 | `action_block` | Block specific actions entirely. | `{"blocked_actions": ["revoke"]}` |
| 10 | `rate_limit` | Max actions per hour. | `{"max_per_hour": 100}` |
| 11 | `attestation_required` | Require Ed25519 signing for actions. | `{"actions": ["create", "revoke"]}` |
| 12 | `capability_limit` | Max capabilities per passport. | `{"max_capabilities": 10}` |

### 5.2 Severity levels

| Level | Behavior |
|-------|----------|
| `block` | Action is denied. Signed denial receipt emitted. |
| `warn` | Action proceeds. Violation recorded in receipt metadata. |
| `log` | Action proceeds. Violation counted in rule hits. |

### 5.3 Evaluation order

All active rules are evaluated for every action. If any `block`-severity rule produces a violation, the action is denied.

---

## 6. OIDC Federation

### 6.1 Overview

AIB accepts external OIDC tokens as authentication. An agent with an Okta, Entra, Auth0, or Google token can create a passport without an AIB account.

### 6.2 Verification flow

1. Extract JWT payload from Bearer token.
2. Look up `iss` (issuer) in `federation_trust` table.
3. Verify `exp` (expiration) is in the future.
4. Verify `aud` (audience) matches `expected_audience` if configured.
5. Fetch JWKS from the issuer's `jwks_uri`.
6. Verify JWT signature using RS256/RS384/RS512.
7. If valid, create passport linked to the OIDC subject.

### 6.3 Supported algorithms

RS256, RS384, RS512 (RSASSA-PKCS1-v1_5 with SHA-256/384/512).

### 6.4 JWKS caching

JWKS responses are cached in memory for 1 hour (3600000ms) per issuer URI.

---

## 7. Webhooks

### 7.1 Event types

| Event | Triggered by |
|-------|-------------|
| `passport.created` | Successful passport creation. |
| `passport.revoked` | Successful passport revocation. |
| `policy.violation` | Policy rule blocks an action. |
| `translate.completed` | Successful credential translation. |

### 7.2 Payload format

```json
{
  "event": "passport.created",
  "timestamp": "2026-03-28T10:00:00Z",
  "data": {
    "passport_id": "urn:aib:agent:myorg:bot",
    "protocols": ["mcp", "a2a"],
    "capabilities": ["booking"]
  }
}
```

### 7.3 Signature

When a webhook has a `secret` configured, the payload is signed with HMAC-SHA256. The signature is sent in the `X-AIB-Signature` header.

---

## 8. Authentication Methods

### 8.1 Priority order

1. **API Key** (`x-api-key` header) — SHA-256 hashed, looked up in `api_keys` table.
2. **Supabase Auth** (`Authorization: Bearer` header) — Supabase JWT token.
3. **OIDC Federation** (`Authorization: Bearer` header) — External OIDC JWT from a trusted issuer.

### 8.2 API key format

```
aib_sk_live_{random_32_chars}
```

Keys are stored as SHA-256 hashes. The raw key is shown once at generation and never stored.

---

## 9. Error Codes

| Code | HTTP | Description |
|------|------|-------------|
| AIB-001 | 400 | Invalid or missing request body. |
| AIB-002 | 400 | Invalid agent_slug format. |
| AIB-003 | 400 | No valid protocols specified. |
| AIB-101 | 401 | Unauthorized — invalid or missing credentials. |
| AIB-201 | 404 | Passport not found. |
| AIB-301 | 409 | Passport already exists (duplicate). |
| AIB-302 | 409 | Passport already revoked. |
| AIB-401 | 400 | Unsupported translation path. |
| AIB-501 | 500 | Internal server error. |
| AIB-601 | 403 | Policy violation (blocked). |
| AIB-602 | 403 | Separation of duties violation. |
| AIB-701 | 429 | Webhook quota exceeded. |

---

## 10. API Endpoints

Base URL: `https://{project}.supabase.co/functions/v1`

All responses include the header `X-AIB-Version: 2.15.1`.

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/auth` | None | Signup, login, generate API key. |
| POST | `/passport-create` | Required | Create agent passport. |
| GET | `/passport-list` | Required | List passports (paginated). |
| POST | `/passport-revoke` | Required | Revoke passport + cascade. |
| POST | `/translate` | Required | Translate credentials between formats. |
| GET | `/usage-check` | Required | Current usage and quotas. |
| GET | `/usage-history` | Required | Daily activity analytics. |
| GET/POST/DELETE | `/policy-manage` | Required | CRUD policy rules. |
| GET/POST/DELETE | `/webhook-manage` | Required | CRUD webhooks. |
| GET | `/did-resolve` | None | Resolve DID Document (W3C DID v1.1, did:web method). |

### 10.1 Versioning policy

The API follows semantic versioning. The `X-AIB-Version` response header indicates the current version. Breaking changes will increment the major version and be announced with at least 30 days notice.

### 10.2 DID Resolution

AIB passports can be resolved as W3C DID Documents using the `did:web` method.

#### DID format

```
did:web:aib-tech.fr:agents:{agent_slug}
```

#### Resolution endpoint

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/did-resolve?agent={slug}` | None | Resolve DID Document by agent slug. |
| GET | `/did-resolve?did={did}` | None | Resolve DID Document by full DID URI. |
| GET | `/did-resolve?agent={slug}&format=resolution` | None | Full DID Resolution result (v0.3 format). |

#### DID Document format

The returned DID Document follows W3C DID v1.1 (Candidate Recommendation 2026-03-05):

- `@context`: `["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"]`
- `verificationMethod`: `Ed25519VerificationKey2020` with `publicKeyMultibase` (z + base58btc encoded)
- `authentication` and `assertionMethod`: reference the verification key
- `service`: includes protocol-specific endpoints (MCPServer, A2AAgent)
- Content-Type: `application/did+json`

#### did:web resolution path

```
did:web:aib-tech.fr:agents:booking
→ https://aib-tech.fr/agents/booking/did.json
→ (proxied to) /functions/v1/did-resolve?agent=booking
```

---

*This specification is a living document. Contributions welcome at [github.com/tntech-consulting/agent-identity-bridge](https://github.com/tntech-consulting/agent-identity-bridge).*
