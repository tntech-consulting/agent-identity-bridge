# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.15.1] - 2026-03-29

### Security
- **AES-256 encryption** — private signing keys encrypted at rest via pgcrypto. Plaintext columns removed.
- **Rate limiting** — 30 req/min per IP via `check_rate_limit()` PostgreSQL function. Returns 429 with `retry_after_seconds`.
- **Auth failure logging** — `auth_failures` table records IP, method, error code, timestamp for every failed auth attempt.
- **SSRF protection** — webhook URLs validated: HTTPS only, RFC 1918 + loopback + link-local blocked.
- **RLS complete** — 17/17 tables with Row Level Security enabled, 21 policies total.
- **ed25519-keygen locked** — returns 401 without X-Admin-Key header. Cannot generate or read keys via public API.
- **4/5 old GitHub tokens revoked**.

### Added — Sprints 5-10
- **Sprint 5: did:key** — `public_key_to_did_key()`, `did_key_to_public_key_hex()`, `did_key_to_did_document()`. Edge Function `did-resolve` v3 handles both did:web and did:key resolution.
- **Sprint 6: Intent fields + EU AI Act** — 7 new columns on receipts (`intent`, `invocation_chain`, `data_accessed`, `risk_level`, `human_oversight`, `decision_rationale`, `affected_persons`). `passport-create` v14 accepts intent fields. New `audit-trail` endpoint with `?format=compliance` for Article 12 report.
- **Sprint 7: Intent Inference API** — `intent-analyze` endpoint. Dual mode: LLM (Claude Haiku) or rule-based fallback. Infers intent, assesses risk, detects anomalies, checks EU AI Act compliance.
- **Sprint 8: Verifiable Credentials** — `verifiable_credentials` + `vc_status_list` tables. `vc-issue` endpoint: POST issues W3C VC (Ed25519Signature2020 proof), GET verifies VC status (public).
- **Sprint 9: Ephemeral credentials** — `task_context`, `task_context_hash`, `single_use`, `used_at` columns on passports for context-bound credentials.
- **Sprint 10: Delegation chains** — `delegation_credentials` table. `parent_passport_id`, `delegation_depth`, `delegated_capabilities` on passports. `check_delegation_scope()` prevents privilege escalation.

### Added — Site
- **Why AIB page** (`/why`) — positioning, 3 pillars, is/isn't cards, comparison table, EU AI Act deep dive, partnerships. EN/FR.
- **EU AI Act Compliance Kit** (`/compliance`) — commercial landing page with countdown to August 2 2026, pricing (490€/990€/custom), terminal demos. EN/FR.
- **Roadmap page** (`/roadmap`) — 5 phases, all features marked DONE.
- **Quickstart** — executable `examples/quickstart.py`, 8 steps, 15 seconds, zero config.

### Changed
- `passport-create` v12 → v14: intent fields, rate limiting, auth failure logging, IP extraction
- `did-resolve` v1 → v3: did:key support, did:web `alsoKnownAs` field
- Edge Functions: 12 → 19 active
- API endpoints: 9 → 13
- SDK version: 2.13.4 → 2.15.1
- Real framework imports: `get_langchain_tools()`, `get_crewai_tools()`, `get_openai_agents_tools()`

## [2.15.0] - 2026-03-27

### Added
- **AIB Cloud SDK** (`aib/cloud.py`) — Python client wrapping all 12 Edge Functions
  - `AIBCloud` class: create_passport, list, revoke, translate, usage, policies, webhooks
  - `AIBCloud.signup()` / `AIBCloud.login()` classmethods for onboarding
  - `AIBCloudError` with code, status, violations for policy enforcement feedback
  - Zero external dependencies (stdlib urllib only)
  - 25 unit tests
- **Webhooks system** — real-time event notifications
  - `webhook-manage` Edge Function: CRUD webhooks (POST/GET/DELETE)
  - `passport-create` v5: fires webhooks on `passport.created` + `policy.violation`
  - HMAC-SHA256 signed payloads when secret is configured (X-AIB-Signature header)
  - 4 event types: passport.created, passport.revoked, policy.violation, translate.completed
  - Quota enforcement (max_webhooks per org)
- **OIDC Federation** in `passport-create` v4→v5
  - 3 auth methods: API key, Supabase Bearer, OIDC external JWT
  - JWKS cache (1h TTL), RS256/384/512 signature verification
  - `federation_trust` table seeded: Google (active), Entra (active), Okta, Auth0
  - 10-point OIDC test suite (`oidc-test` Edge Function) — 10/10 passing
- **Blog system** with auto-publish
  - `blog_posts` table: slug, title/content EN+FR, tags, SEO keywords, scheduled_for
  - `blog-api` Edge Function: serves articles, auto-publishes on schedule, view counting
  - `blog-scheduler` Edge Function: auto-generates new articles from topic pool
  - 5 articles published/scheduled + 8 articles in auto-schedule pool (13 total, ~3 months)
  - `pg_cron`: daily publish at 03:00 UTC, weekly scheduler check Monday 03:05 UTC
  - Full bilingual content EN/FR for SEO
- **Dashboard improvements**
  - Login auto-connects (no API key entry screen needed)
  - Policy form auto-fills config JSON based on rule type
  - Translate form validates same-format, auto-updates samples on format change
  - Generate Key instantly updates the active keys list
  - Chart.js CDN fixed (jsdelivr 4.4.4)
- **policy_rules CHECK constraint** updated to accept all 12 rule types

### Changed
- `passport-create` v3→v5: OIDC federation + webhooks + improved policy enforcement
- `blog-api` v1→v2: triggers blog-scheduler when no scheduled articles remain
- Total tests: 1056 → 1081 (25 new, 0 regressions)

## [2.14.0] - 2026-03-26

### Added
- **Framework integrations** — LangChain, CrewAI, OpenAI Agents SDK (native tools)
- **Cloud SaaS backend** — 8 Supabase Edge Functions, 9 PostgreSQL tables
- **Dashboard** — auth, 6 tabs (Overview, Analytics, Passports, Policies, Translate, API Keys)
- **Landing pages** — aib-cloud.netlify.app (SaaS), aib-tech.fr (protocol), pricing, frameworks
- **Ed25519 signed receipts** — cryptographic audit trail
- **Policy engine** — 12 rule types with deliverable gates and separation of duties
- GitHub push with cloud/ directory

## [2.13.4] - 2026-03-26

### Added
- `aib clean` command — shows full inventory of AIB data, asks confirmation, deletes
- `aib uninstall` command — full uninstall (data + pip package)
- Private keys flagged in red during clean inventory

## [2.13.3] - 2026-03-26

### Added
- `API_REFERENCE.md` — auto-generated from source code (26 modules, 967 lines)
- `docs/api/` — full HTML API reference (pdoc, 38 pages)
- `QUICKSTART.md` — 5-step quickstart for beta testers
- `.github/ISSUE_TEMPLATE/` — bug report + feature request templates
- `aib quickstart` CLI command — 6-check demo in 30 seconds

### Fixed
- Quickstart uses unique slug per run (UUID) — no longer fails on second run

## [2.13.1] - 2026-03-26

### Added
- `ERROR_CODES.md` — all 33 error codes with causes and fixes

### Fixed
- 3 unmapped exceptions in `diagnose_error()`: AudienceError, ProtocolAlreadyExistsError, ProtocolNotFoundError
- Error diagnostic coverage: 22/25 → 25/25 (100%)

## [2.13.0] - 2026-03-26

### Added
- **Policy engine** — 8 rule types: capability_required, capability_limit, protocol_restrict, domain_block, domain_allow, tier_restrict, action_block, time_restrict
- **Deliverable contracts** — verifiable completion criteria with auto-evaluation
- Policy evaluation <1ms (100 rules in <10ms)
- ContractManager with threshold, boolean, match, regex operators

## [2.12.0] - 2026-03-25

### Added
- **Protocol health monitoring** — per-endpoint status (healthy/degraded/down)
- Latency percentiles (p50, p95, p99)
- Status change alerts with callback

## [2.11.0] - 2026-03-25

### Added
- **Component diagnostics** — identifies failing components with suggestions
- **Federation trust scoring** — 0-100 score per org, 5 weighted factors, A-F grades

## [2.10.0] - 2026-03-25

### Added
- AG-UI wired into translator — 11 translation paths across 4 formats
- AG-UI ↔ A2A, AG-UI ↔ MCP, AG-UI ↔ DID complete

## [2.9.0] - 2026-03-25

### Added
- **Passport renewal** — hot-update capabilities, bindings, metadata without revocation
- Version history tracking
- TTL renewal without changing passport_id

## [2.8.0] - 2026-03-25

### Added
- **Webhook system** — pre-action (synchronous, blocking) + post-action (fire-and-forget)
- HMAC-SHA256 signed payloads
- Lifecycle events: passport_created, revoked, renewed

## [2.7.0] - 2026-03-25

### Added
- **TypeScript SDK** — client, translator, types (zero dependencies)
- 15 TypeScript tests

## [2.6.0] - 2026-03-25

### Added
- **AG-UI protocol binding** — 4th protocol complete
- AG-UI descriptor validation

## [2.5.0] - 2026-03-25

### Added
- Signed discovery documents
- PKCE (RFC 7636) for OIDC
- OpenTelemetry context propagation
- Shamir key ceremony (M-of-N secret splitting)

## [2.4.0] - 2026-03-25

### Added
- Circuit breaker (failure threshold, recovery timeout)
- ES256 + EdDSA multi-algorithm support
- Signed CRL (Certificate Revocation List)

## [1.5.0] - 2026-03-24

### Added
- FastAPI gateway server
- OIDC provider binding (Entra, Okta, Auth0, Keycloak)
- Federation discovery documents
- Protocol migration manager
- GDPR compliance (crypto-shredding, PII guard, consent manager)
- Rate limiting (per-tier)
- JSON Schema validation
- Multi-signature with timeout
- Federated JWKS cache
- Async receipt pipeline

## [1.0.0] - 2026-03-24

### Added
- Agent Passport — create, sign, verify, revoke
- Credential Translator — A2A ↔ MCP ↔ DID
- Gateway proxy — protocol detection, credential injection, SSRF protection
- Audit trail — receipts with SHA-256 hash chaining
- Merkle tree proofs
- RSA key management (RS256)
- Delegation chains with cascade revocation
- CLI (`aib create`, `aib translate`, `aib serve`)
- Docker support
