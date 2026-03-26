# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
