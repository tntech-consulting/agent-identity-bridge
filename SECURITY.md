# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.15.x  | ✅ Current |
| 2.13.x  | ⚠️ Legacy (security fixes only) |
| < 2.13  | ❌ Unsupported |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Email: **thomas.nirennold@live.fr**

Subject: `[AIB SECURITY] <brief description>`

Include:
- Description of the vulnerability
- Steps to reproduce
- AIB version and Python version
- Impact assessment (what an attacker could do)
- Suggested fix (if any)

### Response timeline

- **Acknowledgment**: within 48 hours
- **Assessment**: within 1 week
- **Fix**: within 2 weeks for critical, 4 weeks for medium
- **Disclosure**: coordinated disclosure after fix is deployed

## Security Architecture

### Cryptography

- **Ed25519 (RFC 8032)**: All receipts are signed with persistent Ed25519 keys stored in PostgreSQL.
- **AES-256 encryption**: Private signing keys are encrypted at rest using pgcrypto. Plaintext columns removed.
- **SHA-256 hash chain**: Receipts form a tamper-evident chain. Each receipt references the previous hash.
- **Key rotation**: Supported via `key_id` column on receipts and `rotate_signing_key()` SQL function.
- **SECURITY DEFINER**: Private key decryption handled by `get_signing_private_key()` with restricted `search_path`.

### Authentication

Three authentication methods, all validated server-side:

1. **API Key** — SHA-256 hashed, stored in `api_keys` table
2. **Supabase JWT** — Bearer token, verified via `auth.getUser()`
3. **OIDC Federation** — RS256/384/512, JWKS verification, audience claim check, expiration check

All auth failures are logged in the `auth_failures` table with IP address, method, error code, and timestamp.

### Rate Limiting

- **HTTP rate limiting**: 30 requests/minute per IP on `passport-create` (returns 429)
- **Policy-based rate limiting**: configurable per org via `rate_limit` policy rule type
- **Sliding window**: PostgreSQL function `check_rate_limit()` with automatic cleanup

### Row Level Security (RLS)

All 17 tables have RLS enabled with 21 policies. No table is accessible without proper authorization.

### SSRF Protection

Webhook URLs validated in `webhook-manage`:
- HTTPS only (HTTP rejected)
- Blocked: RFC 1918 (10.x, 172.16-31.x, 192.168.x), loopback (127.x, localhost, 0.x), link-local (169.254.x), IPv6 loopback

### Input Validation

- Agent slugs: regex validated, 2-64 chars lowercase alphanumeric
- Protocols: allowlist (mcp, a2a, anp, ag-ui, acp, slim, agora)
- Risk levels: allowlist (low, medium, high, critical)
- Capabilities: max 50 per passport
- TTL: clamped 1-3650 days
- Intent text: truncated 500 chars
- Decision rationale: truncated 1000 chars
- Webhook secret: truncated 256 chars, never returned in responses

### Delegation Security

- `check_delegation_scope()` prevents privilege escalation (child caps must be subset of parent)
- `delegation_depth` tracked on passports

### Edge Function Security

- `ed25519-keygen` locked: returns 401 without X-Admin-Key header
- All functions validate Content-Type, method, and required fields before processing

## What Counts as a Security Vulnerability

- Authentication bypass (forging passports without valid credentials)
- Privilege escalation (child passport gaining parent capabilities)
- SSRF bypass (accessing internal networks through webhooks)
- Injection attacks (XSS, SQL injection via passport fields)
- Cryptographic weaknesses (predictable tokens, weak signing, key leakage)
- Information disclosure (leaking private keys, PII, or internal state)
- Rate limit bypass (circumventing the 30/min IP limit)
- RLS bypass (accessing data across organizations)

## What Does NOT Count

- Denial of service via legitimate rate limit exhaustion
- Missing features or documentation
- Bugs without security impact
- Self-signed certificates in development environments

## Compliance

AIB receipts support EU AI Act Article 12 record-keeping with 7 structured fields:
`intent`, `invocation_chain`, `data_accessed`, `risk_level`, `human_oversight`, `decision_rationale`, `affected_persons`

All fields are signed in the Ed25519 receipt and queryable via the `audit-trail` API.

## Contact

- **Security reports**: thomas.nirennold@live.fr
- **General**: https://github.com/tntech-consulting/agent-identity-bridge/issues
- **Organization**: TNTECH CONSULTING SAS, Paris, France
