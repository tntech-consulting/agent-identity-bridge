# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.13.x  | ✅ Current |
| < 2.13  | ❌ Unsupported |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Email: **thomas.nirennold@live.fr**

Include:
- Description of the vulnerability
- Steps to reproduce
- AIB version and Python version
- Impact assessment (what an attacker could do)

### Response timeline

- **Acknowledgment**: within 48 hours
- **Assessment**: within 1 week
- **Fix**: within 2 weeks for critical, 4 weeks for medium

### What counts as a security vulnerability

- Authentication bypass (forging passports without the secret key)
- Privilege escalation (child passport gaining parent capabilities)
- SSRF bypass (accessing internal networks through the gateway)
- Injection attacks (XSS, SQL injection via passport fields)
- Cryptographic weaknesses (predictable tokens, weak signing)
- Information disclosure (leaking private keys or PII)

### What does NOT count

- Denial of service via rate limiting exhaustion (by design)
- Missing features or documentation
- Bugs that don't have a security impact

## Security Audit

AIB has completed a 45/45 internal security audit covering:
- SSRF protection with DNS rebinding detection
- Input sanitization on all user-facing fields
- Rate limiting per passport tier
- JSON Schema validation on all translation inputs/outputs
- HMAC-SHA256 signed audit receipts
- PKCE for OIDC flows
- Signed CRL for revocation
- Crypto-shredding for GDPR compliance
