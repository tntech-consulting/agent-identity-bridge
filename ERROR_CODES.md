# AIB Error Codes Reference

All error codes returned by the AIB gateway, SDK, and CLI. Each code maps to an HTTP status, a human-readable message, and a fix suggestion.

## Quick lookup

| Code | HTTP | What it means |
|------|------|---------------|
| AIB-001 | 404 | Passport not found |
| AIB-002 | 401 | Passport expired |
| AIB-003 | 401 | Passport revoked |
| AIB-004 | 401 | Invalid signature |
| AIB-005 | 400 | Missing required claim |
| AIB-006 | 403 | Audience mismatch |
| AIB-007 | 400 | Malformed token |
| AIB-101 | 403 | Missing capability |
| AIB-102 | 403 | Delegation denied |
| AIB-103 | 403 | Tier violation |
| AIB-104 | 429 | Max children reached |
| AIB-105 | 403 | Max delegation depth |
| AIB-201 | 400 | Invalid document format |
| AIB-202 | 400 | Schema violation |
| AIB-203 | 400 | Translation failed |
| AIB-204 | 400 | Output validation failed |
| AIB-205 | 403 | Privilege escalation |
| AIB-301 | 403 | SSRF blocked |
| AIB-302 | 403 | DNS rebinding detected |
| AIB-303 | 429 | Rate limit exceeded |
| AIB-304 | 504 | Gateway timeout |
| AIB-305 | 502 | Gateway error |
| AIB-306 | 400 | Unknown protocol |
| AIB-401 | 404 | Receipt not found |
| AIB-402 | 400 | Merkle proof invalid |
| AIB-403 | 400 | Audit chain tampered |
| AIB-404 | 410 | Data crypto-shredded |
| AIB-501 | 403 | Issuer not trusted |
| AIB-502 | 502 | Federation fetch error |
| AIB-503 | 502 | JWKS unavailable |
| AIB-601 | 403 | Policy violation |
| AIB-701 | 429 | Webhook limit reached |
| AIB-702 | 400 | Invalid webhook URL (SSRF) |
| AIB-429 | 429 | HTTP rate limit exceeded (30/min per IP) |
| AIB-901 | 500 | Internal error |
| AIB-902 | 500 | Key rotation failed |
| AIB-903 | 500 | Storage error |

---

## Category 0xx — Passport & Identity

Errors related to passport creation, verification, and token handling.

### AIB-001 — Passport not found

**HTTP 404** · Component: `passport`

The passport_id does not exist in the store.

**Common causes:**
- Typo in passport_id (check `urn:aib:agent:{org}:{slug}` format)
- Passport was never created
- Passport was created on a different gateway instance (no shared storage)

**Fix:**
```python
# List all passports to find the correct ID
svc.list_passports()
```

---

### AIB-002 — Passport expired

**HTTP 401** · Component: `passport`

The passport token's `expires_at` timestamp is in the past.

**Common causes:**
- Ephemeral passport (5 min TTL) used after expiry
- Session passport (4h TTL) not renewed
- Clock skew between gateway and client (>5 seconds)

**Fix:**
```python
# Renew the passport
from aib.renewal import PassportRenewalManager
mgr = PassportRenewalManager()
mgr.renew(passport_id, ttl_days=365)
```

---

### AIB-003 — Passport revoked

**HTTP 401** · Component: `passport`

The passport was explicitly revoked. Revocation is permanent — this passport_id cannot be un-revoked.

**Common causes:**
- Key compromise → admin revoked the passport
- Parent passport revoked → cascade revocation to children
- Agent decommissioned

**Fix:**
```python
# Create a new passport (new passport_id)
svc.create_passport(org_slug="...", agent_slug="new-slug", ...)
```

---

### AIB-004 — Invalid signature

**HTTP 401** · Component: `crypto`

The HMAC/JWS signature on the token does not match. The token has been tampered with or signed by a different key.

**Common causes:**
- Token modified after signing
- Wrong `secret_key` used for verification
- Token from a different gateway instance

**Fix:**
- Verify the `secret_key` matches between creation and verification
- Re-create the passport with the correct key

---

### AIB-005 — Missing required claim

**HTTP 400** · Component: `passport`

The token payload is missing a field that AIB requires (e.g., `passport_id`, `issuer`, `capabilities`).

**Common causes:**
- Manually constructed token without required fields
- Corrupted token payload

**Fix:**
- Use `PassportService.create_passport()` instead of manual token construction
- Inspect the token payload: `base64.urlsafe_b64decode(token.split(".")[1] + "==")`

---

### AIB-006 — Audience mismatch

**HTTP 403** · Component: `passport`

The passport's `aud` (audience) claim does not match the service verifying it. The passport was issued for a different service.

**Common causes:**
- Passport created with `aud="https://service-a.com"` but verified by `service-b.com`
- Multi-tenant deployment with wrong audience configuration

**Fix:**
- Create a passport with the correct audience for the target service
- Check the `aud` claim in the token payload

---

### AIB-007 — Malformed token

**HTTP 400** · Component: `passport`

The token cannot be decoded. It does not have the expected `header.payload.signature` format.

**Common causes:**
- Truncated token (copy-paste error)
- Wrong encoding (not base64url)
- Not a JWS token at all

**Fix:**
- Check that the token has exactly 2 dots: `header.payload.signature`
- Re-create the passport to get a fresh token

---

## Category 1xx — Authorization & Capabilities

Errors related to what an agent is allowed to do.

### AIB-101 — Capability denied

**HTTP 403** · Component: `lifecycle`

The agent's passport does not include the required capability for this action.

**Common causes:**
- Passport has `["booking"]` but action requires `"payment"`
- Child passport was delegated with a capability subset that excludes this action

**Fix:**
```python
# Add the capability via renewal (no revocation needed)
mgr.update_capabilities(passport_id, add=["payment"])
```

---

### AIB-102 — Delegation denied

**HTTP 403** · Component: `lifecycle`

The parent passport cannot delegate to a child. Either the parent is revoked, the parent doesn't have delegation rights, or the delegation parameters are invalid.

**Fix:**
- Check that the parent passport is not revoked
- Check that the parent passport's tier allows delegation (ephemeral cannot delegate)

---

### AIB-103 — Tier violation

**HTTP 403** · Component: `lifecycle`

The passport's tier (permanent/session/ephemeral) cannot perform this action.

**Common causes:**
- Ephemeral passport trying to delegate
- Session passport trying to create a permanent child

**Fix:**
- Use a higher tier for this action
- Check the policy engine tier rules

---

### AIB-104 — Max children reached

**HTTP 429** · Component: `lifecycle`

The parent passport has reached the maximum number of delegated child passports.

**Fix:**
- Revoke unused child passports
- Increase `max_children` on the parent (default: 10)

---

### AIB-105 — Max delegation depth

**HTTP 403** · Component: `lifecycle`

The delegation chain is too deep. An agent cannot delegate beyond `max_depth` levels (default: 3).

**Fix:**
- Flatten the delegation chain
- Increase `max_depth` if legitimate (not recommended beyond 5)

---

## Category 2xx — Translation & Validation

Errors related to format translation and document validation.

### AIB-201 — Invalid document format

**HTTP 400** · Component: `translator`

The source document cannot be parsed or is not a valid JSON object.

**Fix:**
- Validate the source document is valid JSON
- Check the `from_format` parameter matches the actual document structure

---

### AIB-202 — Schema violation

**HTTP 400** · Component: `schema_validator`

The document does not match the expected JSON Schema for its format.

**Common causes:**
- A2A Agent Card missing `skills` array
- MCP Server Card missing `tools` array
- AG-UI descriptor missing `endpoint_url`

**Fix:**
```python
from aib.ag_ui_binding import validate_ag_ui_descriptor
errors = validate_ag_ui_descriptor(my_descriptor)
print(errors)  # List of what's wrong
```

---

### AIB-203 — Translation failed

**HTTP 400** · Component: `translator`

The translation between formats failed. The source document structure is unexpected.

**Fix:**
- Check `translator.translate()` supported paths (11 paths available)
- Verify the source document has the expected fields for its format

---

### AIB-204 — Output validation failed

**HTTP 400** · Component: `translator`

The translated output failed post-translation security validation.

**Fix:**
- Check for script injection or HTML in translated fields
- Review the source document for malicious content

---

### AIB-205 — Privilege escalation detected

**HTTP 403** · Component: `lifecycle`

A translation or delegation attempted to grant more capabilities than the source has.

**Fix:**
- Capabilities in child passports must be a subset of the parent's
- DID Document capabilities cannot exceed the source Agent Card's skills

---

## Category 3xx — Gateway & Proxy

Errors related to proxying requests through the gateway.

### AIB-301 — SSRF blocked

**HTTP 403** · Component: `gateway`

The target URL resolves to a private/internal IP address. This is blocked to prevent Server-Side Request Forgery attacks.

**Blocked ranges:** `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`

**Fix:**
- Use a public URL for the target service
- If the target is intentionally internal, configure an SSRF allowlist

---

### AIB-302 — DNS rebinding detected

**HTTP 403** · Component: `gateway`

The target hostname resolved to different IP addresses on consecutive lookups. This is a DNS rebinding attack indicator.

**Fix:**
- Verify the target hostname has a stable DNS record
- Check for DNS-based load balancing that might trigger false positives

---

### AIB-303 — Rate limit exceeded

**HTTP 429** · Component: `rate_limiter`

Too many requests from this passport in the current time window.

**Default limits:**
- Permanent: 1000 req/hour
- Session: 100 req/hour
- Ephemeral: 10 req/hour

**Fix:**
- Wait for the rate limit window to reset (check `Retry-After` header)
- Use a higher-tier passport for more throughput

---

### AIB-304 — Gateway timeout

**HTTP 504** · Component: `gateway`

The target service did not respond within the timeout (default: 30 seconds).

**Fix:**
- Check if the target service is running
- Increase the gateway timeout if the target is legitimately slow
- Check `ProtocolHealthMonitor` for the endpoint's status

---

### AIB-305 — Gateway error

**HTTP 502** · Component: `gateway`

The gateway could not communicate with the target service.

**Common causes:**
- Target service is down
- Network connectivity issues
- SSL/TLS certificate errors

**Fix:**
- Check `monitor.get_endpoint(target_url)` for status and error details
- Check if the circuit breaker is open for this target

---

### AIB-306 — Unknown protocol

**HTTP 400** · Component: `gateway`

The gateway cannot determine which protocol to use for the target URL.

**Fix:**
- Verify the passport has a protocol binding whose URL matches the target
- Use `detect_protocol()` to debug: `gateway.detect_protocol(url, passport.protocol_bindings)`

---

## Category 4xx — Audit & Compliance

Errors related to audit trail, receipts, and data governance.

### AIB-401 — Receipt not found

**HTTP 404** · Component: `receipts`

The requested audit receipt does not exist.

**Fix:**
- Check the receipt_id format
- Receipts are generated automatically on each gateway action — if missing, the action may not have been logged

---

### AIB-402 — Merkle proof invalid

**HTTP 400** · Component: `merkle`

The Merkle proof for a receipt does not verify against the tree root.

**Common causes:**
- Receipt was modified after proof generation
- Merkle tree was rebuilt (root changed)

**Fix:**
- Regenerate the proof from the current Merkle tree
- Verify the receipt hash hasn't been modified

---

### AIB-403 — Audit chain tampered

**HTTP 400** · Component: `receipts`

The hash chain linking receipts has been broken. A receipt was inserted, deleted, or modified.

**Fix:**
- This is a serious integrity violation — investigate which receipt was altered
- Restore from backup if available

---

### AIB-404 — Data crypto-shredded

**HTTP 410** · Component: `gdpr`

The requested data has been permanently erased via GDPR crypto-shredding. The encryption key was destroyed, making the data unrecoverable.

**Fix:**
- This is permanent and by design (GDPR Art. 17 compliance)
- No recovery possible — the data is gone

---

## Category 5xx — Federation & Discovery

Errors related to cross-organization trust.

### AIB-501 — Issuer not trusted

**HTTP 403** · Component: `federation`

The passport was signed by an issuer that is not in the federation trust list.

**Fix:**
```python
from aib.discovery import FederationDocument, FederationTrust

federation.add_trust(FederationTrust(
    domain="partner.com",
    issuer="urn:aib:org:partner",
    jwks_uri="https://partner.com/.well-known/aib-keys.json",
))
```

---

### AIB-502 — Federation fetch error

**HTTP 502** · Component: `federation`

Failed to retrieve federation data (discovery document or CRL) from a trusted partner.

**Fix:**
- Check network connectivity to the partner's domain
- Verify the partner's `/.well-known/aib.json` is accessible
- Check `ProtocolHealthMonitor` for the federation endpoint's status

---

### AIB-503 — JWKS unavailable

**HTTP 502** · Component: `federation`

Cannot retrieve the signing keys (JWKS) for a federated issuer.

**Fix:**
- Check the `jwks_uri` in the federation trust config
- Verify the partner's `/.well-known/aib-keys.json` returns valid JSON
- Check `FederationTrustScorer` for the partner's reliability score

---

## Category 9xx — Internal

Errors that indicate an AIB system failure.

### AIB-901 — Internal server error

**HTTP 500** · Component: `gateway`

An unexpected error occurred inside the AIB gateway.

**Fix:**
- Check gateway logs for the full traceback
- Use `diagnose_error(exception)` to identify the failing component
- Report the issue on GitHub with the traceback

---

### AIB-902 — Key rotation failed

**HTTP 500** · Component: `crypto`

Automatic key rotation could not complete. The signing keys may be stale.

**Fix:**
- Check file system permissions on the key store
- Manually trigger key rotation: `crypto.rotate_keys()`
- Verify the Shamir key ceremony completed if using split keys

---

### AIB-903 — Storage backend error

**HTTP 500** · Component: `passport`

The passport storage backend (file system or database) is unavailable.

**Fix:**
- Check disk space and file permissions on `./passports/`
- If using PostgreSQL: check connection string and database status

---

## Exception → Component mapping

When an exception occurs, `diagnose_error()` identifies which AIB component is responsible.

| Exception | Component | Suggestion |
|-----------|-----------|------------|
| `URLValidationError` | gateway | Check target URL format and SSRF rules |
| `InputValidationError` | gateway | Validate input data format |
| `DNSRebindingError` | gateway | Target host DNS is inconsistent |
| `SchemaValidationError` | schema_validator | Check document against JSON Schema |
| `AudienceError` | passport | Passport audience doesn't match this service |
| `DelegationError` | lifecycle | Check delegation rules and parent passport |
| `CapabilityEscalationError` | lifecycle | Cannot add capabilities beyond parent scope |
| `TierViolationError` | lifecycle | Check tier delegation rules |
| `MaxDepthExceededError` | lifecycle | Delegation chain too deep |
| `MaxChildrenExceededError` | lifecycle | Reduce delegation count or increase limit |
| `PassportNotFoundError` | passport | Verify passport_id exists |
| `PassportRevokedError` | passport | Passport was revoked — create a new one |
| `MigrationError` | migration | Check protocol migration parameters |
| `ProtocolAlreadyExistsError` | migration | Protocol already added to this passport |
| `ProtocolNotFoundError` | migration | Protocol not found in passport bindings |
| `RenewalError` | renewal | Check renewal parameters |
| `PIIViolationError` | gdpr | Input contains PII that must be encrypted |
| `ShredError` | gdpr | Crypto-shredding failed — check key store |
| `SignatureTimeoutError` | crypto | Multi-sig request expired — start a new one |
| `SignedDocumentError` | federation | Discovery document signature invalid |
| `IssuerValidationError` | federation | Passport issuer not trusted |
| `CircuitBreakerError` | circuit_breaker | Target service is down — circuit open |
| `WebhookDeniedError` | webhooks | External policy check denied the request |
| `OutputValidationError` | translator | Translated output failed validation |
| `OIDCDevGuardError` | oidc | OIDC dev mode not allowed in production |

### Using diagnose_error()

```python
from aib.diagnostics import diagnose_error

try:
    result = gateway.proxy_request(...)
except Exception as e:
    diag = diagnose_error(e)
    print(f"[{diag.component.upper()}] {diag.message}")
    print(f"Fix: {diag.suggestion}")
    # Output: [GATEWAY] URLValidationError: SSRF blocked — 10.0.0.1
    # Fix: Check target URL format and SSRF rules
```
