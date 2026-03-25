"""
AIB — Security Hardening Sprint 1.

Five quick wins from the Security Audit document:

1. OPT-ID-01:  Audience claim (aud) in passports — prevents cross-org replay
2. OPT-OIDC-03: Clock skew tolerance — prevents false rejections on clock drift
3. OPT-NET-04:  Double DNS resolution — closes TOCTOU/DNS rebinding
4. OPT-ID-03:   max_children per tier — prevents delegation bombing
5. OPT-OPS-04:  Standardized error codes — prevents internal info leakage

Each optimization is independent. None modifies existing modules —
they wrap or extend existing functions.
"""

import socket
import ipaddress
from typing import Optional
from dataclasses import dataclass, field


# ═══════════════════════════════════════════════════════════════════
# 1. OPT-ID-01 — AUDIENCE CLAIM (aud)
# ═══════════════════════════════════════════════════════════════════

class AudienceError(ValueError):
    """Raised when passport audience doesn't match expected domain."""
    pass


def inject_audience(payload: dict, audiences: list[str]) -> dict:
    """
    Inject audience claim into a passport payload before signing.

    Args:
        payload: The passport payload dict
        audiences: List of target domains/org URIs this passport is valid for
                   e.g. ["partner.com", "urn:aib:org:partner"]

    The 'aud' claim restricts WHERE this passport can be presented.
    A passport without aud is valid everywhere (backward compatible).
    A passport WITH aud is only valid at the listed audiences.
    """
    if not audiences:
        return payload
    # JWT spec: aud can be a string (single) or list (multiple)
    payload["aud"] = audiences if len(audiences) > 1 else audiences[0]
    return payload


def verify_audience(
    payload: dict,
    expected_audience: Optional[str] = None,
) -> tuple[bool, str]:
    """
    Verify the audience claim in a passport payload.

    Backward compatible:
    - If passport has no 'aud' claim → passes (old passports)
    - If passport has 'aud' but no expected_audience → passes
    - If passport has 'aud' AND expected_audience → must match

    Args:
        payload: Decoded passport payload
        expected_audience: The domain/URI of the verifying party

    Returns:
        (valid, reason)
    """
    aud = payload.get("aud")

    # No aud in passport → backward compatible, always valid
    if aud is None:
        return True, "No audience restriction (backward compatible)"

    # Passport has aud but verifier didn't specify expected → pass
    if expected_audience is None:
        return True, "Audience present but no expected audience specified"

    # Check match
    if isinstance(aud, str):
        audiences = [aud]
    elif isinstance(aud, list):
        audiences = aud
    else:
        return False, f"Invalid audience type: {type(aud).__name__}"

    if expected_audience in audiences:
        return True, f"Audience matches: {expected_audience}"

    return False, (
        f"Audience mismatch: passport is for {audiences}, "
        f"but presented to {expected_audience}"
    )


# ═══════════════════════════════════════════════════════════════════
# 2. OPT-OIDC-03 — CLOCK SKEW TOLERANCE
# ═══════════════════════════════════════════════════════════════════

# Default leeway for JWT time-based claims (exp, nbf, iat)
DEFAULT_CLOCK_SKEW_SECONDS = 30

def get_jwt_decode_options(
    leeway_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
    require_claims: Optional[list[str]] = None,
) -> dict:
    """
    Build JWT decode options with clock skew tolerance.

    Usage in PassportSigner.verify() or OIDCBridge.exchange():
        options = get_jwt_decode_options(leeway_seconds=30)
        payload = jwt.decode(token, key, algorithms=["RS256"],
                             options=options, leeway=leeway_seconds)

    Args:
        leeway_seconds: Clock skew tolerance in seconds (default 30)
        require_claims: Claims that must be present

    Returns:
        Dict of options for PyJWT's decode()
    """
    options = {
        "verify_exp": True,
        "verify_iat": True,
        "verify_nbf": True,
    }
    if require_claims:
        options["require"] = require_claims
    return options


# ═══════════════════════════════════════════════════════════════════
# 3. OPT-NET-04 — DOUBLE DNS RESOLUTION
# ═══════════════════════════════════════════════════════════════════

class DNSRebindingError(ValueError):
    """Raised when DNS rebinding is detected."""
    pass


def _resolve_ip(hostname: str) -> Optional[str]:
    """Resolve hostname to first IP address."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if results:
            return results[0][4][0]
    except socket.gaierror:
        pass
    return None


def _is_private(ip_str: str) -> bool:
    """Check if IP is private/reserved."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_reserved or addr.is_loopback or addr.is_link_local
    except ValueError:
        return True  # Can't parse → treat as unsafe


def double_dns_check(hostname: str) -> tuple[bool, str]:
    """
    Double DNS resolution to prevent TOCTOU/DNS rebinding.

    Resolves the hostname TWICE. If the IP changes between
    resolutions, or if either resolution hits a private IP,
    the check fails.

    This closes the attack where:
    1. First resolution → public IP (passes validation)
    2. Attacker changes DNS record
    3. Second resolution (actual fetch) → private IP (169.254.169.254)

    Returns:
        (is_safe, reason)
    """
    # First resolution
    ip1 = _resolve_ip(hostname)
    if ip1 is None:
        return False, f"Cannot resolve hostname: {hostname}"

    if _is_private(ip1):
        return False, f"First resolution to private IP: {ip1}"

    # Second resolution (catches rebinding)
    ip2 = _resolve_ip(hostname)
    if ip2 is None:
        return False, f"Second resolution failed for: {hostname}"

    if _is_private(ip2):
        return False, f"DNS rebinding detected: second resolution to private IP {ip2}"

    # IPs must match (prevents rebinding between two public IPs too,
    # which could be used for request smuggling)
    if ip1 != ip2:
        return False, (
            f"DNS rebinding detected: IP changed between resolutions "
            f"({ip1} → {ip2})"
        )

    return True, f"Safe: {hostname} → {ip1}"


# ═══════════════════════════════════════════════════════════════════
# 4. OPT-ID-03 — MAX CHILDREN PER TIER
# ═══════════════════════════════════════════════════════════════════

# Default limits on how many children a passport can delegate
DEFAULT_MAX_CHILDREN = {
    "permanent": 100,
    "session": 10,
    "ephemeral": 0,  # Ephemeral passports cannot delegate
}


class MaxChildrenExceededError(ValueError):
    """Raised when a passport exceeds its maximum children count."""
    pass


class ChildrenLimiter:
    """
    Tracks and enforces maximum children per passport.

    Usage:
        limiter = ChildrenLimiter()

        # Before creating a child passport:
        limiter.check_can_delegate(parent_id, parent_tier)  # raises if over limit

        # After creating:
        limiter.record_child(parent_id)

        # On revocation:
        limiter.remove_child(parent_id)  # optional, frees a slot
    """

    def __init__(self, limits: Optional[dict[str, int]] = None):
        self._limits = limits or dict(DEFAULT_MAX_CHILDREN)
        self._counts: dict[str, int] = {}  # parent_id → child count

    def check_can_delegate(self, parent_id: str, parent_tier: str) -> tuple[bool, str]:
        """
        Check if a parent passport can create another child.

        Returns:
            (allowed, reason)

        Raises:
            MaxChildrenExceededError if limit exceeded
        """
        limit = self._limits.get(parent_tier, 100)

        # Ephemeral = no delegation
        if limit == 0:
            raise MaxChildrenExceededError(
                f"{parent_tier} passports cannot delegate (max_children=0)"
            )

        current = self._counts.get(parent_id, 0)
        if current >= limit:
            raise MaxChildrenExceededError(
                f"Passport {parent_id} has reached max children "
                f"({current}/{limit}) for tier {parent_tier}"
            )

        return True, f"{current}/{limit} children used"

    def record_child(self, parent_id: str):
        """Record that a child was created."""
        self._counts[parent_id] = self._counts.get(parent_id, 0) + 1

    def remove_child(self, parent_id: str):
        """Remove a child (on revocation, frees a slot)."""
        if parent_id in self._counts and self._counts[parent_id] > 0:
            self._counts[parent_id] -= 1

    def get_count(self, parent_id: str) -> int:
        return self._counts.get(parent_id, 0)

    def get_limit(self, tier: str) -> int:
        return self._limits.get(tier, 100)

    def get_usage(self, parent_id: str, tier: str) -> dict:
        count = self._counts.get(parent_id, 0)
        limit = self._limits.get(tier, 100)
        return {
            "parent_id": parent_id,
            "tier": tier,
            "children": count,
            "limit": limit,
            "remaining": max(0, limit - count),
            "can_delegate": count < limit and limit > 0,
        }


# ═══════════════════════════════════════════════════════════════════
# 5. OPT-OPS-04 — STANDARDIZED ERROR CODES
# ═══════════════════════════════════════════════════════════════════

@dataclass
class AIBError:
    """
    Standardized error response.

    External (HTTP response): code + message (generic, safe)
    Internal (logs): code + message + detail (full context)

    The detail field NEVER appears in HTTP responses.
    """
    code: str           # e.g. "AIB-001"
    message: str        # Generic, safe for external display
    detail: str = ""    # Internal only, for logs
    http_status: int = 400

    def to_response(self) -> dict:
        """For HTTP response body (no detail leaked)."""
        return {
            "error": {
                "code": self.code,
                "message": self.message,
            }
        }

    def to_log(self) -> dict:
        """For internal structured logging (includes detail)."""
        return {
            "error_code": self.code,
            "message": self.message,
            "detail": self.detail,
            "http_status": self.http_status,
        }


# Error code registry
class ErrorCodes:
    """
    Centralized error code registry.

    Naming: AIB-{category}{number}
      Category 0xx: Authentication & identity
      Category 1xx: Authorization & capabilities
      Category 2xx: Translation & validation
      Category 3xx: Gateway & proxy
      Category 4xx: Audit & compliance
      Category 5xx: Federation & discovery
      Category 9xx: Internal / system
    """

    # ── Authentication & Identity ──
    PASSPORT_NOT_FOUND = AIBError("AIB-001", "Passport not found", http_status=404)
    PASSPORT_EXPIRED = AIBError("AIB-002", "Passport has expired", http_status=401)
    PASSPORT_REVOKED = AIBError("AIB-003", "Passport has been revoked", http_status=401)
    INVALID_SIGNATURE = AIBError("AIB-004", "Invalid passport signature", http_status=401)
    MISSING_CLAIM = AIBError("AIB-005", "Required claim missing from passport", http_status=400)
    AUDIENCE_MISMATCH = AIBError("AIB-006", "Passport audience does not match this service", http_status=403)
    INVALID_TOKEN = AIBError("AIB-007", "Token is malformed or cannot be decoded", http_status=400)

    # ── Authorization & Capabilities ──
    CAPABILITY_DENIED = AIBError("AIB-101", "Agent lacks the required capability", http_status=403)
    DELEGATION_DENIED = AIBError("AIB-102", "Delegation not allowed", http_status=403)
    TIER_VIOLATION = AIBError("AIB-103", "Passport tier cannot perform this action", http_status=403)
    MAX_CHILDREN = AIBError("AIB-104", "Maximum delegated passports reached", http_status=429)
    MAX_DEPTH = AIBError("AIB-105", "Maximum delegation depth reached", http_status=403)

    # ── Translation & Validation ──
    INVALID_FORMAT = AIBError("AIB-201", "Document format is invalid", http_status=400)
    SCHEMA_VIOLATION = AIBError("AIB-202", "Document does not match expected schema", http_status=400)
    TRANSLATION_ERROR = AIBError("AIB-203", "Translation between formats failed", http_status=400)
    OUTPUT_VALIDATION = AIBError("AIB-204", "Translated output failed security validation", http_status=400)
    SCOPE_ESCALATION = AIBError("AIB-205", "Potential privilege escalation detected", http_status=403)

    # ── Gateway & Proxy ──
    SSRF_BLOCKED = AIBError("AIB-301", "Request blocked by SSRF protection", http_status=403)
    DNS_REBINDING = AIBError("AIB-302", "DNS rebinding attack detected", http_status=403)
    RATE_LIMITED = AIBError("AIB-303", "Rate limit exceeded", http_status=429)
    GATEWAY_TIMEOUT = AIBError("AIB-304", "Target service did not respond in time", http_status=504)
    GATEWAY_ERROR = AIBError("AIB-305", "Error communicating with target service", http_status=502)
    PROTOCOL_UNKNOWN = AIBError("AIB-306", "Cannot detect target protocol", http_status=400)

    # ── Audit & Compliance ──
    RECEIPT_NOT_FOUND = AIBError("AIB-401", "Audit receipt not found", http_status=404)
    MERKLE_PROOF_INVALID = AIBError("AIB-402", "Merkle proof verification failed", http_status=400)
    CHAIN_TAMPERED = AIBError("AIB-403", "Audit chain integrity check failed", http_status=400)
    GDPR_SHREDDED = AIBError("AIB-404", "Data has been crypto-shredded (GDPR erasure)", http_status=410)

    # ── Federation & Discovery ──
    ISSUER_UNTRUSTED = AIBError("AIB-501", "Passport issuer is not trusted", http_status=403)
    FEDERATION_ERROR = AIBError("AIB-502", "Error fetching federation data", http_status=502)
    JWKS_UNAVAILABLE = AIBError("AIB-503", "Cannot retrieve signing keys for issuer", http_status=502)

    # ── Internal ──
    INTERNAL_ERROR = AIBError("AIB-901", "Internal server error", http_status=500)
    KEY_ROTATION_FAILED = AIBError("AIB-902", "Key rotation failed", http_status=500)
    STORAGE_ERROR = AIBError("AIB-903", "Storage backend error", http_status=500)


def make_error(
    template: AIBError,
    detail: str = "",
) -> AIBError:
    """
    Create an error instance from a template with specific detail.

    The detail is for internal logging only — it never reaches the client.

    Usage:
        err = make_error(
            ErrorCodes.PASSPORT_NOT_FOUND,
            detail=f"Looked up {passport_id} in PostgreSQL, table passports"
        )
        # Log: err.to_log()  → includes detail
        # HTTP: err.to_response()  → generic message only
    """
    return AIBError(
        code=template.code,
        message=template.message,
        detail=detail or template.detail,
        http_status=template.http_status,
    )
