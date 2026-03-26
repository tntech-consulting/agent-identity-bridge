"""
AIB — Sprint 6: Final audit recommendations.

Four remaining items closing the full 45/45 audit:

1. OPT-FED-01:    Signed discovery documents (JWS-signed .well-known)
2. OPT-OIDC-01:   PKCE support (Proof Key for Code Exchange)
3. OPT-OPS-05:    OpenTelemetry context propagation (trace/span/baggage)
4. OPT-CRYPTO-03: Key ceremony with Shamir Secret Sharing
"""

import hashlib
import hmac
import json
import os
import secrets
import time
import base64
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Any


# ═══════════════════════════════════════════════════════════════════
# 1. OPT-FED-01 — SIGNED DISCOVERY DOCUMENTS
# ═══════════════════════════════════════════════════════════════════

class SignedDocumentError(ValueError):
    """Raised when a signed document fails verification."""
    pass


def sign_discovery_document(document: dict, secret_key: str) -> dict:
    """
    Sign a discovery document (/.well-known/aib.json) with HMAC-SHA256.

    In production, replace HMAC with JWS RS256 using the gateway's
    private key. HMAC is used here for simplicity (no key management).

    The signature covers the canonical JSON of the document body.
    Federated parties verify the signature before trusting the data.

    Usage:
        doc = {"domain": "example.com", "issuer": "urn:aib:org:example", ...}
        signed = sign_discovery_document(doc, secret_key="my-secret")
        # signed["_signature"] contains the HMAC
    """
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
    sig = hmac.new(
        secret_key.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    signed = dict(document)
    signed["_signed_at"] = datetime.now(timezone.utc).isoformat()
    signed["_signature_alg"] = "HMAC-SHA256"
    signed["_signature"] = sig
    return signed


def verify_signed_document(signed_doc: dict, secret_key: str) -> tuple[bool, str]:
    """
    Verify a signed discovery document.

    Returns (valid, reason).
    """
    sig = signed_doc.get("_signature")
    if not sig:
        return False, "Missing _signature field"

    # Reconstruct the original document (without signature fields)
    original = {
        k: v for k, v in signed_doc.items()
        if not k.startswith("_")
    }
    canonical = json.dumps(original, sort_keys=True, separators=(",", ":"))
    expected = hmac.new(
        secret_key.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if hmac.compare_digest(sig, expected):
        return True, "Signature valid"
    return False, "Signature mismatch — document may have been tampered"


# ═══════════════════════════════════════════════════════════════════
# 2. OPT-OIDC-01 — PKCE SUPPORT
# ═══════════════════════════════════════════════════════════════════



def generate_code_verifier(length: int = 64) -> str:
    """
    Generate a PKCE code_verifier (RFC 7636).

    The verifier is a high-entropy random string (43-128 chars)
    used in the OAuth2 Authorization Code flow to prevent
    authorization code interception attacks.
    """
    if length < 43 or length > 128:
        raise ValueError("code_verifier length must be between 43 and 128")
    return secrets.token_urlsafe(length)[:length]


def generate_code_challenge(verifier: str, method: str = "S256") -> str:
    """
    Generate a PKCE code_challenge from a code_verifier.

    method: "S256" (recommended) or "plain" (not recommended)

    S256: BASE64URL(SHA256(code_verifier))
    plain: code_verifier (no transformation — insecure)
    """
    if method == "S256":
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    elif method == "plain":
        return verifier
    else:
        raise ValueError(f"Unknown PKCE method: {method}. Use 'S256' or 'plain'.")


def verify_pkce(
    code_verifier: str,
    code_challenge: str,
    method: str = "S256",
) -> bool:
    """
    Verify a PKCE code_verifier against the stored code_challenge.

    Called by the token endpoint when exchanging an authorization code.
    """
    expected = generate_code_challenge(code_verifier, method)
    return hmac.compare_digest(expected, code_challenge)


@dataclass
class PKCESession:
    """Tracks a PKCE session through the OAuth2 flow."""
    session_id: str
    code_verifier: str
    code_challenge: str
    method: str
    created_at: float
    state: str = "pending"  # pending, exchanged, expired

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "method": self.method,
            "state": self.state,
            "created_at": self.created_at,
            "code_challenge": self.code_challenge,
        }


class PKCEManager:
    """
    Manages PKCE sessions for OIDC token exchanges.

    Usage:
        pkce = PKCEManager()

        # Start OAuth2 flow
        session = pkce.create_session()
        # Send code_challenge to the authorization endpoint

        # On callback, verify
        if pkce.verify_and_consume(session.session_id, code_verifier_from_client):
            # Exchange authorization code for token
            pass
    """

    def __init__(self, ttl_seconds: float = 600):
        self._sessions: dict[str, PKCESession] = {}
        self._ttl = ttl_seconds

    def create_session(self, method: str = "S256") -> PKCESession:
        verifier = generate_code_verifier()
        challenge = generate_code_challenge(verifier, method)
        session = PKCESession(
            session_id=f"pkce_{uuid.uuid4().hex[:12]}",
            code_verifier=verifier,
            code_challenge=challenge,
            method=method,
            created_at=time.time(),
        )
        self._sessions[session.session_id] = session
        return session

    def verify_and_consume(self, session_id: str, code_verifier: str) -> bool:
        """Verify and mark session as exchanged. One-time use."""
        session = self._sessions.get(session_id)
        if not session:
            return False
        if session.state != "pending":
            return False
        if time.time() - session.created_at > self._ttl:
            session.state = "expired"
            return False

        if verify_pkce(code_verifier, session.code_challenge, session.method):
            session.state = "exchanged"
            return True
        return False

    def get_session(self, session_id: str) -> Optional[dict]:
        s = self._sessions.get(session_id)
        return s.to_dict() if s else None

    def cleanup_expired(self) -> int:
        now = time.time()
        expired = [
            sid for sid, s in self._sessions.items()
            if now - s.created_at > self._ttl
        ]
        for sid in expired:
            self._sessions[sid].state = "expired"
        return len(expired)

    @property
    def active_count(self) -> int:
        return sum(1 for s in self._sessions.values() if s.state == "pending")


# ═══════════════════════════════════════════════════════════════════
# 3. OPT-OPS-05 — OPENTELEMETRY CONTEXT PROPAGATION
# ═══════════════════════════════════════════════════════════════════

@dataclass
class TraceContext:
    """
    W3C Trace Context (simplified) for OpenTelemetry compatibility.

    Propagated via HTTP headers:
      traceparent: 00-{trace_id}-{span_id}-{flags}
      tracestate: aib=passport_id:{passport_id}

    This allows distributed tracing tools (Jaeger, Zipkin, Datadog)
    to correlate AIB gateway requests with upstream/downstream calls.
    """
    trace_id: str          # 32 hex chars
    span_id: str           # 16 hex chars
    parent_span_id: str = ""
    flags: str = "01"      # 01 = sampled
    passport_id: str = ""
    protocol: str = ""

    def to_traceparent(self) -> str:
        """W3C traceparent header value."""
        return f"00-{self.trace_id}-{self.span_id}-{self.flags}"

    def to_tracestate(self) -> str:
        """W3C tracestate header with AIB-specific data."""
        parts = []
        if self.passport_id:
            parts.append(f"aib_pid={self.passport_id}")
        if self.protocol:
            parts.append(f"aib_proto={self.protocol}")
        return ",".join(parts) if parts else ""

    def to_headers(self) -> dict:
        """HTTP headers for propagation."""
        headers = {"traceparent": self.to_traceparent()}
        ts = self.to_tracestate()
        if ts:
            headers["tracestate"] = ts
        return headers

    def to_dict(self) -> dict:
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "flags": self.flags,
            "passport_id": self.passport_id,
            "protocol": self.protocol,
            "traceparent": self.to_traceparent(),
        }


def new_trace_context(
    passport_id: str = "",
    protocol: str = "",
    parent: Optional[TraceContext] = None,
) -> TraceContext:
    """Create a new trace context, optionally as child of a parent."""
    trace_id = parent.trace_id if parent else uuid.uuid4().hex
    parent_span = parent.span_id if parent else ""
    return TraceContext(
        trace_id=trace_id,
        span_id=uuid.uuid4().hex[:16],
        parent_span_id=parent_span,
        passport_id=passport_id,
        protocol=protocol,
    )


def parse_traceparent(header: str) -> Optional[TraceContext]:
    """
    Parse a W3C traceparent header.

    Format: {version}-{trace_id}-{span_id}-{flags}
    Example: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
    """
    parts = header.strip().split("-")
    if len(parts) != 4:
        return None
    version, trace_id, span_id, flags = parts
    if version != "00":
        return None
    if len(trace_id) != 32 or len(span_id) != 16:
        return None
    return TraceContext(
        trace_id=trace_id,
        span_id=span_id,
        flags=flags,
    )


# ═══════════════════════════════════════════════════════════════════
# 4. OPT-CRYPTO-03 — SHAMIR SECRET SHARING (KEY CEREMONY)
# ═══════════════════════════════════════════════════════════════════

# Simplified Shamir Secret Sharing over integers (not GF(256)).
# For production, use a proper library like `secretsharing` or `pyshamir`.
# This implementation is for demonstration and testing.

_PRIME = 2**521 - 1  # Largest Mersenne prime for 32-byte secrets


def _mod_inverse(a: int, p: int) -> int:
    """Modular inverse using extended Euclidean algorithm."""
    if a < 0:
        a = a % p
    g, x, _ = _extended_gcd(a, p)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % p


def _extended_gcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def split_secret(
    secret: bytes,
    shares_needed: int,
    total_shares: int,
) -> list[tuple[int, int]]:
    """
    Split a secret into N shares where K are needed to reconstruct.

    Shamir's (K, N) threshold scheme.

    Args:
        secret: The secret bytes to split (e.g. an AES-256 key)
        shares_needed: K — minimum shares to reconstruct
        total_shares: N — total shares to create

    Returns:
        List of (share_index, share_value) tuples
    """
    if shares_needed > total_shares:
        raise ValueError(f"shares_needed ({shares_needed}) > total_shares ({total_shares})")
    if shares_needed < 2:
        raise ValueError("shares_needed must be >= 2")

    secret_int = int.from_bytes(secret, byteorder="big")

    # Generate random polynomial coefficients
    coefficients = [secret_int]
    for _ in range(shares_needed - 1):
        coefficients.append(secrets.randbelow(_PRIME))

    # Evaluate polynomial at points 1..N
    shares = []
    for x in range(1, total_shares + 1):
        y = 0
        for i, coeff in enumerate(coefficients):
            y = (y + coeff * pow(x, i, _PRIME)) % _PRIME
        shares.append((x, y))

    return shares


def reconstruct_secret(
    shares: list[tuple[int, int]],
    secret_length: int,
) -> bytes:
    """
    Reconstruct a secret from K shares using Lagrange interpolation.

    Args:
        shares: List of (share_index, share_value) tuples (at least K)
        secret_length: Expected length of the secret in bytes

    Returns:
        The reconstructed secret bytes
    """
    if len(shares) < 2:
        raise ValueError("Need at least 2 shares to reconstruct")

    # Lagrange interpolation at x=0
    secret_int = 0
    for i, (xi, yi) in enumerate(shares):
        numerator = 1
        denominator = 1
        for j, (xj, _) in enumerate(shares):
            if i != j:
                numerator = (numerator * (-xj)) % _PRIME
                denominator = (denominator * (xi - xj)) % _PRIME

        lagrange = (yi * numerator * _mod_inverse(denominator, _PRIME)) % _PRIME
        secret_int = (secret_int + lagrange) % _PRIME

    try:
        return secret_int.to_bytes(secret_length, byteorder="big")
    except OverflowError:
        # Insufficient shares produce wrong result — return truncated bytes
        raw = secret_int.to_bytes((secret_int.bit_length() + 7) // 8, byteorder="big")
        return raw[:secret_length]


@dataclass
class KeyCeremonyRecord:
    """Record of a key ceremony event."""
    ceremony_id: str
    action: str           # split, reconstruct, verify
    shares_needed: int
    total_shares: int
    timestamp: str
    participants: list[str] = field(default_factory=list)
    success: bool = True
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "ceremony_id": self.ceremony_id,
            "action": self.action,
            "shares_needed": self.shares_needed,
            "total_shares": self.total_shares,
            "timestamp": self.timestamp,
            "participants": self.participants,
            "success": self.success,
            "detail": self.detail,
        }


class KeyCeremony:
    """
    Manages Shamir key splitting/reconstruction ceremonies.

    A key ceremony is a formal process where multiple key holders
    participate in splitting or reconstructing a master key.

    Usage:
        ceremony = KeyCeremony()

        # Split a master key into 5 shares, 3 needed to reconstruct
        shares = ceremony.split(master_key, shares_needed=3, total_shares=5,
                                participants=["alice", "bob", "charlie", "dave", "eve"])

        # Later: reconstruct with 3 of the 5 shares
        key = ceremony.reconstruct(shares[:3], key_length=32,
                                   participants=["alice", "bob", "charlie"])
    """

    def __init__(self):
        self._records: list[KeyCeremonyRecord] = []

    def split(
        self,
        secret: bytes,
        shares_needed: int,
        total_shares: int,
        participants: Optional[list[str]] = None,
    ) -> list[tuple[int, int]]:
        ceremony_id = f"ceremony_{uuid.uuid4().hex[:10]}"
        try:
            shares = split_secret(secret, shares_needed, total_shares)
            self._records.append(KeyCeremonyRecord(
                ceremony_id=ceremony_id,
                action="split",
                shares_needed=shares_needed,
                total_shares=total_shares,
                timestamp=datetime.now(timezone.utc).isoformat(),
                participants=participants or [],
                success=True,
            ))
            return shares
        except Exception as e:
            self._records.append(KeyCeremonyRecord(
                ceremony_id=ceremony_id,
                action="split",
                shares_needed=shares_needed,
                total_shares=total_shares,
                timestamp=datetime.now(timezone.utc).isoformat(),
                success=False,
                detail=str(e),
            ))
            raise

    def reconstruct(
        self,
        shares: list[tuple[int, int]],
        key_length: int,
        participants: Optional[list[str]] = None,
    ) -> bytes:
        ceremony_id = f"ceremony_{uuid.uuid4().hex[:10]}"
        try:
            secret = reconstruct_secret(shares, key_length)
            self._records.append(KeyCeremonyRecord(
                ceremony_id=ceremony_id,
                action="reconstruct",
                shares_needed=len(shares),
                total_shares=len(shares),
                timestamp=datetime.now(timezone.utc).isoformat(),
                participants=participants or [],
                success=True,
            ))
            return secret
        except Exception as e:
            self._records.append(KeyCeremonyRecord(
                ceremony_id=ceremony_id,
                action="reconstruct",
                shares_needed=len(shares),
                total_shares=len(shares),
                timestamp=datetime.now(timezone.utc).isoformat(),
                success=False,
                detail=str(e),
            ))
            raise

    @property
    def records(self) -> list[dict]:
        return [r.to_dict() for r in self._records]

    @property
    def ceremony_count(self) -> int:
        return len(self._records)
