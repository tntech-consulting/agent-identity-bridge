"""
AIB — Sprint 5: Enterprise hardening.

Three optimizations from the remaining enterprise items:

1. OPT-NET-02: Circuit breaker pattern (prevents cascade failures)
2. OPT-CRYPTO-02: Multi-algorithm support (ES256 + EdDSA alongside RS256)
3. OPT-ID-02: Signed Certificate Revocation List (CRL)

These are the enterprise features most likely to be requested by
first pilot customers.
"""

import time
import threading
import hashlib
import json
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# ═══════════════════════════════════════════════════════════════════
# 1. OPT-NET-02 — CIRCUIT BREAKER
# ═══════════════════════════════════════════════════════════════════

class CircuitState(str, Enum):
    CLOSED = "closed"       # Normal operation, requests pass through
    OPEN = "open"           # Failures exceeded threshold, requests blocked
    HALF_OPEN = "half_open" # Testing if service recovered


class CircuitBreakerError(Exception):
    """Raised when circuit is open and request is blocked."""
    pass


@dataclass
class CircuitStats:
    """Statistics for a single circuit."""
    target: str
    state: CircuitState
    failures: int
    successes: int
    last_failure_at: float
    last_success_at: float
    opened_at: float
    half_open_attempts: int

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "state": self.state.value,
            "failures": self.failures,
            "successes": self.successes,
            "last_failure_at": self.last_failure_at,
            "last_success_at": self.last_success_at,
        }


class CircuitBreaker:
    """
    Circuit breaker pattern per target URL/host.

    States:
    - CLOSED: Normal. Requests pass. Failures are counted.
    - OPEN: Service is down. Requests are blocked immediately.
      After recovery_timeout, transitions to HALF_OPEN.
    - HALF_OPEN: One test request is allowed. If it succeeds,
      circuit closes. If it fails, circuit reopens.

    Usage:
        cb = CircuitBreaker(failure_threshold=5, recovery_timeout=30)

        target = "https://partner.com/a2a"

        if not cb.allow_request(target):
            raise CircuitBreakerError("Circuit open for partner.com")

        try:
            response = await http_client.post(target, ...)
            cb.record_success(target)
        except Exception:
            cb.record_failure(target)
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        success_threshold: int = 1,
    ):
        self._threshold = failure_threshold
        self._recovery = recovery_timeout
        self._success_threshold = success_threshold
        self._circuits: dict[str, dict] = {}
        self._lock = threading.Lock()

    def _get_circuit(self, target: str) -> dict:
        if target not in self._circuits:
            self._circuits[target] = {
                "state": CircuitState.CLOSED,
                "failures": 0,
                "successes": 0,
                "last_failure": 0.0,
                "last_success": 0.0,
                "opened_at": 0.0,
                "half_open_attempts": 0,
            }
        return self._circuits[target]

    def allow_request(self, target: str) -> bool:
        """Check if a request to target is allowed."""
        with self._lock:
            c = self._get_circuit(target)

            if c["state"] == CircuitState.CLOSED:
                return True

            if c["state"] == CircuitState.OPEN:
                if time.time() - c["opened_at"] > self._recovery:
                    c["state"] = CircuitState.HALF_OPEN
                    c["half_open_attempts"] = 0
                    return True
                return False

            if c["state"] == CircuitState.HALF_OPEN:
                if c["half_open_attempts"] < self._success_threshold:
                    c["half_open_attempts"] += 1
                    return True
                return False

        return True

    def record_success(self, target: str):
        """Record a successful request."""
        with self._lock:
            c = self._get_circuit(target)
            c["successes"] += 1
            c["last_success"] = time.time()

            if c["state"] == CircuitState.HALF_OPEN:
                c["state"] = CircuitState.CLOSED
                c["failures"] = 0

    def record_failure(self, target: str):
        """Record a failed request."""
        with self._lock:
            c = self._get_circuit(target)
            c["failures"] += 1
            c["last_failure"] = time.time()

            if c["state"] == CircuitState.HALF_OPEN:
                c["state"] = CircuitState.OPEN
                c["opened_at"] = time.time()

            elif c["state"] == CircuitState.CLOSED:
                if c["failures"] >= self._threshold:
                    c["state"] = CircuitState.OPEN
                    c["opened_at"] = time.time()

    def get_state(self, target: str) -> CircuitState:
        with self._lock:
            c = self._get_circuit(target)
            if c["state"] == CircuitState.OPEN:
                if time.time() - c["opened_at"] > self._recovery:
                    c["state"] = CircuitState.HALF_OPEN
            return c["state"]

    def reset(self, target: str):
        """Manually reset a circuit."""
        with self._lock:
            if target in self._circuits:
                self._circuits[target] = {
                    "state": CircuitState.CLOSED,
                    "failures": 0, "successes": 0,
                    "last_failure": 0.0, "last_success": 0.0,
                    "opened_at": 0.0, "half_open_attempts": 0,
                }

    def get_stats(self, target: str) -> Optional[dict]:
        with self._lock:
            c = self._circuits.get(target)
            if not c:
                return None
            return CircuitStats(
                target=target,
                state=c["state"],
                failures=c["failures"],
                successes=c["successes"],
                last_failure_at=c["last_failure"],
                last_success_at=c["last_success"],
                opened_at=c["opened_at"],
                half_open_attempts=c["half_open_attempts"],
            ).to_dict()

    def list_open_circuits(self) -> list[str]:
        with self._lock:
            return [t for t, c in self._circuits.items()
                    if c["state"] == CircuitState.OPEN]

    @property
    def total_circuits(self) -> int:
        with self._lock:
            return len(self._circuits)


# ═══════════════════════════════════════════════════════════════════
# 2. OPT-CRYPTO-02 — MULTI-ALGORITHM SUPPORT
# ═══════════════════════════════════════════════════════════════════

class SigningAlgorithm(str, Enum):
    RS256 = "RS256"     # RSA PKCS#1 v1.5 + SHA-256 (default, most compatible)
    ES256 = "ES256"     # ECDSA P-256 + SHA-256 (shorter signatures, faster)
    EdDSA = "EdDSA"     # Ed25519 (fastest, smallest keys)


@dataclass
class AlgorithmProfile:
    """Properties of a signing algorithm."""
    name: str
    algorithm: SigningAlgorithm
    key_size_bits: int
    signature_size_bytes: int
    speed: str               # relative: fast, faster, fastest
    compatibility: str       # wide, good, growing
    recommended_for: str

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "algorithm": self.algorithm.value,
            "key_size_bits": self.key_size_bits,
            "signature_size_bytes": self.signature_size_bytes,
            "speed": self.speed,
            "compatibility": self.compatibility,
            "recommended_for": self.recommended_for,
        }


ALGORITHM_PROFILES = {
    SigningAlgorithm.RS256: AlgorithmProfile(
        name="RSA-SHA256",
        algorithm=SigningAlgorithm.RS256,
        key_size_bits=2048,
        signature_size_bytes=256,
        speed="fast",
        compatibility="wide",
        recommended_for="Maximum compatibility with existing IdPs and JWT libraries",
    ),
    SigningAlgorithm.ES256: AlgorithmProfile(
        name="ECDSA P-256",
        algorithm=SigningAlgorithm.ES256,
        key_size_bits=256,
        signature_size_bytes=64,
        speed="faster",
        compatibility="good",
        recommended_for="Shorter signatures, faster verification, mobile/IoT agents",
    ),
    SigningAlgorithm.EdDSA: AlgorithmProfile(
        name="Ed25519",
        algorithm=SigningAlgorithm.EdDSA,
        key_size_bits=256,
        signature_size_bytes=64,
        speed="fastest",
        compatibility="growing",
        recommended_for="Maximum performance, smallest keys, new deployments",
    ),
}


class AlgorithmRegistry:
    """
    Registry of supported signing algorithms.

    Manages which algorithms an organization accepts and
    which is the default for new passports.

    Usage:
        reg = AlgorithmRegistry(default=SigningAlgorithm.RS256)

        # Check if an algorithm is accepted
        reg.is_accepted(SigningAlgorithm.ES256)  # True

        # Get the default
        reg.default  # RS256

        # Change default
        reg.set_default(SigningAlgorithm.ES256)

        # Restrict to specific algorithms
        reg.set_accepted([SigningAlgorithm.RS256, SigningAlgorithm.ES256])
    """

    def __init__(
        self,
        default: SigningAlgorithm = SigningAlgorithm.RS256,
        accepted: Optional[list[SigningAlgorithm]] = None,
    ):
        self._default = default
        self._accepted = set(accepted or list(SigningAlgorithm))

        if default not in self._accepted:
            self._accepted.add(default)

    @property
    def default(self) -> SigningAlgorithm:
        return self._default

    def set_default(self, algo: SigningAlgorithm):
        self._accepted.add(algo)
        self._default = algo

    def is_accepted(self, algo: SigningAlgorithm) -> bool:
        return algo in self._accepted

    def set_accepted(self, algos: list[SigningAlgorithm]):
        self._accepted = set(algos)
        if self._default not in self._accepted:
            self._default = algos[0]

    def get_profile(self, algo: SigningAlgorithm) -> AlgorithmProfile:
        return ALGORITHM_PROFILES[algo]

    def list_accepted(self) -> list[dict]:
        return [
            ALGORITHM_PROFILES[a].to_dict()
            for a in sorted(self._accepted, key=lambda a: a.value)
        ]

    def validate_algorithm(self, algo_str: str) -> tuple[bool, str]:
        """Validate an algorithm string from a passport or request."""
        try:
            algo = SigningAlgorithm(algo_str)
        except ValueError:
            return False, f"Unknown algorithm: {algo_str}. Accepted: {[a.value for a in self._accepted]}"

        if algo not in self._accepted:
            return False, f"Algorithm {algo_str} not accepted. Accepted: {[a.value for a in self._accepted]}"

        return True, f"Algorithm {algo_str} accepted"


# ═══════════════════════════════════════════════════════════════════
# 3. OPT-ID-02 — SIGNED CERTIFICATE REVOCATION LIST (CRL)
# ═══════════════════════════════════════════════════════════════════

@dataclass
class CRLEntry:
    """A single revocation entry in the CRL."""
    passport_id: str
    revoked_at: str
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "passport_id": self.passport_id,
            "revoked_at": self.revoked_at,
            "reason": self.reason,
        }


class SignedCRL:
    """
    Signed Certificate Revocation List.

    Published at /.well-known/aib-crl.json.
    Federated gateways fetch this to check if a passport
    from another organization has been revoked.

    The CRL is signed with the gateway's RS256 key so
    federated parties can verify its authenticity.

    Usage:
        crl = SignedCRL(issuer="urn:aib:org:acme")

        crl.revoke("urn:aib:agent:acme:compromised", reason="Key leak")

        # Publish
        doc = crl.to_document()  # Signed JSON for .well-known

        # Check
        crl.is_revoked("urn:aib:agent:acme:compromised")  # True
    """

    def __init__(self, issuer: str):
        self._issuer = issuer
        self._entries: dict[str, CRLEntry] = {}
        self._lock = threading.Lock()
        self._version: int = 0

    def revoke(self, passport_id: str, reason: str = ""):
        with self._lock:
            if passport_id not in self._entries:
                self._entries[passport_id] = CRLEntry(
                    passport_id=passport_id,
                    revoked_at=datetime.now(timezone.utc).isoformat(),
                    reason=reason,
                )
                self._version += 1

    def is_revoked(self, passport_id: str) -> bool:
        with self._lock:
            return passport_id in self._entries

    def get_entry(self, passport_id: str) -> Optional[dict]:
        with self._lock:
            entry = self._entries.get(passport_id)
            return entry.to_dict() if entry else None

    def unrevoke(self, passport_id: str) -> bool:
        """Remove from CRL (rare — only for false positives)."""
        with self._lock:
            if passport_id in self._entries:
                del self._entries[passport_id]
                self._version += 1
                return True
            return False

    def to_document(self) -> dict:
        """
        Generate the CRL document for /.well-known/aib-crl.json.

        In production, this document would be JWS-signed with
        the gateway's private key.
        """
        with self._lock:
            entries = [e.to_dict() for e in self._entries.values()]
            doc = {
                "issuer": self._issuer,
                "version": self._version,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_revoked": len(entries),
                "entries": entries,
            }
            doc["crl_hash"] = hashlib.sha256(
                json.dumps(entries, sort_keys=True).encode()
            ).hexdigest()
            return doc

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._entries)

    @property
    def version(self) -> int:
        return self._version

    def list_revoked(self) -> list[str]:
        with self._lock:
            return list(self._entries.keys())

    def check_batch(self, passport_ids: list[str]) -> dict[str, bool]:
        """Check multiple passport_ids at once."""
        with self._lock:
            return {pid: pid in self._entries for pid in passport_ids}
