"""
AIB — Sprint 13: Protocol Health Monitoring.

Real-time monitoring of every protocol endpoint the gateway routes to.
Answers: "Is MCP up? What's the A2A latency? How many AG-UI errors today?"

Integrates with:
- CircuitBreaker (sprint5): shares state (open/closed/half-open)
- MetricsCollector (sprint2): feeds latency + error data
- DiagnosticRunner (sprint12): registers as a component check
- WebhookManager (sprint9): fires alerts on status change

Exposes /health/protocols endpoint.
"""

import time
import threading
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Callable
from enum import Enum
from collections import deque


# ═══════════════════════════════════════════════════════════════════
# PROTOCOL STATUS
# ═══════════════════════════════════════════════════════════════════

class EndpointStatus(str, Enum):
    HEALTHY = "healthy"       # Responding normally
    DEGRADED = "degraded"     # Responding but slow or partial failures
    DOWN = "down"             # Not responding / circuit open
    UNKNOWN = "unknown"       # No data yet


@dataclass
class EndpointMetrics:
    """Rolling metrics for a single protocol endpoint."""
    target: str
    protocol: str
    status: EndpointStatus = EndpointStatus.UNKNOWN
    total_requests: int = 0
    successful: int = 0
    failed: int = 0
    last_status_code: int = 0
    last_error: str = ""
    last_request_at: str = ""
    last_success_at: str = ""
    last_failure_at: str = ""
    latencies: list = field(default_factory=list)
    status_changed_at: str = ""
    consecutive_failures: int = 0
    consecutive_successes: int = 0

    # Rolling window config
    _max_latencies: int = 200

    def record_success(self, latency_ms: float, status_code: int = 200):
        now = datetime.now(timezone.utc).isoformat()
        self.total_requests += 1
        self.successful += 1
        self.last_status_code = status_code
        self.last_request_at = now
        self.last_success_at = now
        self.consecutive_successes += 1
        self.consecutive_failures = 0
        self.last_error = ""
        self._add_latency(latency_ms)
        self._update_status()

    def record_failure(self, latency_ms: float, status_code: int = 0, error: str = ""):
        now = datetime.now(timezone.utc).isoformat()
        self.total_requests += 1
        self.failed += 1
        self.last_status_code = status_code
        self.last_request_at = now
        self.last_failure_at = now
        self.last_error = error
        self.consecutive_failures += 1
        self.consecutive_successes = 0
        self._add_latency(latency_ms)
        self._update_status()

    def _add_latency(self, ms: float):
        self.latencies.append(ms)
        if len(self.latencies) > self._max_latencies:
            self.latencies = self.latencies[-self._max_latencies:]

    def _update_status(self):
        old = self.status
        if self.consecutive_failures >= 5:
            self.status = EndpointStatus.DOWN
        elif self.consecutive_failures >= 2:
            self.status = EndpointStatus.DEGRADED
        elif self.consecutive_successes >= 1:
            # Recovery: consecutive success overrides historical error_rate
            if self.error_rate > 0.2 and self.consecutive_successes < 3:
                self.status = EndpointStatus.DEGRADED
            else:
                self.status = EndpointStatus.HEALTHY
        if self.status != old:
            self.status_changed_at = datetime.now(timezone.utc).isoformat()

    @property
    def error_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.failed / self.total_requests

    @property
    def success_rate(self) -> float:
        return 1.0 - self.error_rate

    @property
    def p50(self) -> float:
        return self._percentile(50)

    @property
    def p95(self) -> float:
        return self._percentile(95)

    @property
    def p99(self) -> float:
        return self._percentile(99)

    @property
    def avg_latency(self) -> float:
        if not self.latencies:
            return 0.0
        return sum(self.latencies) / len(self.latencies)

    def _percentile(self, p: float) -> float:
        if not self.latencies:
            return 0.0
        s = sorted(self.latencies)
        idx = int(len(s) * p / 100)
        return s[min(idx, len(s) - 1)]

    def uptime_percent(self) -> float:
        """Approximate uptime based on success rate."""
        if self.total_requests == 0:
            return 0.0
        return round(self.success_rate * 100, 2)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "protocol": self.protocol,
            "status": self.status.value,
            "total_requests": self.total_requests,
            "successful": self.successful,
            "failed": self.failed,
            "success_rate": round(self.success_rate, 4),
            "error_rate": round(self.error_rate, 4),
            "uptime_percent": self.uptime_percent(),
            "latency": {
                "avg_ms": round(self.avg_latency, 2),
                "p50_ms": round(self.p50, 2),
                "p95_ms": round(self.p95, 2),
                "p99_ms": round(self.p99, 2),
            },
            "last_status_code": self.last_status_code,
            "last_error": self.last_error,
            "last_request_at": self.last_request_at,
            "last_success_at": self.last_success_at,
            "last_failure_at": self.last_failure_at,
            "consecutive_failures": self.consecutive_failures,
            "status_changed_at": self.status_changed_at,
        }


# ═══════════════════════════════════════════════════════════════════
# PROTOCOL HEALTH MONITOR
# ═══════════════════════════════════════════════════════════════════

@dataclass
class StatusChangeEvent:
    """Emitted when an endpoint's status changes."""
    target: str
    protocol: str
    old_status: str
    new_status: str
    timestamp: str
    consecutive_failures: int = 0
    last_error: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "protocol": self.protocol,
            "old_status": self.old_status,
            "new_status": self.new_status,
            "timestamp": self.timestamp,
            "consecutive_failures": self.consecutive_failures,
            "last_error": self.last_error,
        }


class ProtocolHealthMonitor:
    """
    Tracks health of every protocol endpoint the gateway talks to.

    Usage:
        monitor = ProtocolHealthMonitor()

        # After each gateway proxy call:
        monitor.record_success("https://partner.com/a2a", "a2a", latency_ms=45)
        monitor.record_failure("https://mcp.vendor.com", "mcp", error="Connection refused")

        # Status page
        status = monitor.get_status()
        # → {protocols: {a2a: {healthy: 1}, mcp: {down: 1}}, ...}

        # Per-endpoint detail
        detail = monitor.get_endpoint("https://partner.com/a2a")
        # → {status: "healthy", p95: 52.3, error_rate: 0.01, ...}

        # Alerts (status changes)
        changes = monitor.get_status_changes(limit=10)
    """

    def __init__(self, on_status_change: Optional[Callable[[StatusChangeEvent], None]] = None):
        self._endpoints: dict[str, EndpointMetrics] = {}
        self._lock = threading.Lock()
        self._status_changes: list[StatusChangeEvent] = []
        self._max_changes = 500
        self._on_change = on_status_change

    def _get_or_create(self, target: str, protocol: str) -> EndpointMetrics:
        if target not in self._endpoints:
            self._endpoints[target] = EndpointMetrics(target=target, protocol=protocol)
        return self._endpoints[target]

    def _check_status_change(self, endpoint: EndpointMetrics, old_status: EndpointStatus):
        if endpoint.status != old_status:
            event = StatusChangeEvent(
                target=endpoint.target,
                protocol=endpoint.protocol,
                old_status=old_status.value,
                new_status=endpoint.status.value,
                timestamp=datetime.now(timezone.utc).isoformat(),
                consecutive_failures=endpoint.consecutive_failures,
                last_error=endpoint.last_error,
            )
            self._status_changes.append(event)
            if len(self._status_changes) > self._max_changes:
                self._status_changes = self._status_changes[-self._max_changes:]

            if self._on_change:
                try:
                    self._on_change(event)
                except Exception:
                    pass

    # ── Recording ─────────────────────────────────────────────────

    def record_success(
        self, target: str, protocol: str,
        latency_ms: float, status_code: int = 200,
    ):
        with self._lock:
            ep = self._get_or_create(target, protocol)
            old = ep.status
            ep.record_success(latency_ms, status_code)
            self._check_status_change(ep, old)

    def record_failure(
        self, target: str, protocol: str,
        latency_ms: float = 0.0, status_code: int = 0, error: str = "",
    ):
        with self._lock:
            ep = self._get_or_create(target, protocol)
            old = ep.status
            ep.record_failure(latency_ms, status_code, error)
            self._check_status_change(ep, old)

    # ── Query ─────────────────────────────────────────────────────

    def get_endpoint(self, target: str) -> Optional[dict]:
        with self._lock:
            ep = self._endpoints.get(target)
            return ep.to_dict() if ep else None

    def get_all_endpoints(self) -> list[dict]:
        with self._lock:
            return [ep.to_dict() for ep in self._endpoints.values()]

    def get_endpoints_by_protocol(self, protocol: str) -> list[dict]:
        with self._lock:
            return [
                ep.to_dict() for ep in self._endpoints.values()
                if ep.protocol == protocol
            ]

    def get_endpoints_by_status(self, status: str) -> list[dict]:
        with self._lock:
            return [
                ep.to_dict() for ep in self._endpoints.values()
                if ep.status.value == status
            ]

    # ── Status page ───────────────────────────────────────────────

    def get_status(self) -> dict:
        """
        Aggregated status page for /health/protocols.

        Returns overall health + per-protocol breakdown.
        """
        with self._lock:
            endpoints = list(self._endpoints.values())

        if not endpoints:
            return {
                "overall": "no_data",
                "total_endpoints": 0,
                "protocols": {},
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }

        by_protocol: dict[str, dict] = {}
        overall_down = 0
        overall_degraded = 0

        for ep in endpoints:
            proto = ep.protocol
            if proto not in by_protocol:
                by_protocol[proto] = {
                    "healthy": 0, "degraded": 0, "down": 0, "unknown": 0,
                    "total_requests": 0, "avg_latency_ms": 0.0,
                    "endpoints": [],
                }

            by_protocol[proto][ep.status.value] += 1
            by_protocol[proto]["total_requests"] += ep.total_requests
            by_protocol[proto]["endpoints"].append(ep.target)

            if ep.status == EndpointStatus.DOWN:
                overall_down += 1
            elif ep.status == EndpointStatus.DEGRADED:
                overall_degraded += 1

        # Compute avg latency per protocol
        for proto, info in by_protocol.items():
            proto_eps = [ep for ep in endpoints if ep.protocol == proto]
            latencies = [ep.avg_latency for ep in proto_eps if ep.avg_latency > 0]
            info["avg_latency_ms"] = round(sum(latencies) / max(len(latencies), 1), 2)

        if overall_down > 0:
            overall = "degraded"
        elif overall_degraded > 0:
            overall = "partial"
        else:
            overall = "healthy"

        return {
            "overall": overall,
            "total_endpoints": len(endpoints),
            "healthy": sum(1 for ep in endpoints if ep.status == EndpointStatus.HEALTHY),
            "degraded": overall_degraded,
            "down": overall_down,
            "protocols": by_protocol,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    # ── Status changes (alerts) ───────────────────────────────────

    def get_status_changes(self, limit: int = 50) -> list[dict]:
        with self._lock:
            return [e.to_dict() for e in reversed(self._status_changes[-limit:])]

    def get_down_endpoints(self) -> list[dict]:
        return self.get_endpoints_by_status("down")

    def get_degraded_endpoints(self) -> list[dict]:
        return self.get_endpoints_by_status("degraded")

    # ── Stats ─────────────────────────────────────────────────────

    @property
    def endpoint_count(self) -> int:
        with self._lock:
            return len(self._endpoints)

    @property
    def protocols_tracked(self) -> list[str]:
        with self._lock:
            return list(set(ep.protocol for ep in self._endpoints.values()))

    def reset_endpoint(self, target: str):
        with self._lock:
            if target in self._endpoints:
                del self._endpoints[target]
