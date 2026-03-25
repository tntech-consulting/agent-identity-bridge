"""Tests for Sprint 13 — Protocol Health Monitoring."""

import time
import threading
import pytest
from aib.protocol_health import (
    ProtocolHealthMonitor, EndpointMetrics, EndpointStatus,
    StatusChangeEvent,
)


@pytest.fixture
def monitor():
    return ProtocolHealthMonitor()


# ═══════════════════════════════════════════════════════════════════
# ENDPOINT METRICS
# ═══════════════════════════════════════════════════════════════════

class TestEndpointMetrics:

    def test_initial_state(self):
        ep = EndpointMetrics(target="https://test.com", protocol="a2a")
        assert ep.status == EndpointStatus.UNKNOWN
        assert ep.total_requests == 0

    def test_success_sets_healthy(self):
        ep = EndpointMetrics(target="https://test.com", protocol="a2a")
        ep.record_success(45.0, 200)
        assert ep.status == EndpointStatus.HEALTHY
        assert ep.total_requests == 1
        assert ep.successful == 1
        assert ep.consecutive_successes == 1

    def test_failure_tracking(self):
        ep = EndpointMetrics(target="https://test.com", protocol="mcp")
        ep.record_failure(0.0, 502, "Bad Gateway")
        assert ep.failed == 1
        assert ep.last_error == "Bad Gateway"
        assert ep.consecutive_failures == 1

    def test_degraded_on_2_failures(self):
        ep = EndpointMetrics(target="https://test.com", protocol="a2a")
        ep.record_failure(0.0, 500, "err1")
        ep.record_failure(0.0, 500, "err2")
        assert ep.status == EndpointStatus.DEGRADED

    def test_down_on_5_failures(self):
        ep = EndpointMetrics(target="https://test.com", protocol="a2a")
        for i in range(5):
            ep.record_failure(0.0, 500, f"err{i}")
        assert ep.status == EndpointStatus.DOWN

    def test_recovery_from_down(self):
        ep = EndpointMetrics(target="https://test.com", protocol="a2a")
        for _ in range(5):
            ep.record_failure(0.0)
        assert ep.status == EndpointStatus.DOWN

        # 3 successes needed to override high error_rate
        ep.record_success(30.0)
        ep.record_success(30.0)
        ep.record_success(30.0)
        assert ep.status == EndpointStatus.HEALTHY
        assert ep.consecutive_failures == 0

    def test_success_resets_consecutive_failures(self):
        ep = EndpointMetrics(target="https://test.com", protocol="a2a")
        ep.record_failure(0.0)
        ep.record_failure(0.0)
        ep.record_success(50.0)
        assert ep.consecutive_failures == 0
        assert ep.consecutive_successes == 1

    def test_error_rate(self):
        ep = EndpointMetrics(target="https://test.com", protocol="a2a")
        for _ in range(8):
            ep.record_success(50.0)
        for _ in range(2):
            ep.record_failure(0.0)
        assert abs(ep.error_rate - 0.2) < 0.01

    def test_latency_percentiles(self):
        ep = EndpointMetrics(target="https://test.com", protocol="a2a")
        for i in range(100):
            ep.record_success(float(i))
        assert ep.p50 >= 40
        assert ep.p95 >= 90
        assert ep.p99 >= 95
        assert ep.avg_latency > 40

    def test_uptime_percent(self):
        ep = EndpointMetrics(target="https://test.com", protocol="a2a")
        for _ in range(9):
            ep.record_success(50.0)
        ep.record_failure(0.0)
        assert ep.uptime_percent() == 90.0

    def test_to_dict(self):
        ep = EndpointMetrics(target="https://test.com", protocol="mcp")
        ep.record_success(42.0, 200)
        d = ep.to_dict()
        assert d["target"] == "https://test.com"
        assert d["protocol"] == "mcp"
        assert d["status"] == "healthy"
        assert "latency" in d
        assert "p95_ms" in d["latency"]


# ═══════════════════════════════════════════════════════════════════
# PROTOCOL HEALTH MONITOR
# ═══════════════════════════════════════════════════════════════════

class TestProtocolHealthMonitor:

    def test_record_success(self, monitor):
        monitor.record_success("https://a2a.test", "a2a", 45.0)
        ep = monitor.get_endpoint("https://a2a.test")
        assert ep is not None
        assert ep["status"] == "healthy"

    def test_record_failure(self, monitor):
        for _ in range(5):
            monitor.record_failure("https://mcp.test", "mcp", error="Timeout")
        ep = monitor.get_endpoint("https://mcp.test")
        assert ep["status"] == "down"
        assert ep["last_error"] == "Timeout"

    def test_get_nonexistent(self, monitor):
        assert monitor.get_endpoint("https://nope.test") is None

    def test_get_all_endpoints(self, monitor):
        monitor.record_success("https://a.test", "a2a", 50)
        monitor.record_success("https://b.test", "mcp", 30)
        monitor.record_success("https://c.test", "ag_ui", 20)
        eps = monitor.get_all_endpoints()
        assert len(eps) == 3

    def test_get_by_protocol(self, monitor):
        monitor.record_success("https://a.test", "a2a", 50)
        monitor.record_success("https://b.test", "a2a", 60)
        monitor.record_success("https://c.test", "mcp", 30)
        a2a_eps = monitor.get_endpoints_by_protocol("a2a")
        assert len(a2a_eps) == 2

    def test_get_by_status(self, monitor):
        monitor.record_success("https://good.test", "a2a", 50)
        for _ in range(5):
            monitor.record_failure("https://bad.test", "mcp")
        down = monitor.get_endpoints_by_status("down")
        assert len(down) == 1
        assert down[0]["target"] == "https://bad.test"


# ═══════════════════════════════════════════════════════════════════
# STATUS PAGE
# ═══════════════════════════════════════════════════════════════════

class TestStatusPage:

    def test_no_data(self, monitor):
        status = monitor.get_status()
        assert status["overall"] == "no_data"
        assert status["total_endpoints"] == 0

    def test_all_healthy(self, monitor):
        monitor.record_success("https://a.test", "a2a", 50)
        monitor.record_success("https://b.test", "mcp", 30)
        status = monitor.get_status()
        assert status["overall"] == "healthy"
        assert status["healthy"] == 2
        assert status["down"] == 0

    def test_partial_degradation(self, monitor):
        monitor.record_success("https://good.test", "a2a", 50)
        monitor.record_failure("https://slow.test", "mcp")
        monitor.record_failure("https://slow.test", "mcp")
        status = monitor.get_status()
        assert status["overall"] == "partial"
        assert status["degraded"] == 1

    def test_has_down_endpoint(self, monitor):
        monitor.record_success("https://good.test", "a2a", 50)
        for _ in range(5):
            monitor.record_failure("https://dead.test", "mcp")
        status = monitor.get_status()
        assert status["overall"] == "degraded"
        assert status["down"] == 1

    def test_per_protocol_breakdown(self, monitor):
        monitor.record_success("https://a1.test", "a2a", 50)
        monitor.record_success("https://a2.test", "a2a", 60)
        monitor.record_success("https://m1.test", "mcp", 30)
        status = monitor.get_status()
        assert "a2a" in status["protocols"]
        assert "mcp" in status["protocols"]
        assert status["protocols"]["a2a"]["healthy"] == 2
        assert len(status["protocols"]["a2a"]["endpoints"]) == 2

    def test_per_protocol_avg_latency(self, monitor):
        for _ in range(10):
            monitor.record_success("https://a.test", "a2a", 100.0)
        status = monitor.get_status()
        assert status["protocols"]["a2a"]["avg_latency_ms"] > 0


# ═══════════════════════════════════════════════════════════════════
# STATUS CHANGES (ALERTS)
# ═══════════════════════════════════════════════════════════════════

class TestStatusChanges:

    def test_status_change_recorded(self, monitor):
        # unknown → healthy
        monitor.record_success("https://a.test", "a2a", 50)
        changes = monitor.get_status_changes()
        assert len(changes) >= 1
        assert changes[0]["new_status"] == "healthy"

    def test_healthy_to_down(self, monitor):
        monitor.record_success("https://a.test", "a2a", 50)
        for _ in range(5):
            monitor.record_failure("https://a.test", "a2a", error="Timeout")
        changes = monitor.get_status_changes()
        # Should have: unknown→healthy, healthy→degraded, degraded→down
        statuses = [c["new_status"] for c in changes]
        assert "down" in statuses

    def test_callback_on_change(self):
        events = []
        monitor = ProtocolHealthMonitor(on_status_change=lambda e: events.append(e))
        monitor.record_success("https://a.test", "a2a", 50)
        assert len(events) >= 1
        assert events[0].new_status == "healthy"

    def test_down_endpoints(self, monitor):
        for _ in range(5):
            monitor.record_failure("https://dead.test", "mcp")
        down = monitor.get_down_endpoints()
        assert len(down) == 1

    def test_degraded_endpoints(self, monitor):
        monitor.record_failure("https://slow.test", "a2a")
        monitor.record_failure("https://slow.test", "a2a")
        degraded = monitor.get_degraded_endpoints()
        assert len(degraded) == 1


# ═══════════════════════════════════════════════════════════════════
# PROPERTIES & MANAGEMENT
# ═══════════════════════════════════════════════════════════════════

class TestManagement:

    def test_endpoint_count(self, monitor):
        monitor.record_success("https://a.test", "a2a", 50)
        monitor.record_success("https://b.test", "mcp", 30)
        assert monitor.endpoint_count == 2

    def test_protocols_tracked(self, monitor):
        monitor.record_success("https://a.test", "a2a", 50)
        monitor.record_success("https://b.test", "mcp", 30)
        monitor.record_success("https://c.test", "ag_ui", 20)
        assert set(monitor.protocols_tracked) == {"a2a", "mcp", "ag_ui"}

    def test_reset_endpoint(self, monitor):
        monitor.record_success("https://a.test", "a2a", 50)
        assert monitor.endpoint_count == 1
        monitor.reset_endpoint("https://a.test")
        assert monitor.endpoint_count == 0

    def test_thread_safe(self):
        monitor = ProtocolHealthMonitor()
        def hammer(prefix):
            for i in range(100):
                if i % 3 == 0:
                    monitor.record_failure(f"https://{prefix}.test", prefix, error="err")
                else:
                    monitor.record_success(f"https://{prefix}.test", prefix, float(i))

        threads = [threading.Thread(target=hammer, args=(f"t{t}",)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert monitor.endpoint_count == 4
        status = monitor.get_status()
        assert status["total_endpoints"] == 4


# ═══════════════════════════════════════════════════════════════════
# END-TO-END
# ═══════════════════════════════════════════════════════════════════

class TestEndToEnd:

    def test_full_monitoring_lifecycle(self):
        """Simulate: healthy → degraded → down → recovery → healthy."""
        alerts = []
        monitor = ProtocolHealthMonitor(
            on_status_change=lambda e: alerts.append(e),
        )
        target = "https://partner.com/a2a"

        # Phase 1: healthy
        for _ in range(10):
            monitor.record_success(target, "a2a", 45.0)
        ep = monitor.get_endpoint(target)
        assert ep["status"] == "healthy"
        assert ep["uptime_percent"] == 100.0

        # Phase 2: start failing
        monitor.record_failure(target, "a2a", error="Connection reset")
        monitor.record_failure(target, "a2a", error="Connection reset")
        ep = monitor.get_endpoint(target)
        assert ep["status"] == "degraded"

        # Phase 3: total failure
        for _ in range(3):
            monitor.record_failure(target, "a2a", error="Connection refused")
        ep = monitor.get_endpoint(target)
        assert ep["status"] == "down"
        assert ep["consecutive_failures"] == 5

        # Phase 4: recovery (3 successes to clear high error_rate)
        monitor.record_success(target, "a2a", 50.0)
        monitor.record_success(target, "a2a", 48.0)
        monitor.record_success(target, "a2a", 52.0)
        ep = monitor.get_endpoint(target)
        assert ep["status"] == "healthy"

        # Verify alerts captured transitions
        assert len(alerts) >= 3

        # Status page
        status = monitor.get_status()
        assert status["overall"] == "healthy"
        assert status["protocols"]["a2a"]["total_requests"] == 18
