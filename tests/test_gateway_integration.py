"""Tests for gateway integration — wiring all sprint modules together."""

import pytest
from aib.gateway_integration import (
    GatewayStack, check_rate_limit, validate_and_translate,
    make_error_response, health_deep,
    get_discovery_document, get_jwks, get_agents_registry,
    get_federation, get_metrics_prometheus,
)
from aib.translator import CredentialTranslator
from aib.hardening_sprint1 import ErrorCodes
from aib.discovery import PublicAgentEntry, FederationTrust


@pytest.fixture
def stack():
    return GatewayStack(
        domain="test.com",
        org_slug="test",
        org_name="Test Corp",
        rate_limits={"permanent": 5, "session": 2, "ephemeral": 1},
        rate_window=1,
    )


# ═══════════════════════════════════════════════════════════════════
# STACK INITIALIZATION
# ═══════════════════════════════════════════════════════════════════

class TestGatewayStack:

    def test_init(self, stack):
        assert stack.version == "2.1.0"
        assert stack.rate_limiter is not None
        assert stack.schema_validator is not None
        assert stack.metrics is not None
        assert stack.logger is not None
        assert stack.discovery is not None

    def test_trace_id(self, stack):
        tid = stack.generate_trace_id()
        assert tid.startswith("aib_")
        assert len(tid) == 20

    def test_logger_recorded_init(self, stack):
        entries = stack.logger.get_entries(level="INFO")
        assert any("initialized" in e["message"] for e in entries)


# ═══════════════════════════════════════════════════════════════════
# RATE LIMITING INTEGRATION
# ═══════════════════════════════════════════════════════════════════

class TestRateLimitIntegration:

    def test_allowed(self, stack):
        result = check_rate_limit(stack, "agent-1", "permanent")
        assert result is None  # None = allowed

    def test_blocked_returns_error(self, stack):
        for _ in range(5):
            check_rate_limit(stack, "agent-1", "permanent")

        result = check_rate_limit(stack, "agent-1", "permanent")
        assert result is not None
        assert result["status_code"] == 429
        assert "AIB-303" in str(result["body"])
        assert "Retry-After" in result["headers"]

    def test_blocked_records_metric(self, stack):
        for _ in range(5):
            check_rate_limit(stack, "agent-1", "permanent")
        check_rate_limit(stack, "agent-1", "permanent")  # Blocked

        stats = stack.metrics.get_stats()
        assert stats["rate_limit_hits"] >= 1
        assert "AIB-303" in stats["errors_by_code"]

    def test_blocked_logs_warning(self, stack):
        for _ in range(5):
            check_rate_limit(stack, "agent-1", "permanent")
        check_rate_limit(stack, "agent-1", "permanent")

        warns = stack.logger.get_entries(level="WARN")
        assert any("rate limit" in e["message"].lower() for e in warns)


# ═══════════════════════════════════════════════════════════════════
# SCHEMA VALIDATION INTEGRATION
# ═══════════════════════════════════════════════════════════════════

class TestSchemaValidationIntegration:

    def test_valid_translation(self, stack):
        source = {
            "name": "Booking Agent",
            "url": "https://example.com",
            "skills": [{"id": "book", "name": "Book Hotel"}],
        }
        translator = CredentialTranslator()
        result = validate_and_translate(
            stack, source, "a2a_agent_card", "mcp_server_card", translator, trace_id="t1",
        )
        assert result["name"] == "Booking Agent"
        assert "tools" in result

    def test_invalid_input_raises(self, stack):
        translator = CredentialTranslator()
        with pytest.raises(ValueError):
            validate_and_translate(
                stack, {}, "a2a_agent_card", "mcp_server_card", translator, trace_id="t2",
            )

    def test_invalid_input_records_error(self, stack):
        translator = CredentialTranslator()
        try:
            validate_and_translate(stack, {}, "a2a_agent_card", "mcp_server_card", translator)
        except ValueError:
            pass
        stats = stack.metrics.get_stats()
        assert "AIB-202" in stats["errors_by_code"]


# ═══════════════════════════════════════════════════════════════════
# ERROR RESPONSES
# ═══════════════════════════════════════════════════════════════════

class TestErrorResponses:

    def test_make_error_response(self):
        resp = make_error_response(ErrorCodes.PASSPORT_NOT_FOUND)
        assert resp["status_code"] == 404
        assert "AIB-001" in str(resp["body"])

    def test_no_detail_in_response(self):
        from aib.hardening_sprint1 import make_error
        err = make_error(ErrorCodes.INTERNAL_ERROR, detail="PostgreSQL connection refused")
        resp = make_error_response(err)
        assert "PostgreSQL" not in str(resp["body"])


# ═══════════════════════════════════════════════════════════════════
# HEALTH CHECK
# ═══════════════════════════════════════════════════════════════════

class TestHealthDeep:

    def test_healthy(self, stack):
        h = health_deep(stack, passport_count=42)
        assert h["status"] == "ready"
        assert h["passports_count"] == 42
        assert h["version"] == "2.1.0"
        assert all(v == "ok" for v in h["checks"].values())

    def test_protocols_listed(self, stack):
        h = health_deep(stack)
        assert "mcp" in h["supported_protocols"]
        assert "ag-ui" in h["supported_protocols"]

    def test_metrics_summary(self, stack):
        stack.metrics.record_request("mcp", "proxy", "success", 1.0)
        h = health_deep(stack)
        assert h["metrics_summary"]["total_requests"] == 1


# ═══════════════════════════════════════════════════════════════════
# DISCOVERY ENDPOINTS
# ═══════════════════════════════════════════════════════════════════

class TestDiscoveryIntegration:

    def test_discovery_document(self, stack):
        doc = get_discovery_document(stack)
        assert doc["domain"] == "test.com"
        assert doc["issuer"] == "urn:aib:org:test"
        assert "mcp" in doc["supported_protocols"]

    def test_jwks_no_manager(self, stack):
        jwks = get_jwks(stack)
        assert "keys" in jwks

    def test_jwks_with_manager(self, stack):
        class FakeKM:
            def jwks(self):
                return {"keys": [{"kid": "k1", "kty": "RSA"}]}
        jwks = get_jwks(stack, key_manager=FakeKM())
        assert jwks["keys"][0]["kid"] == "k1"

    def test_agents_registry(self, stack):
        stack.discovery.register_agent(PublicAgentEntry(
            passport_id="urn:aib:agent:test:bot",
            display_name="Bot",
            capabilities=["support"],
            protocols=["mcp"],
        ))
        reg = get_agents_registry(stack)
        assert reg["total_agents"] == 1

    def test_federation(self, stack):
        stack.discovery.add_federation_trust(FederationTrust(
            domain="partner.com",
            issuer="urn:aib:org:partner",
            jwks_uri="https://partner.com/.well-known/aib-keys.json",
        ))
        fed = get_federation(stack)
        assert fed["total_trusted"] == 1


# ═══════════════════════════════════════════════════════════════════
# METRICS ENDPOINT
# ═══════════════════════════════════════════════════════════════════

class TestMetricsEndpoint:

    def test_prometheus_format(self, stack):
        stack.metrics.record_request("a2a", "proxy", "success", 2.0)
        stack.metrics.record_error("AIB-001")
        output = get_metrics_prometheus(stack)
        assert "aib_requests_total 1" in output
        assert 'aib_errors_total{code="AIB-001"} 1' in output

    def test_empty_metrics(self, stack):
        output = get_metrics_prometheus(stack)
        assert "aib_requests_total 0" in output


# ═══════════════════════════════════════════════════════════════════
# END-TO-END SCENARIO
# ═══════════════════════════════════════════════════════════════════

class TestEndToEnd:

    def test_full_request_lifecycle(self, stack):
        """Simulate a complete gateway request with all checks."""
        trace_id = stack.generate_trace_id()
        passport_id = "urn:aib:agent:test:booking"

        # 1. Rate limit check
        blocked = check_rate_limit(stack, passport_id, "permanent")
        assert blocked is None

        # 2. Validate + translate
        source = {
            "name": "Booking Agent",
            "skills": [{"id": "book", "name": "Book"}],
        }
        translator = CredentialTranslator()
        result = validate_and_translate(
            stack, source, "a2a_agent_card", "mcp_server_card", translator, trace_id=trace_id,
        )
        assert "tools" in result

        # 3. Record metrics
        stack.metrics.record_request("a2a", "translate", "success", 0.5)

        # 4. Log
        stack.logger.info(
            "Translation complete",
            trace_id=trace_id,
            passport_id=passport_id,
            protocol="a2a",
            action="translate",
            latency_ms=0.5,
        )

        # 5. Verify health
        h = health_deep(stack, passport_count=1)
        assert h["status"] == "ready"
        assert h["metrics_summary"]["total_requests"] == 1

        # 6. Check logs
        entries = stack.logger.get_entries(limit=5)
        assert any(e.get("trace_id") == trace_id for e in entries)
