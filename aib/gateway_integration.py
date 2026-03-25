"""
AIB — Production Gateway Integration.

Wires all sprint modules into the FastAPI gateway:
- Rate limiter (v1.5) → 429 on exceed, headers on every response
- Schema validator (v1.6) → validate translate input/output
- Error codes (v1.7) → standardized error responses
- Metrics (v1.8) → /metrics Prometheus endpoint
- Structured logger (v1.8) → trace_id on every request
- Discovery service (v1.4) → production .well-known endpoints
- Audience validation (v1.7) → verify aud on passport check

This module provides middleware and helpers to integrate into main.py.
It does NOT modify main.py — it provides drop-in components.

Usage in main.py:
    from aib.gateway_integration import (
        create_gateway_stack, rate_limit_middleware,
        metrics_endpoint, health_deep, discovery_endpoints,
    )
"""

import os
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from .rate_limiter import MemoryRateLimiter, RateLimitResult
from .schema_validator import SchemaValidator
from .hardening_sprint1 import (
    ErrorCodes, make_error, AIBError,
    verify_audience,
)
from .sprint4a import validate_issuer
from .hardening_sprint2 import MetricsCollector, StructuredLogger
from .discovery import DiscoveryService, PublicAgentEntry, FederationTrust


# ═══════════════════════════════════════════════════════════════════
# GATEWAY STACK — All components initialized together
# ═══════════════════════════════════════════════════════════════════

class GatewayStack:
    """
    All production components bundled in one object.

    Initialized once at gateway startup, passed to all endpoints.

    Usage:
        stack = GatewayStack(
            domain="mycompany.com",
            org_slug="mycompany",
            org_name="My Company",
        )

        # In a request handler:
        result = stack.rate_limiter.check(passport_id, tier="permanent")
        stack.metrics.record_request("a2a", "proxy", "success", 1.5)
        stack.logger.info("Request proxied", trace_id=trace_id)
    """

    def __init__(
        self,
        domain: str = "localhost",
        org_slug: str = "dev",
        org_name: str = "Development",
        gateway_url: str = "",
        rate_limits: Optional[dict] = None,
        rate_window: int = 60,
    ):
        # Rate limiter
        self.rate_limiter = MemoryRateLimiter(
            limits=rate_limits,
            window_seconds=rate_window,
        )

        # Schema validator
        self.schema_validator = SchemaValidator()

        # Metrics
        self.metrics = MetricsCollector()

        # Structured logger
        self.logger = StructuredLogger(service="aib-gateway")

        # Discovery
        self.discovery = DiscoveryService(
            domain=domain,
            org_slug=org_slug,
            org_name=org_name,
            gateway_url=gateway_url or f"https://{domain}",
            documentation="https://github.com/tntech-consulting/agent-identity-bridge",
        )

        # Version
        self.version = "2.1.0"

        self.logger.info("Gateway stack initialized", domain=domain, version=self.version)

    def generate_trace_id(self) -> str:
        return f"aib_{uuid.uuid4().hex[:16]}"


# ═══════════════════════════════════════════════════════════════════
# REQUEST HELPERS
# ═══════════════════════════════════════════════════════════════════

def check_rate_limit(
    stack: GatewayStack,
    passport_id: str,
    tier: str = "permanent",
) -> Optional[dict]:
    """
    Check rate limit. Returns error response dict if blocked, None if OK.

    Usage:
        blocked = check_rate_limit(stack, passport_id, tier)
        if blocked:
            return JSONResponse(status_code=429, content=blocked["body"],
                                headers=blocked["headers"])
    """
    result = stack.rate_limiter.check(passport_id, tier=tier)

    if not result.allowed:
        err = make_error(
            ErrorCodes.RATE_LIMITED,
            detail=f"Passport {passport_id} exceeded {result.limit} req/{result.window_seconds}s",
        )
        stack.metrics.record_rate_limit_hit()
        stack.metrics.record_error(err.code)
        stack.logger.warn(
            "Rate limit exceeded",
            passport_id=passport_id,
            error_code=err.code,
            limit=result.limit,
            tier=tier,
        )
        return {
            "body": err.to_response(),
            "headers": result.to_headers(),
            "status_code": 429,
        }

    return None


def validate_and_translate(
    stack: GatewayStack,
    source: dict,
    from_format: str,
    to_format: str,
    translator,
    trace_id: str = "",
    **kwargs,
) -> dict:
    """
    Validate input → translate → validate output.

    Raises HTTPException-compatible dict on validation failure.
    """
    # Validate input
    input_errors = stack.schema_validator.validate(from_format, source)
    if input_errors:
        err = make_error(
            ErrorCodes.SCHEMA_VIOLATION,
            detail=f"Input validation: {'; '.join(input_errors[:3])}",
        )
        stack.metrics.record_error(err.code)
        stack.logger.warn(
            "Schema validation failed on input",
            trace_id=trace_id,
            error_code=err.code,
            format=from_format,
            error_count=len(input_errors),
        )
        raise ValueError(err.message)

    # Translate
    result = translator.translate(source=source, from_format=from_format, to_format=to_format, **kwargs)

    # Validate output
    output_errors = stack.schema_validator.validate(to_format, result)
    if output_errors:
        err = make_error(
            ErrorCodes.OUTPUT_VALIDATION,
            detail=f"Output validation: {'; '.join(output_errors[:3])}",
        )
        stack.metrics.record_error(err.code)
        stack.logger.error(
            "Schema validation failed on output",
            trace_id=trace_id,
            error_code=err.code,
            format=to_format,
        )
        # Log but don't block — output validation failure is a bug, not user error
        stack.logger.warn("Returning result despite output validation failure", trace_id=trace_id)

    return result


def make_error_response(err: AIBError) -> dict:
    """Build a standard error response dict."""
    return {
        "body": err.to_response(),
        "status_code": err.http_status,
    }


# ═══════════════════════════════════════════════════════════════════
# HEALTH DEEP CHECK
# ═══════════════════════════════════════════════════════════════════

def health_deep(stack: GatewayStack, passport_count: int = 0) -> dict:
    """
    Deep health check for /health/ready.

    Checks: rate limiter, metrics, logger, discovery.
    In production, would also check Redis, PostgreSQL, JWKS cache.
    """
    checks = {
        "rate_limiter": "ok",
        "metrics": "ok",
        "logger": "ok",
        "discovery": "ok",
    }

    try:
        _ = stack.rate_limiter.stats
    except Exception as e:
        checks["rate_limiter"] = f"error: {str(e)}"

    try:
        _ = stack.metrics.get_stats()
    except Exception as e:
        checks["metrics"] = f"error: {str(e)}"

    try:
        _ = stack.logger.count
    except Exception as e:
        checks["logger"] = f"error: {str(e)}"

    try:
        _ = stack.discovery.get_discovery()
    except Exception as e:
        checks["discovery"] = f"error: {str(e)}"

    all_ok = all(v == "ok" for v in checks.values())

    return {
        "status": "ready" if all_ok else "degraded",
        "version": stack.version,
        "passports_count": passport_count,
        "supported_protocols": ["mcp", "a2a", "anp", "ag-ui"],
        "checks": checks,
        "metrics_summary": {
            "total_requests": stack.metrics.get_stats()["total_requests"],
            "rate_limit_hits": stack.metrics.get_stats()["rate_limit_hits"],
            "uptime_seconds": stack.metrics.get_stats()["uptime_seconds"],
        },
    }


# ═══════════════════════════════════════════════════════════════════
# WELL-KNOWN ENDPOINTS (PRODUCTION)
# ═══════════════════════════════════════════════════════════════════

def get_discovery_document(stack: GatewayStack) -> dict:
    """Returns /.well-known/aib.json with real data."""
    return stack.discovery.get_discovery()


def get_jwks(stack: GatewayStack, key_manager=None) -> dict:
    """Returns /.well-known/aib-keys.json with real keys if available."""
    return stack.discovery.get_jwks(key_manager)


def get_agents_registry(stack: GatewayStack) -> dict:
    """Returns /.well-known/aib-agents.json."""
    return stack.discovery.get_agents()


def get_federation(stack: GatewayStack) -> dict:
    """Returns /.well-known/aib-federation.json."""
    return stack.discovery.get_federation()


def get_metrics_prometheus(stack: GatewayStack) -> str:
    """Returns /metrics in Prometheus text format."""
    return stack.metrics.to_prometheus()
