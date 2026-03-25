"""
AIB — Security Patches: Output Validation + OIDC Dev Guard.

Two targeted fixes for the two most exploitable attack vectors:

1. OUTPUT VALIDATION (Translation Injection mitigation)
   The translator validates INPUT but not OUTPUT. An attacker can craft
   an input that passes input validation but whose translation produces
   a dangerous document. This module validates translator OUTPUT before
   it's returned to the caller.

2. OIDC DEV GUARD
   verify_signature=False in OIDCBridge.exchange() allows token forging.
   This guard ensures it only works when AIB_ENV=development.

These are surgical patches — they wrap existing functions, not rewrite them.
"""

import os
import json
import re
from typing import Optional
from urllib.parse import urlparse
from functools import wraps


# ═══════════════════════════════════════════════════════════════════
# 1. OUTPUT VALIDATION — Translator output sanitization
# ═══════════════════════════════════════════════════════════════════

class OutputValidationError(ValueError):
    """Raised when translator output fails validation."""
    pass


# Maximum sizes for output documents
OUTPUT_MAX_FIELD_LENGTH = 1000
OUTPUT_MAX_URL_LENGTH = 2048
OUTPUT_MAX_ARRAY_ITEMS = 50
OUTPUT_MAX_DOCUMENT_SIZE = 51200  # 50KB — output should be smaller than input
OUTPUT_MAX_SCOPE_LENGTH = 100
OUTPUT_MAX_SCOPES_COUNT = 20

# Dangerous patterns that should NEVER appear in output
_DANGEROUS_URL_PATTERNS = [
    r"javascript:",
    r"data:",
    r"vbscript:",
    r"file://",
    r"ftp://",
    r"gopher://",
    r"ldap://",
    r"localhost",
    r"127\.0\.0\.1",
    r"0\.0\.0\.0",
    r"169\.254\.",             # AWS/GCP metadata
    r"metadata\.google",
    r"10\.\d+\.\d+\.\d+",    # Private range
    r"192\.168\.",             # Private range
    r"172\.(1[6-9]|2\d|3[01])\.",  # Private range
]

_DANGEROUS_PATTERNS_COMPILED = [re.compile(p, re.IGNORECASE) for p in _DANGEROUS_URL_PATTERNS]

# Scope/permission escalation patterns
_ESCALATION_PATTERNS = [
    r"\badmin\b",
    r"\broot\b",
    r"\bsuperuser\b",
    r"\*",                    # Wildcard scope
    r"\ball\b",
]

_ESCALATION_COMPILED = [re.compile(p, re.IGNORECASE) for p in _ESCALATION_PATTERNS]


def validate_output_url(url: str, field_name: str) -> str:
    """
    Validate a URL in translator output.

    Checks for:
    - Dangerous schemes (javascript:, data:, file://)
    - Private/internal IPs
    - Metadata endpoints
    - Excessive length
    """
    if not url:
        return url

    if len(url) > OUTPUT_MAX_URL_LENGTH:
        raise OutputValidationError(
            f"Output {field_name}: URL exceeds {OUTPUT_MAX_URL_LENGTH} chars"
        )

    url_lower = url.lower().strip()

    for pattern in _DANGEROUS_PATTERNS_COMPILED:
        if pattern.search(url_lower):
            raise OutputValidationError(
                f"Output {field_name}: dangerous URL pattern detected in '{url[:80]}...'"
            )

    parsed = urlparse(url)
    if parsed.scheme and parsed.scheme not in ("https", "http", "wss", "ws"):
        raise OutputValidationError(
            f"Output {field_name}: disallowed scheme '{parsed.scheme}'"
        )

    if parsed.username or parsed.password:
        raise OutputValidationError(
            f"Output {field_name}: embedded credentials in URL"
        )

    return url


def validate_output_string(value: str, field_name: str, max_length: int = OUTPUT_MAX_FIELD_LENGTH) -> str:
    """Validate a string field in translator output."""
    if not isinstance(value, str):
        raise OutputValidationError(
            f"Output {field_name}: expected string, got {type(value).__name__}"
        )

    # Control characters
    control_chars = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
    if control_chars.search(value):
        raise OutputValidationError(
            f"Output {field_name}: contains control characters"
        )

    if len(value) > max_length:
        raise OutputValidationError(
            f"Output {field_name}: exceeds {max_length} chars (got {len(value)})"
        )

    return value


def validate_output_scopes(scopes: list, field_name: str, check_escalation: bool = True) -> list:
    """
    Validate scopes/permissions in translator output.

    Catches privilege escalation: if the translation produces scopes
    like 'admin', 'root', or wildcard '*' that weren't in the source.
    """
    if not isinstance(scopes, list):
        raise OutputValidationError(
            f"Output {field_name}: expected list, got {type(scopes).__name__}"
        )

    if len(scopes) > OUTPUT_MAX_SCOPES_COUNT:
        raise OutputValidationError(
            f"Output {field_name}: too many scopes ({len(scopes)} > {OUTPUT_MAX_SCOPES_COUNT})"
        )

    escalations = []
    for scope in scopes:
        if not isinstance(scope, str):
            continue
        if len(scope) > OUTPUT_MAX_SCOPE_LENGTH:
            raise OutputValidationError(
                f"Output {field_name}: scope '{scope[:30]}...' exceeds max length"
            )
        if check_escalation:
            for pattern in _ESCALATION_COMPILED:
                if pattern.search(scope):
                    escalations.append(scope)

    if escalations:
        raise OutputValidationError(
            f"Output {field_name}: potential privilege escalation detected "
            f"in scopes: {escalations}. These scopes should not appear in "
            f"translated output unless explicitly in the source document."
        )

    return scopes


def validate_output_document_size(doc: dict, max_bytes: int = OUTPUT_MAX_DOCUMENT_SIZE) -> dict:
    """Check output document doesn't exceed size limits."""
    size = len(json.dumps(doc, ensure_ascii=False).encode())
    if size > max_bytes:
        raise OutputValidationError(
            f"Output document exceeds {max_bytes} bytes (got {size})"
        )
    return doc


# ── Full output validators per format ─────────────────────────────

def validate_mcp_output(card: dict) -> dict:
    """
    Validate a translated MCP Server Card output.

    Catches:
    - Dangerous URLs in server_url
    - Oversized tool lists
    - Control characters in names/descriptions
    - Privilege escalation in scopes
    """
    validate_output_document_size(card)

    if "server_url" in card:
        validate_output_url(card["server_url"], "server_url")

    if "name" in card:
        validate_output_string(card["name"], "name", max_length=200)

    if "description" in card:
        validate_output_string(card["description"], "description", max_length=2000)

    if "tools" in card:
        tools = card["tools"]
        if not isinstance(tools, list):
            raise OutputValidationError("Output tools: expected list")
        if len(tools) > OUTPUT_MAX_ARRAY_ITEMS:
            raise OutputValidationError(
                f"Output tools: too many ({len(tools)} > {OUTPUT_MAX_ARRAY_ITEMS})"
            )
        for i, tool in enumerate(tools):
            if "name" in tool:
                validate_output_string(tool["name"], f"tools[{i}].name", max_length=200)
            if "description" in tool:
                validate_output_string(tool["description"], f"tools[{i}].description", max_length=2000)

    if "auth" in card and isinstance(card["auth"], dict):
        auth_type = card["auth"].get("type", "")
        if auth_type not in ("none", "bearer", "oauth2", "api_key", ""):
            raise OutputValidationError(
                f"Output auth.type: unexpected value '{auth_type}'"
            )
        if "flows" in card["auth"]:
            flows = card["auth"]["flows"]
            if isinstance(flows, dict):
                for flow_name, flow in flows.items():
                    if isinstance(flow, dict):
                        for url_field in ("authorizationUrl", "tokenUrl", "authorization_url", "token_url"):
                            if url_field in flow:
                                validate_output_url(flow[url_field], f"auth.flows.{flow_name}.{url_field}")
                        if "scopes" in flow:
                            if isinstance(flow["scopes"], list):
                                validate_output_scopes(flow["scopes"], f"auth.flows.{flow_name}.scopes")

    return card


def validate_a2a_output(card: dict) -> dict:
    """Validate a translated A2A Agent Card output."""
    validate_output_document_size(card)

    if "url" in card:
        validate_output_url(card["url"], "url")

    if "name" in card:
        validate_output_string(card["name"], "name", max_length=200)

    if "description" in card:
        validate_output_string(card["description"], "description", max_length=2000)

    if "skills" in card:
        skills = card["skills"]
        if not isinstance(skills, list):
            raise OutputValidationError("Output skills: expected list")
        if len(skills) > OUTPUT_MAX_ARRAY_ITEMS:
            raise OutputValidationError(
                f"Output skills: too many ({len(skills)} > {OUTPUT_MAX_ARRAY_ITEMS})"
            )
        for i, skill in enumerate(skills):
            if "name" in skill:
                validate_output_string(skill["name"], f"skills[{i}].name", max_length=200)
            if "id" in skill:
                validate_output_string(skill["id"], f"skills[{i}].id", max_length=200)

    if "authentication" in card and isinstance(card["authentication"], dict):
        schemes = card["authentication"].get("schemes", [])
        if isinstance(schemes, list):
            for scheme in schemes:
                if isinstance(scheme, str) and len(scheme) > 50:
                    raise OutputValidationError(
                        f"Output authentication.schemes: oversized scheme '{scheme[:30]}...'"
                    )

    return card


def validate_did_output(doc: dict) -> dict:
    """Validate a translated DID Document output."""
    validate_output_document_size(doc)

    if "id" in doc:
        did = doc["id"]
        validate_output_string(did, "id", max_length=500)
        if not did.startswith("did:"):
            raise OutputValidationError(
                f"Output id: DID must start with 'did:', got '{did[:30]}'"
            )

    if "service" in doc:
        services = doc["service"]
        if not isinstance(services, list):
            raise OutputValidationError("Output service: expected list")
        for i, svc in enumerate(services):
            if "serviceEndpoint" in svc:
                validate_output_url(svc["serviceEndpoint"], f"service[{i}].serviceEndpoint")

    if "verificationMethod" in doc:
        methods = doc["verificationMethod"]
        if isinstance(methods, list) and len(methods) > 20:
            raise OutputValidationError(
                f"Output verificationMethod: too many ({len(methods)} > 20)"
            )

    return doc


def validate_translator_output(output: dict, target_format: str) -> dict:
    """
    Main entry point: validate any translator output.

    Call this AFTER every translation, BEFORE returning the result.
    """
    validators = {
        "mcp_server_card": validate_mcp_output,
        "mcp": validate_mcp_output,
        "a2a_agent_card": validate_a2a_output,
        "a2a": validate_a2a_output,
        "did_document": validate_did_output,
        "did": validate_did_output,
    }

    validator = validators.get(target_format)
    if validator:
        return validator(output)

    # Unknown format — do generic validation
    validate_output_document_size(output)
    return output


# ═══════════════════════════════════════════════════════════════════
# 2. OIDC DEV GUARD — Prevent verify_signature=False in production
# ═══════════════════════════════════════════════════════════════════

class OIDCDevGuardError(RuntimeError):
    """Raised when verify_signature=False is used outside development."""
    pass


def is_development_mode() -> bool:
    """Check if we're running in development mode."""
    env = os.environ.get("AIB_ENV", "").lower()
    return env in ("development", "dev", "test", "testing", "local")


def guard_verify_signature(verify_signature: bool) -> bool:
    """
    Enforce that verify_signature=False only works in development.

    If AIB_ENV is not set to a development value and verify_signature
    is False, this raises OIDCDevGuardError.

    Usage in OIDCBridge.exchange():
        verify_signature = guard_verify_signature(verify_signature)
    """
    if verify_signature is False and not is_development_mode():
        raise OIDCDevGuardError(
            "verify_signature=False is only allowed when AIB_ENV is set to "
            "'development', 'dev', 'test', or 'local'. "
            "In production, OIDC tokens MUST be cryptographically verified. "
            "Set AIB_ENV=development to use this in local testing, or "
            "remove verify_signature=False for production use."
        )
    return verify_signature


def oidc_dev_guard(func):
    """
    Decorator for OIDCBridge.exchange() that enforces the dev guard.

    Apply to any function that accepts verify_signature as a kwarg.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "verify_signature" in kwargs:
            kwargs["verify_signature"] = guard_verify_signature(kwargs["verify_signature"])
        return func(*args, **kwargs)
    return wrapper
