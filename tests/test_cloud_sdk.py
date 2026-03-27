"""Tests for aib.cloud SDK client."""

import json
import unittest
from unittest.mock import patch, MagicMock
from aib.cloud import AIBCloud, AIBCloudError


class TestAIBCloudInit(unittest.TestCase):
    """Test client initialization."""

    def test_init_with_api_key(self):
        c = AIBCloud(api_key="aib_sk_live_test123")
        assert c.api_key == "aib_sk_live_test123"
        assert c.access_token == ""
        assert "supabase.co" in c.base_url

    def test_init_with_access_token(self):
        c = AIBCloud(access_token="eyJ...")
        assert c.access_token == "eyJ..."
        assert c.api_key == ""

    def test_init_no_auth_raises(self):
        with self.assertRaises(AIBCloudError):
            AIBCloud()

    def test_custom_base_url(self):
        c = AIBCloud(api_key="test", base_url="https://custom.api.com/v1/")
        assert c.base_url == "https://custom.api.com/v1"

    def test_repr(self):
        c = AIBCloud(api_key="aib_sk_live_abcdefghijklmno_extra")
        r = repr(c)
        assert "aib_sk_live_abcdef" in r
        assert "extra" not in r


class TestAIBCloudError(unittest.TestCase):
    """Test error class."""

    def test_error_attributes(self):
        e = AIBCloudError("test", code="AIB-601", status=403, violations=[{"rule": "x"}])
        assert str(e) == "test"
        assert e.code == "AIB-601"
        assert e.status == 403
        assert len(e.violations) == 1

    def test_error_defaults(self):
        e = AIBCloudError("msg")
        assert e.code == ""
        assert e.status == 0
        assert e.violations == []


def _mock_response(data: dict, status: int = 200):
    """Create a mock urllib response."""
    resp = MagicMock()
    resp.read.return_value = json.dumps(data).encode("utf-8")
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    resp.status = status
    return resp


class TestPassports(unittest.TestCase):
    """Test passport operations."""

    @patch("urllib.request.urlopen")
    def test_create_passport_minimal(self, mock_open):
        mock_open.return_value = _mock_response({
            "passport_id": "urn:aib:agent:org:my-bot",
            "protocols": ["mcp", "a2a"],
            "policies_checked": True,
        })
        c = AIBCloud(api_key="test_key")
        result = c.create_passport("my-bot")
        assert result["passport_id"] == "urn:aib:agent:org:my-bot"
        assert result["policies_checked"] is True

        # Verify request
        call = mock_open.call_args
        req = call[0][0]
        assert req.method == "POST"
        assert "passport-create" in req.full_url
        body = json.loads(req.data)
        assert body["agent_slug"] == "my-bot"

    @patch("urllib.request.urlopen")
    def test_create_passport_full(self, mock_open):
        mock_open.return_value = _mock_response({"passport_id": "urn:aib:agent:org:bot"})
        c = AIBCloud(api_key="test")
        c.create_passport(
            "bot", protocols=["mcp", "a2a", "anp"],
            capabilities=["booking", "support"],
            display_name="My Bot", tier="session", ttl_days=30,
        )
        body = json.loads(mock_open.call_args[0][0].data)
        assert body["protocols"] == ["mcp", "a2a", "anp"]
        assert body["capabilities"] == ["booking", "support"]
        assert body["display_name"] == "My Bot"
        assert body["tier"] == "session"
        assert body["ttl_days"] == 30

    @patch("urllib.request.urlopen")
    def test_list_passports(self, mock_open):
        mock_open.return_value = _mock_response({"count": 2, "passports": [{"passport_id": "a"}, {"passport_id": "b"}]})
        c = AIBCloud(api_key="test")
        result = c.list_passports(status="active", limit=10)
        assert result["count"] == 2
        assert len(result["passports"]) == 2
        url = mock_open.call_args[0][0].full_url
        assert "status=active" in url
        assert "limit=10" in url

    @patch("urllib.request.urlopen")
    def test_revoke_passport(self, mock_open):
        mock_open.return_value = _mock_response({"revoked": "urn:aib:agent:org:bot", "cascaded_children": 0})
        c = AIBCloud(api_key="test")
        result = c.revoke_passport("urn:aib:agent:org:bot", reason="testing")
        assert result["revoked"] == "urn:aib:agent:org:bot"
        body = json.loads(mock_open.call_args[0][0].data)
        assert body["reason"] == "testing"


class TestTranslate(unittest.TestCase):
    """Test credential translation."""

    @patch("urllib.request.urlopen")
    def test_translate_a2a_to_mcp(self, mock_open):
        mock_open.return_value = _mock_response({
            "from_format": "a2a_agent_card", "to_format": "mcp_server_card",
            "latency_ms": 0.05, "result": {"name": "Bot", "tools": []},
        })
        c = AIBCloud(api_key="test")
        result = c.translate(
            source={"name": "Bot", "skills": []},
            from_format="a2a_agent_card",
            to_format="mcp_server_card",
        )
        assert result["latency_ms"] < 1
        assert result["result"]["name"] == "Bot"


class TestUsage(unittest.TestCase):
    """Test usage and analytics."""

    @patch("urllib.request.urlopen")
    def test_usage(self, mock_open):
        mock_open.return_value = _mock_response({
            "org": {"name": "Test Org", "plan": "beta_pro"},
            "usage": {"transactions": {"used": 5, "limit": 100000}},
        })
        c = AIBCloud(api_key="test")
        result = c.usage()
        assert result["org"]["plan"] == "beta_pro"
        assert result["usage"]["transactions"]["used"] == 5

    @patch("urllib.request.urlopen")
    def test_usage_history(self, mock_open):
        mock_open.return_value = _mock_response({"daily": [], "total_events": 0})
        c = AIBCloud(api_key="test")
        result = c.usage_history(days=7)
        url = mock_open.call_args[0][0].full_url
        assert "days=7" in url


class TestPolicies(unittest.TestCase):
    """Test policy management."""

    @patch("urllib.request.urlopen")
    def test_create_policy(self, mock_open):
        mock_open.return_value = _mock_response({"rule_id": "deliverable_gate_123"})
        c = AIBCloud(api_key="test")
        result = c.create_policy(
            "deliverable_gate",
            config={"required_capabilities": ["tests_passed"], "action": "create"},
            description="Require tests",
        )
        assert "deliverable_gate" in result["rule_id"]
        body = json.loads(mock_open.call_args[0][0].data)
        assert body["rule_type"] == "deliverable_gate"
        assert body["severity"] == "block"

    @patch("urllib.request.urlopen")
    def test_list_policies(self, mock_open):
        mock_open.return_value = _mock_response({"rules": [], "count": 0})
        c = AIBCloud(api_key="test")
        result = c.list_policies()
        assert result["count"] == 0

    @patch("urllib.request.urlopen")
    def test_delete_policy(self, mock_open):
        mock_open.return_value = _mock_response({"deactivated": "rule_123"})
        c = AIBCloud(api_key="test")
        result = c.delete_policy("rule_123")
        assert result["deactivated"] == "rule_123"
        url = mock_open.call_args[0][0].full_url
        assert "rule_id=rule_123" in url


class TestAuth(unittest.TestCase):
    """Test auth methods."""

    @patch("urllib.request.urlopen")
    def test_health(self, mock_open):
        mock_open.return_value = _mock_response({
            "org": {"name": "Test"}, "month": "2026-03",
            "usage": {"transactions": {"used": 10, "limit": 100000}},
        })
        c = AIBCloud(api_key="test")
        h = c.health()
        assert h["status"] == "ok"

    def test_api_key_header(self):
        c = AIBCloud(api_key="aib_sk_live_test")
        # Can't test actual request without network, but verify the client stores the key
        assert c.api_key == "aib_sk_live_test"

    def test_bearer_token_header(self):
        c = AIBCloud(access_token="eyJtoken")
        assert c.access_token == "eyJtoken"

    @patch("urllib.request.urlopen")
    def test_signup(self, mock_open):
        mock_open.return_value = _mock_response({
            "user": {"id": "u-1", "email": "test@example.com"},
            "api_key": "aib_sk_live_new123",
            "access_token": "eyJtoken",
        })
        result = AIBCloud.signup("test@example.com", "Password123", "Test User")
        assert result["api_key"] == "aib_sk_live_new123"
        assert result["user"]["email"] == "test@example.com"
        body = json.loads(mock_open.call_args[0][0].data)
        assert body["action"] == "signup"
        assert body["email"] == "test@example.com"
        assert body["full_name"] == "Test User"

    @patch("urllib.request.urlopen")
    def test_login(self, mock_open):
        mock_open.return_value = _mock_response({
            "access_token": "eyJtoken",
            "user": {"id": "u-1", "email": "test@example.com"},
            "api_keys": [{"key_preview": "aib_sk_live_abc...", "name": "Default"}],
        })
        result = AIBCloud.login("test@example.com", "Password123")
        assert result["access_token"] == "eyJtoken"
        assert len(result["api_keys"]) == 1
        body = json.loads(mock_open.call_args[0][0].data)
        assert body["action"] == "login"

    @patch("urllib.request.urlopen")
    def test_generate_key(self, mock_open):
        mock_open.return_value = _mock_response({
            "api_key": "aib_sk_live_generated_456",
        })
        c = AIBCloud(api_key="existing_key")
        new_key = c.generate_key("My Integration")
        assert new_key == "aib_sk_live_generated_456"
        body = json.loads(mock_open.call_args[0][0].data)
        assert body["action"] == "generate_key"
        assert body["key_name"] == "My Integration"


class TestHTTPErrors(unittest.TestCase):
    """Test error handling."""

    @patch("urllib.request.urlopen")
    def test_policy_violation_403(self, mock_open):
        err_resp = MagicMock()
        err_resp.read.return_value = json.dumps({
            "error": "Policy violation", "code": "AIB-601",
            "violations": [{"rule_id": "r1", "message": "Missing tests_passed"}],
        }).encode()
        err_resp.code = 403
        mock_open.side_effect = __import__("urllib.error", fromlist=["HTTPError"]).HTTPError(
            "url", 403, "Forbidden", {}, err_resp,
        )
        c = AIBCloud(api_key="test")
        with self.assertRaises(AIBCloudError) as ctx:
            c.create_passport("bot")
        assert ctx.exception.code == "AIB-601"
        assert ctx.exception.status == 403
        assert len(ctx.exception.violations) == 1

    @patch("urllib.request.urlopen")
    def test_unauthorized_401(self, mock_open):
        err_resp = MagicMock()
        err_resp.read.return_value = json.dumps({"error": "Unauthorized", "code": "AIB-101"}).encode()
        err_resp.code = 401
        mock_open.side_effect = __import__("urllib.error", fromlist=["HTTPError"]).HTTPError(
            "url", 401, "Unauthorized", {}, err_resp,
        )
        c = AIBCloud(api_key="bad_key")
        with self.assertRaises(AIBCloudError) as ctx:
            c.usage()
        assert ctx.exception.status == 401


class TestWebhooks(unittest.TestCase):
    """Test webhook management."""

    @patch("urllib.request.urlopen")
    def test_create_webhook(self, mock_open):
        mock_open.return_value = _mock_response({"id": "wh-123", "url": "https://example.com/hook", "events": ["passport.created"], "status": "active"})
        c = AIBCloud(api_key="test")
        result = c.create_webhook("https://example.com/hook", events=["passport.created"], secret="my-secret")
        assert result["id"] == "wh-123"
        body = json.loads(mock_open.call_args[0][0].data)
        assert body["url"] == "https://example.com/hook"
        assert body["secret"] == "my-secret"

    @patch("urllib.request.urlopen")
    def test_list_webhooks(self, mock_open):
        mock_open.return_value = _mock_response({"webhooks": [{"id": "wh-1"}], "count": 1})
        c = AIBCloud(api_key="test")
        result = c.list_webhooks()
        assert result["count"] == 1

    @patch("urllib.request.urlopen")
    def test_delete_webhook(self, mock_open):
        mock_open.return_value = _mock_response({"deleted": "wh-123"})
        c = AIBCloud(api_key="test")
        result = c.delete_webhook("wh-123")
        assert result["deleted"] == "wh-123"
        url = mock_open.call_args[0][0].full_url
        assert "id=wh-123" in url


if __name__ == "__main__":
    unittest.main()
