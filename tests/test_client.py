"""Tests for the AIB SDK client."""

import pytest
import json
from unittest.mock import MagicMock, patch
from aib.client import AIBClient, SendResult, Passport, VerifyResult, TranslateResult


class MockResponse:
    """Mock httpx response."""
    def __init__(self, status_code=200, data=None):
        self.status_code = status_code
        self._data = data or {}
        self.text = json.dumps(self._data)

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")


@pytest.fixture
def client():
    mock_http = MagicMock()
    c = AIBClient.__new__(AIBClient)
    c.api_key = None
    c.gateway_url = "http://localhost:8420"
    c.timeout = 30.0
    c._http = mock_http
    yield c, mock_http


class TestAIBClient:

    def test_init_default(self, client):
        c, _ = client
        assert c.gateway_url == "http://localhost:8420"

    def test_init_cloud(self):
        c = AIBClient.__new__(AIBClient)
        c.api_key = "aib_sk_test123"
        c.gateway_url = "http://localhost:8420"
        c.timeout = 30.0
        # Simulate the cloud detection logic
        if c.api_key and c.api_key.startswith("aib_sk_"):
            c.gateway_url = "https://gateway.aib.cloud"
        assert c.gateway_url == "https://gateway.aib.cloud"

    def test_repr(self, client):
        c, _ = client
        assert "localhost:8420" in repr(c)

    def test_send_success(self, client):
        c, mock_http = client
        mock_http.post.return_value = MockResponse(200, {
            "detected_protocol": "a2a",
            "trace_id": "abc123def456",
            "upstream_status": 200,
            "response": {"result": "booked"},
            "passport_id": "urn:aib:agent:test:bot",
        })

        result = c.send("https://partner.com/agent", {"task": "book"})

        assert isinstance(result, SendResult)
        assert result.success is True
        assert result.protocol == "a2a"
        assert result.trace_id == "abc123def456"
        assert result.data == {"result": "booked"}
        assert result.latency_ms > 0

    def test_send_failure(self, client):
        c, mock_http = client
        mock_http.post.return_value = MockResponse(502, {"error": "upstream down"})

        result = c.send("https://partner.com/agent", {"task": "book"})

        assert result.success is False
        assert result.status_code == 502

    def test_send_repr(self, client):
        r = SendResult(True, "mcp", "abc123def456789", 200, {}, 42.5)
        assert "mcp" in repr(r)
        assert "42ms" in repr(r)

    def test_create_passport(self, client):
        c, mock_http = client
        mock_http.post.return_value = MockResponse(200, {
            "passport": {
                "passport_id": "urn:aib:agent:myco:bot",
                "display_name": "myco/bot",
                "protocol_bindings": {"mcp": {}, "a2a": {}},
                "capabilities": ["booking"],
                "expires_at": "2027-03-24T00:00:00Z",
            },
            "token": "eyJ...",
        })

        p = c.create_passport(org="myco", agent="bot", protocols=["mcp", "a2a"])

        assert isinstance(p, Passport)
        assert p.passport_id == "urn:aib:agent:myco:bot"
        assert p.protocols == ["mcp", "a2a"]
        assert p.token == "eyJ..."

    def test_passport_repr(self):
        p = Passport("urn:aib:agent:x:y", "x/y", ["mcp"], ["search"], "2027-01-01T00:00:00Z")
        assert "x:y" in repr(p)
        assert "mcp" in repr(p)

    def test_verify_valid(self, client):
        c, mock_http = client
        mock_http.post.return_value = MockResponse(200, {
            "valid": True,
            "passport": {
                "passport_id": "urn:aib:agent:test:bot",
                "issuer": "urn:aib:org:test",
                "protocol_bindings": {"mcp": {}},
                "expires_at": "2027-01-01T00:00:00Z",
            }
        })

        result = c.verify("eyJ...")

        assert isinstance(result, VerifyResult)
        assert result.valid is True
        assert bool(result) is True
        assert result.passport_id == "urn:aib:agent:test:bot"

    def test_verify_invalid(self, client):
        c, mock_http = client
        mock_http.post.return_value = MockResponse(200, {
            "valid": False,
            "reason": "Passport expired",
        })

        result = c.verify("eyJ...")

        assert result.valid is False
        assert bool(result) is False
        assert "expired" in result.reason.lower()

    def test_revoke(self, client):
        c, mock_http = client
        mock_http.post.return_value = MockResponse(200, {"revoked": True})

        assert c.revoke("urn:aib:agent:test:bot") is True

    def test_list_passports(self, client):
        c, mock_http = client
        mock_http.get.return_value = MockResponse(200, {
            "passports": [
                {
                    "passport_id": "urn:aib:agent:test:a",
                    "display_name": "test/a",
                    "protocol_bindings": {"mcp": {}},
                    "capabilities": ["search"],
                    "expires_at": "2027-01-01",
                },
                {
                    "passport_id": "urn:aib:agent:test:b",
                    "display_name": "test/b",
                    "protocol_bindings": {"a2a": {}, "anp": {}},
                    "capabilities": ["booking"],
                    "expires_at": "2027-06-01",
                },
            ]
        })

        passports = c.list_passports()

        assert len(passports) == 2
        assert passports[0].passport_id == "urn:aib:agent:test:a"
        assert passports[1].protocols == ["a2a", "anp"]

    def test_translate(self, client):
        c, mock_http = client
        mock_http.post.return_value = MockResponse(200, {
            "name": "Test Agent",
            "server_url": "https://example.com",
            "tools": [{"name": "search", "description": "Search"}],
        })

        result = c.translate(
            source={"name": "Test", "skills": [{"id": "s1"}]},
            from_format="a2a",
            to_format="mcp",
        )

        assert isinstance(result, TranslateResult)
        assert result.source_format == "a2a"
        assert result.target_format == "mcp"
        assert result.tools_count == 1
        assert "a2a" in repr(result)
        assert "mcp" in repr(result)

    def test_get_audit(self, client):
        c, mock_http = client
        mock_http.get.return_value = MockResponse(200, {
            "entries": [
                {"timestamp": "2026-03-24T12:00:00", "action": "proxy", "protocol": "a2a"},
                {"timestamp": "2026-03-24T12:01:00", "action": "translate", "protocol": "mcp"},
            ]
        })

        entries = c.get_audit(passport_id="urn:aib:agent:test:bot")
        assert len(entries) == 2
        assert entries[0]["protocol"] == "a2a"

    def test_health(self, client):
        c, mock_http = client
        mock_http.get.return_value = MockResponse(200, {"status": "ok", "version": "0.3.0"})

        health = c.health()
        assert health["status"] == "ok"

    def test_context_manager(self, client):
        c, mock_http = client
        with c as ctx:
            assert ctx is c
        mock_http.close.assert_called_once()
