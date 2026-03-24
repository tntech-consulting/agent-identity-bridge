"""Tests for the plugin system — auto-discovery, registration, detection."""

import pytest
from pathlib import Path
from aib.plugins import (
    ProtocolBinding, PluginRegistry,
    McpBinding, A2aBinding, AnpBinding, AgUiBinding,
)


@pytest.fixture
def registry():
    return PluginRegistry(auto_discover=False)


@pytest.fixture
def full_registry():
    return PluginRegistry(auto_discover=True)


class CustomTestBinding(ProtocolBinding):
    """A custom binding for testing."""
    protocol_name = "custom-test"
    display_name = "Custom Test Protocol"
    version = "0.1"
    description = "For unit tests"

    def to_passport_binding(self, native_card):
        return {"endpoint_url": native_card.get("url", ""), "auth_method": "token"}

    def from_passport_binding(self, binding):
        return {"url": binding.get("endpoint_url", ""), "type": "custom"}

    def detect_protocol(self, url):
        return "/custom-test/" in url


# ═══════════════════════════════════════════════════════════════════
# Built-in bindings
# ═══════════════════════════════════════════════════════════════════

class TestBuiltinBindings:

    def test_registry_has_4_builtins(self, registry):
        assert registry.count == 4
        assert "mcp" in registry
        assert "a2a" in registry
        assert "anp" in registry
        assert "ag-ui" in registry

    def test_mcp_binding(self, registry):
        mcp = registry.get("mcp")
        assert mcp.protocol_name == "mcp"
        assert mcp.display_name == "Model Context Protocol"

    def test_a2a_binding(self, registry):
        a2a = registry.get("a2a")
        assert a2a.protocol_name == "a2a"

    def test_anp_binding(self, registry):
        anp = registry.get("anp")
        assert anp.protocol_name == "anp"

    def test_agui_binding(self, registry):
        agui = registry.get("ag-ui")
        assert agui.protocol_name == "ag-ui"


# ═══════════════════════════════════════════════════════════════════
# Protocol detection
# ═══════════════════════════════════════════════════════════════════

class TestProtocolDetection:

    def test_detect_mcp(self, registry):
        assert registry.detect("https://example.com/mcp/tools/list") == "mcp"
        assert registry.detect("https://example.com/.well-known/mcp.json") == "mcp"

    def test_detect_a2a(self, registry):
        assert registry.detect("https://partner.com/a2a/tasks/send") == "a2a"
        assert registry.detect("https://partner.com/.well-known/agent.json") == "a2a"

    def test_detect_anp(self, registry):
        assert registry.detect("https://peer.org/anp/did:web:peer.org") == "anp"

    def test_detect_agui(self, registry):
        assert registry.detect("https://ui.app.com/ag-ui/events/subscribe") == "ag-ui"

    def test_detect_unknown(self, registry):
        assert registry.detect("https://random.com/api/v1/data") is None

    def test_detect_custom(self, registry):
        registry.register(CustomTestBinding())
        assert registry.detect("https://example.com/custom-test/endpoint") == "custom-test"


# ═══════════════════════════════════════════════════════════════════
# Registration
# ═══════════════════════════════════════════════════════════════════

class TestRegistration:

    def test_register_custom(self, registry):
        binding = CustomTestBinding()
        registry.register(binding)
        assert "custom-test" in registry
        assert registry.count == 5

    def test_register_no_name_raises(self, registry):
        class BadBinding(ProtocolBinding):
            protocol_name = ""
            def to_passport_binding(self, c): return {}
            def from_passport_binding(self, b): return {}
            def detect_protocol(self, u): return False
        with pytest.raises(ValueError, match="protocol_name"):
            registry.register(BadBinding())

    def test_unregister(self, registry):
        registry.register(CustomTestBinding())
        assert registry.unregister("custom-test") is True
        assert "custom-test" not in registry

    def test_unregister_nonexistent(self, registry):
        assert registry.unregister("doesnt-exist") is False

    def test_override_builtin(self, registry):
        """Custom binding can override a built-in."""
        class BetterMcp(ProtocolBinding):
            protocol_name = "mcp"
            display_name = "MCP v2"
            def to_passport_binding(self, c): return {"custom": True}
            def from_passport_binding(self, b): return {}
            def detect_protocol(self, u): return "/mcp-v2/" in u

        registry.register(BetterMcp())
        mcp = registry.get("mcp")
        assert mcp.display_name == "MCP v2"


# ═══════════════════════════════════════════════════════════════════
# Passport binding conversion
# ═══════════════════════════════════════════════════════════════════

class TestPassportConversion:

    def test_mcp_to_passport(self, registry):
        mcp = registry.get("mcp")
        card = {
            "name": "Calendar Service",
            "server_url": "https://calendar.api/mcp",
            "tools": [{"name": "create_event"}, {"name": "list_events"}],
            "auth": {"type": "oauth2"},
        }
        binding = mcp.to_passport_binding(card)
        assert binding["endpoint_url"] == "https://calendar.api/mcp"
        assert binding["auth_method"] == "oauth2"
        assert "create_event" in binding["tools"]

    def test_mcp_from_passport(self, registry):
        mcp = registry.get("mcp")
        binding = {"endpoint_url": "https://calendar.api/mcp", "auth_method": "oauth2"}
        card = mcp.from_passport_binding(binding)
        assert card["server_url"] == "https://calendar.api/mcp"
        assert card["transport"] == "streamable-http"

    def test_a2a_to_passport(self, registry):
        a2a = registry.get("a2a")
        card = {
            "name": "Booking Agent",
            "url": "https://partner.com/agent",
            "skills": [{"name": "booking"}, {"name": "search"}],
            "authentication": {"schemes": ["bearer"]},
        }
        binding = a2a.to_passport_binding(card)
        assert binding["endpoint_url"] == "https://partner.com/agent"
        assert binding["auth_method"] == "bearer"
        assert "booking" in binding["skills"]

    def test_anp_to_passport(self, registry):
        anp = registry.get("anp")
        did_doc = {
            "id": "did:web:peer.org:agents:bot",
            "service": [{"serviceEndpoint": "https://peer.org/anp"}],
        }
        binding = anp.to_passport_binding(did_doc)
        assert binding["did"] == "did:web:peer.org:agents:bot"
        assert binding["auth_method"] == "did-auth"

    def test_anp_from_passport(self, registry):
        anp = registry.get("anp")
        binding = {"endpoint_url": "https://peer.org/anp", "did": "did:web:peer.org:agents:bot"}
        doc = anp.from_passport_binding(binding)
        assert doc["id"] == "did:web:peer.org:agents:bot"
        assert doc["service"][0]["serviceEndpoint"] == "https://peer.org/anp"


# ═══════════════════════════════════════════════════════════════════
# Auto-discovery
# ═══════════════════════════════════════════════════════════════════

class TestAutoDiscovery:

    def test_auto_discovers_example(self, full_registry):
        assert "example" in full_registry
        example = full_registry.get("example")
        assert example.display_name == "Example Protocol"

    def test_full_registry_count(self, full_registry):
        # 4 builtins + 1 example
        assert full_registry.count >= 5

    def test_example_detection(self, full_registry):
        assert full_registry.detect("https://test.com/example-protocol/api") == "example"

    def test_example_passport_binding(self, full_registry):
        example = full_registry.get("example")
        card = {"url": "https://test.com/api", "id": "test-agent", "auth_type": "api_key"}
        binding = example.to_passport_binding(card)
        assert binding["endpoint_url"] == "https://test.com/api"
        assert binding["auth_method"] == "api_key"


# ═══════════════════════════════════════════════════════════════════
# Listing & repr
# ═══════════════════════════════════════════════════════════════════

class TestListing:

    def test_list_protocols(self, registry):
        protocols = registry.list_protocols()
        assert len(protocols) == 4
        names = [p["name"] for p in protocols]
        assert "mcp" in names
        assert "a2a" in names

    def test_list_shows_builtin_flag(self, registry):
        registry.register(CustomTestBinding())
        protocols = registry.list_protocols()
        custom = next(p for p in protocols if p["name"] == "custom-test")
        mcp = next(p for p in protocols if p["name"] == "mcp")
        assert custom["builtin"] is False
        assert mcp["builtin"] is True

    def test_supported_protocols(self, registry):
        names = registry.supported_protocols()
        assert "mcp" in names
        assert "a2a" in names

    def test_repr(self, registry):
        r = repr(registry)
        assert "4 protocols" in r
        assert "mcp" in r

    def test_binding_repr(self):
        b = McpBinding()
        assert "McpBinding" in repr(b)
        assert "mcp" in repr(b)

    def test_contains(self, registry):
        assert "mcp" in registry
        assert "nonexistent" not in registry
