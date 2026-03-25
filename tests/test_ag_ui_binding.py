"""Tests for Sprint 7 — AG-UI Protocol Binding."""

import pytest
from aib.ag_ui_binding import (
    AgUiBinding,
    create_ag_ui_descriptor, AG_UI_EVENTS, AG_UI_CAPABILITIES,
    ag_ui_to_a2a, a2a_to_ag_ui,
    ag_ui_to_mcp, mcp_to_ag_ui,
    validate_ag_ui_descriptor,
    map_ag_ui_event_to_audit_action,
)


# ═══════════════════════════════════════════════════════════════════
# 1. AG-UI BINDING
# ═══════════════════════════════════════════════════════════════════

class TestAgUiBinding:

    def test_default_binding(self):
        b = AgUiBinding(endpoint_url="https://myapp.com/api/agent")
        assert b.auth_method == "bearer"
        assert b.endpoint_url == "https://myapp.com/api/agent"
        assert b.a2ui_support is False

    def test_full_binding(self):
        b = AgUiBinding(
            auth_method="oauth2",
            endpoint_url="https://myapp.com/api/agent",
            ui_capabilities=["text_message", "tool_call", "generative_ui"],
            supported_events=["RUN_STARTED", "TEXT_MESSAGE_START", "TOOL_CALL_START"],
            a2ui_support=True,
            shared_state=True,
        )
        d = b.to_dict()
        assert d["a2ui_support"] is True
        assert d["shared_state"] is True
        assert len(d["ui_capabilities"]) == 3
        assert len(d["supported_events"]) == 3

    def test_to_dict(self):
        b = AgUiBinding(endpoint_url="https://test.com/agent")
        d = b.to_dict()
        assert "endpoint_url" in d
        assert "auth_method" in d
        assert "ui_capabilities" in d


# ═══════════════════════════════════════════════════════════════════
# 2. AG-UI DESCRIPTOR
# ═══════════════════════════════════════════════════════════════════

class TestAgUiDescriptor:

    def test_create_minimal(self):
        desc = create_ag_ui_descriptor(
            name="Test Agent",
            endpoint_url="https://myapp.com/api/agent",
        )
        assert desc["name"] == "Test Agent"
        assert desc["endpoint_url"] == "https://myapp.com/api/agent"
        assert "text_message" in desc["capabilities"]
        assert "RUN_STARTED" in desc["supported_events"]

    def test_create_full(self):
        desc = create_ag_ui_descriptor(
            name="Full Agent",
            endpoint_url="https://myapp.com/api/agent",
            description="A fully-featured AG-UI agent",
            capabilities=["text_message", "tool_call", "generative_ui"],
            supported_events=AG_UI_EVENTS,
            a2ui_support=True,
            shared_state=True,
            metadata={"framework": "copilotkit"},
        )
        assert desc["a2ui_support"] is True
        assert len(desc["supported_events"]) == len(AG_UI_EVENTS)
        assert desc["metadata"]["framework"] == "copilotkit"

    def test_event_types_complete(self):
        assert "RUN_STARTED" in AG_UI_EVENTS
        assert "TEXT_MESSAGE_CONTENT" in AG_UI_EVENTS
        assert "TOOL_CALL_START" in AG_UI_EVENTS
        assert "STATE_DELTA" in AG_UI_EVENTS
        assert len(AG_UI_EVENTS) == 13

    def test_capability_types(self):
        assert "text_message" in AG_UI_CAPABILITIES
        assert "tool_call" in AG_UI_CAPABILITIES
        assert "generative_ui" in AG_UI_CAPABILITIES
        assert "human_in_loop" in AG_UI_CAPABILITIES


# ═══════════════════════════════════════════════════════════════════
# 3. TRANSLATION AG-UI ↔ A2A
# ═══════════════════════════════════════════════════════════════════

class TestAgUiA2aTranslation:

    @pytest.fixture
    def ag_ui_desc(self):
        return create_ag_ui_descriptor(
            name="Support Agent",
            endpoint_url="https://myapp.com/api/support",
            description="Customer support via AG-UI",
            capabilities=["text_message", "tool_call", "human_in_loop"],
            a2ui_support=True,
        )

    def test_ag_ui_to_a2a(self, ag_ui_desc):
        card = ag_ui_to_a2a(ag_ui_desc)
        assert card["name"] == "Support Agent"
        assert card["url"] == "https://myapp.com/api/support"
        assert len(card["skills"]) == 3
        assert card["skills"][0]["id"] == "text_message"

    def test_ag_ui_to_a2a_preserves_metadata(self, ag_ui_desc):
        card = ag_ui_to_a2a(ag_ui_desc)
        assert card["provider"]["a2ui_support"] is True

    def test_a2a_to_ag_ui(self):
        card = {
            "name": "Booking Agent",
            "url": "https://example.com/agent",
            "description": "Books appointments",
            "skills": [
                {"id": "booking", "name": "Appointment Booking"},
                {"id": "scheduling", "name": "Calendar Scheduling"},
            ],
        }
        desc = a2a_to_ag_ui(card)
        assert desc["name"] == "Booking Agent"
        assert desc["endpoint_url"] == "https://example.com/agent"
        assert "booking" in desc["capabilities"]
        assert "scheduling" in desc["capabilities"]

    def test_a2a_to_ag_ui_with_events(self):
        card = {
            "name": "Agent",
            "url": "https://test.com",
            "skills": [],
            "provider": {
                "ag_ui_events": ["RUN_STARTED", "RUN_FINISHED", "TOOL_CALL_START"],
                "a2ui_support": True,
            },
        }
        desc = a2a_to_ag_ui(card)
        assert "TOOL_CALL_START" in desc["supported_events"]
        assert desc["a2ui_support"] is True

    def test_roundtrip_ag_ui_a2a(self, ag_ui_desc):
        card = ag_ui_to_a2a(ag_ui_desc)
        back = a2a_to_ag_ui(card)
        assert back["name"] == ag_ui_desc["name"]
        assert set(back["capabilities"]) == set(ag_ui_desc["capabilities"])


# ═══════════════════════════════════════════════════════════════════
# 4. TRANSLATION AG-UI ↔ MCP
# ═══════════════════════════════════════════════════════════════════

class TestAgUiMcpTranslation:

    @pytest.fixture
    def ag_ui_desc(self):
        return create_ag_ui_descriptor(
            name="Tool Agent",
            endpoint_url="https://myapp.com/api/tools",
            description="Agent with tool capabilities",
            capabilities=["text_message", "tool_call"],
        )

    def test_ag_ui_to_mcp(self, ag_ui_desc):
        card = ag_ui_to_mcp(ag_ui_desc)
        assert card["name"] == "Tool Agent"
        assert card["url"] == "https://myapp.com/api/tools"
        assert len(card["tools"]) == 2

    def test_ag_ui_to_mcp_tool_schema(self, ag_ui_desc):
        card = ag_ui_to_mcp(ag_ui_desc)
        tool_call = next(t for t in card["tools"] if t["name"] == "tool_call")
        assert "inputSchema" in tool_call
        assert tool_call["inputSchema"]["type"] == "object"

    def test_mcp_to_ag_ui(self):
        card = {
            "name": "MCP Server",
            "url": "https://example.com/mcp",
            "description": "An MCP server",
            "tools": [
                {"name": "search", "description": "Search the web"},
                {"name": "calendar", "description": "Manage calendar"},
            ],
        }
        desc = mcp_to_ag_ui(card)
        assert desc["name"] == "MCP Server"
        assert desc["endpoint_url"] == "https://example.com/mcp"
        assert "search" in desc["capabilities"]
        assert "calendar" in desc["capabilities"]
        assert desc["a2ui_support"] is False

    def test_roundtrip_ag_ui_mcp(self, ag_ui_desc):
        card = ag_ui_to_mcp(ag_ui_desc)
        back = mcp_to_ag_ui(card)
        assert back["name"] == ag_ui_desc["name"]
        assert set(back["capabilities"]) == set(ag_ui_desc["capabilities"])


# ═══════════════════════════════════════════════════════════════════
# 5. SCHEMA VALIDATION
# ═══════════════════════════════════════════════════════════════════

class TestAgUiValidation:

    def test_valid_descriptor(self):
        desc = create_ag_ui_descriptor(
            name="Test", endpoint_url="https://test.com/agent",
        )
        errors = validate_ag_ui_descriptor(desc)
        assert errors == []

    def test_missing_name(self):
        errors = validate_ag_ui_descriptor({"endpoint_url": "https://test.com"})
        assert any("name" in e for e in errors)

    def test_missing_endpoint(self):
        errors = validate_ag_ui_descriptor({"name": "Test"})
        assert any("endpoint_url" in e for e in errors)

    def test_invalid_endpoint(self):
        errors = validate_ag_ui_descriptor({
            "name": "Test", "endpoint_url": "ftp://bad.com",
        })
        assert any("HTTP" in e for e in errors)

    def test_unknown_event(self):
        errors = validate_ag_ui_descriptor({
            "name": "Test",
            "endpoint_url": "https://test.com",
            "supported_events": ["INVENTED_EVENT"],
        })
        assert any("Unknown event" in e for e in errors)

    def test_valid_with_all_events(self):
        desc = create_ag_ui_descriptor(
            name="Full",
            endpoint_url="https://test.com",
            supported_events=AG_UI_EVENTS,
        )
        errors = validate_ag_ui_descriptor(desc)
        assert errors == []

    def test_empty_descriptor(self):
        errors = validate_ag_ui_descriptor({})
        assert len(errors) >= 2  # Missing name + endpoint

    def test_not_a_dict(self):
        errors = validate_ag_ui_descriptor("not a dict")
        assert len(errors) == 1


# ═══════════════════════════════════════════════════════════════════
# 6. AUDIT EVENT MAPPING
# ═══════════════════════════════════════════════════════════════════

class TestAuditMapping:

    def test_known_events(self):
        assert map_ag_ui_event_to_audit_action("RUN_STARTED") == "ag_ui_run_start"
        assert map_ag_ui_event_to_audit_action("TOOL_CALL_START") == "ag_ui_tool_call"
        assert map_ag_ui_event_to_audit_action("STATE_DELTA") == "ag_ui_state_delta"

    def test_unknown_event_fallback(self):
        action = map_ag_ui_event_to_audit_action("CUSTOM")
        assert action == "ag_ui_custom"

    def test_all_core_events_mapped(self):
        for event in ["RUN_STARTED", "RUN_FINISHED", "RUN_ERROR",
                       "TEXT_MESSAGE_START", "TOOL_CALL_START",
                       "TOOL_CALL_END", "STATE_SNAPSHOT", "STATE_DELTA"]:
            action = map_ag_ui_event_to_audit_action(event)
            assert action.startswith("ag_ui_")


# ═══════════════════════════════════════════════════════════════════
# 7. END-TO-END: AG-UI → A2A → MCP → AG-UI
# ═══════════════════════════════════════════════════════════════════

class TestFullTranslationChain:

    def test_ag_ui_a2a_mcp_roundtrip(self):
        """Full chain: AG-UI → A2A → MCP → AG-UI."""
        # Start with AG-UI
        original = create_ag_ui_descriptor(
            name="Chain Test Agent",
            endpoint_url="https://chain.test/agent",
            capabilities=["text_message", "tool_call"],
        )

        # AG-UI → A2A
        a2a = ag_ui_to_a2a(original)
        assert a2a["name"] == "Chain Test Agent"
        assert len(a2a["skills"]) == 2

        # A2A → MCP (using existing translator format)
        from aib.translator import CredentialTranslator
        t = CredentialTranslator()
        mcp = t.translate(
            source=a2a,
            from_format="a2a_agent_card",
            to_format="mcp_server_card",
        )
        assert mcp["name"] == "Chain Test Agent"
        assert len(mcp["tools"]) == 2

        # MCP → AG-UI
        back = mcp_to_ag_ui(mcp)
        assert back["name"] == "Chain Test Agent"
        assert len(back["capabilities"]) == 2
