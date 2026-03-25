"""Tests for Sprint 11 — AG-UI wiring in translator.py (all 11 translation paths)."""

import pytest
from aib.translator import CredentialTranslator
from aib.ag_ui_binding import create_ag_ui_descriptor


@pytest.fixture
def t():
    return CredentialTranslator()


@pytest.fixture
def a2a_card():
    return {
        "name": "Booking Agent",
        "url": "https://example.com/agent",
        "description": "Books hotels and flights",
        "skills": [
            {"id": "booking", "name": "Hotel Booking"},
            {"id": "search", "name": "Flight Search"},
        ],
    }


@pytest.fixture
def mcp_card():
    return {
        "name": "MCP Server",
        "url": "https://example.com/mcp",
        "description": "MCP tool server",
        "tools": [
            {"name": "search", "description": "Search the web"},
            {"name": "calendar", "description": "Manage calendar"},
        ],
    }


@pytest.fixture
def ag_ui_desc():
    return create_ag_ui_descriptor(
        name="UI Agent",
        endpoint_url="https://example.com/ui-agent",
        description="Agent with UI capabilities",
        capabilities=["text_message", "tool_call", "generative_ui"],
        a2ui_support=True,
        shared_state=True,
    )


@pytest.fixture
def did_doc():
    return {
        "id": "did:web:example.com:agents:bot",
        "authentication": ["did:web:example.com:agents:bot#key-1"],
        "verificationMethod": [{
            "id": "did:web:example.com:agents:bot#key-1",
            "type": "JsonWebKey2020",
        }],
        "service": [{
            "id": "did:web:example.com:agents:bot#agent-service",
            "type": "AgentService",
            "serviceEndpoint": "https://example.com/agent",
            "capabilities": ["booking", "support"],
        }],
    }


# ═══════════════════════════════════════════════════════════════════
# ORIGINAL 5 PATHS (regression)
# ═══════════════════════════════════════════════════════════════════

class TestOriginalPaths:

    def test_a2a_to_mcp(self, t, a2a_card):
        result = t.translate(a2a_card, "a2a_agent_card", "mcp_server_card")
        assert result["name"] == "Booking Agent"
        assert len(result["tools"]) == 2

    def test_mcp_to_a2a(self, t, mcp_card):
        result = t.translate(mcp_card, "mcp_server_card", "a2a_agent_card")
        assert result["name"] == "MCP Server"
        assert len(result["skills"]) == 2

    def test_a2a_to_did(self, t, a2a_card):
        result = t.translate(a2a_card, "a2a_agent_card", "did_document",
                             domain="example.com", agent_slug="booking")
        assert "did:web:example.com" in result["id"]

    def test_mcp_to_did(self, t, mcp_card):
        result = t.translate(mcp_card, "mcp_server_card", "did_document",
                             domain="example.com", agent_slug="server")
        assert "did:web:example.com" in result["id"]

    def test_did_to_a2a(self, t, did_doc):
        result = t.translate(did_doc, "did_document", "a2a_agent_card")
        assert result["url"] == "https://example.com/agent"
        assert len(result["skills"]) == 2


# ═══════════════════════════════════════════════════════════════════
# NEW AG-UI ↔ A2A PATHS
# ═══════════════════════════════════════════════════════════════════

class TestAgUiA2a:

    def test_ag_ui_to_a2a(self, t, ag_ui_desc):
        result = t.translate(ag_ui_desc, "ag_ui_descriptor", "a2a_agent_card")
        assert result["name"] == "UI Agent"
        assert result["url"] == "https://example.com/ui-agent"
        assert len(result["skills"]) == 3
        assert result["provider"]["a2ui_support"] is True

    def test_a2a_to_ag_ui(self, t, a2a_card):
        result = t.translate(a2a_card, "a2a_agent_card", "ag_ui_descriptor")
        assert result["name"] == "Booking Agent"
        assert result["endpoint_url"] == "https://example.com/agent"
        assert "booking" in result["capabilities"]

    def test_roundtrip_ag_ui_a2a(self, t, ag_ui_desc):
        a2a = t.translate(ag_ui_desc, "ag_ui_descriptor", "a2a_agent_card")
        back = t.translate(a2a, "a2a_agent_card", "ag_ui_descriptor")
        assert back["name"] == ag_ui_desc["name"]
        assert set(back["capabilities"]) == set(ag_ui_desc["capabilities"])


# ═══════════════════════════════════════════════════════════════════
# NEW AG-UI ↔ MCP PATHS
# ═══════════════════════════════════════════════════════════════════

class TestAgUiMcp:

    def test_ag_ui_to_mcp(self, t, ag_ui_desc):
        result = t.translate(ag_ui_desc, "ag_ui_descriptor", "mcp_server_card")
        assert result["name"] == "UI Agent"
        assert len(result["tools"]) == 3

    def test_mcp_to_ag_ui(self, t, mcp_card):
        result = t.translate(mcp_card, "mcp_server_card", "ag_ui_descriptor")
        assert result["name"] == "MCP Server"
        assert "search" in result["capabilities"]
        assert "calendar" in result["capabilities"]

    def test_roundtrip_ag_ui_mcp(self, t, ag_ui_desc):
        mcp = t.translate(ag_ui_desc, "ag_ui_descriptor", "mcp_server_card")
        back = t.translate(mcp, "mcp_server_card", "ag_ui_descriptor")
        assert back["name"] == ag_ui_desc["name"]
        assert len(back["capabilities"]) == len(ag_ui_desc["capabilities"])


# ═══════════════════════════════════════════════════════════════════
# NEW AG-UI ↔ DID PATHS
# ═══════════════════════════════════════════════════════════════════

class TestAgUiDid:

    def test_ag_ui_to_did(self, t, ag_ui_desc):
        result = t.translate(ag_ui_desc, "ag_ui_descriptor", "did_document",
                             domain="example.com", agent_slug="ui-agent")
        assert "did:web:example.com" in result["id"]
        assert len(result["service"]) > 0

    def test_did_to_ag_ui(self, t, did_doc):
        result = t.translate(did_doc, "did_document", "ag_ui_descriptor")
        assert result["endpoint_url"] == "https://example.com/agent"
        assert "booking" in result["capabilities"]

    def test_roundtrip_ag_ui_did(self, t, ag_ui_desc):
        did = t.translate(ag_ui_desc, "ag_ui_descriptor", "did_document",
                          domain="example.com", agent_slug="ui-agent")
        back = t.translate(did, "did_document", "ag_ui_descriptor")
        assert back["name"] is not None
        assert len(back["capabilities"]) > 0


# ═══════════════════════════════════════════════════════════════════
# FULL 4-FORMAT CHAINS
# ═══════════════════════════════════════════════════════════════════

class TestFullChains:

    def test_ag_ui_a2a_mcp_chain(self, t, ag_ui_desc):
        """AG-UI → A2A → MCP"""
        a2a = t.translate(ag_ui_desc, "ag_ui_descriptor", "a2a_agent_card")
        mcp = t.translate(a2a, "a2a_agent_card", "mcp_server_card")
        assert mcp["name"] == "UI Agent"
        assert len(mcp["tools"]) == 3

    def test_mcp_a2a_ag_ui_chain(self, t, mcp_card):
        """MCP → A2A → AG-UI"""
        a2a = t.translate(mcp_card, "mcp_server_card", "a2a_agent_card")
        agui = t.translate(a2a, "a2a_agent_card", "ag_ui_descriptor")
        assert agui["name"] == "MCP Server"
        assert len(agui["capabilities"]) == 2

    def test_ag_ui_a2a_did_chain(self, t, ag_ui_desc):
        """AG-UI → A2A → DID"""
        a2a = t.translate(ag_ui_desc, "ag_ui_descriptor", "a2a_agent_card")
        did = t.translate(a2a, "a2a_agent_card", "did_document",
                          domain="example.com", agent_slug="test")
        assert "did:web:example.com" in did["id"]

    def test_did_a2a_mcp_ag_ui_chain(self, t, did_doc):
        """DID → A2A → MCP → AG-UI (full 4-format)"""
        a2a = t.translate(did_doc, "did_document", "a2a_agent_card")
        mcp = t.translate(a2a, "a2a_agent_card", "mcp_server_card")
        agui = t.translate(mcp, "mcp_server_card", "ag_ui_descriptor")
        assert agui["name"] is not None
        assert len(agui["capabilities"]) == 2

    def test_ag_ui_mcp_a2a_did_chain(self, t, ag_ui_desc):
        """AG-UI → MCP → A2A → DID (alternative 4-format)"""
        mcp = t.translate(ag_ui_desc, "ag_ui_descriptor", "mcp_server_card")
        a2a = t.translate(mcp, "mcp_server_card", "a2a_agent_card")
        did = t.translate(a2a, "a2a_agent_card", "did_document",
                          domain="chain.test", agent_slug="agent")
        assert "did:web:chain.test" in did["id"]


# ═══════════════════════════════════════════════════════════════════
# ALL 11 PATHS ENUMERATION
# ═══════════════════════════════════════════════════════════════════

class TestAllPaths:

    def test_all_11_paths_exist(self, t):
        """Verify all 11 translation paths are registered."""
        formats = ["a2a_agent_card", "mcp_server_card", "did_document", "ag_ui_descriptor"]
        working = 0
        for f1 in formats:
            for f2 in formats:
                if f1 == f2:
                    continue
                try:
                    # Build minimal source for each format
                    source = self._make_source(f1)
                    t.translate(source, f1, f2,
                                domain="test.com", agent_slug="test")
                    working += 1
                except ValueError as e:
                    if "Unsupported" in str(e):
                        pass  # Missing path
                    else:
                        working += 1  # Other error = path exists
                except Exception:
                    working += 1  # Path exists but data issue

        # 4 formats × 3 targets each = 12 possible, minus did→mcp (not direct) = 11
        assert working >= 11

    def _make_source(self, fmt):
        if fmt == "a2a_agent_card":
            return {"name": "Test", "url": "https://t.com",
                    "skills": [{"id": "s1", "name": "S"}]}
        elif fmt == "mcp_server_card":
            return {"name": "Test", "url": "https://t.com",
                    "tools": [{"name": "t1", "description": "T"}]}
        elif fmt == "did_document":
            return {"id": "did:web:test.com:agent", "authentication": [],
                    "service": [{"serviceEndpoint": "https://t.com",
                                 "capabilities": ["cap"]}]}
        elif fmt == "ag_ui_descriptor":
            return {"name": "Test", "endpoint_url": "https://t.com",
                    "capabilities": ["text_message"]}
        return {}


# ═══════════════════════════════════════════════════════════════════
# ERROR HANDLING
# ═══════════════════════════════════════════════════════════════════

class TestErrors:

    def test_unsupported_format(self, t):
        with pytest.raises(ValueError, match="Unsupported"):
            t.translate({}, "unknown_format", "a2a_agent_card")

    def test_same_format(self, t):
        with pytest.raises(ValueError, match="Unsupported"):
            t.translate({}, "a2a_agent_card", "a2a_agent_card")
