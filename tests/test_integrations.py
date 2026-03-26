"""Tests for AIB framework integrations."""

import json
import pytest
from aib.integrations import AIBToolkit


class TestAIBToolkit:
    """Test the base toolkit (no framework dependency)."""

    @pytest.fixture
    def tk(self, tmp_path):
        return AIBToolkit(secret_key="test-key", storage_path=str(tmp_path / "passports"))

    def test_create_passport(self, tk):
        result = tk.create_passport("testorg", "bot", "mcp,a2a", "booking,support")
        assert "urn:aib:agent:testorg:bot" in result
        assert "mcp" in result
        assert "Token:" in result

    def test_create_and_verify(self, tk):
        result = tk.create_passport("testorg", "bot2")
        token = result.split("Token: ")[1].strip().rstrip(".")
        # Verify (HMAC-based passport service)
        verify_result = tk.verify_passport(token)
        assert "VALID" in verify_result or "urn:aib" in verify_result

    def test_list_passports(self, tk):
        tk.create_passport("org", "agent1")
        tk.create_passport("org", "agent2")
        result = tk.list_passports()
        assert "agent1" in result
        assert "agent2" in result

    def test_revoke_passport(self, tk):
        tk.create_passport("org", "revokeme")
        result = tk.revoke_passport("urn:aib:agent:org:revokeme")
        assert "Revoked" in result or "revok" in result.lower()

    def test_translate_a2a_to_mcp(self, tk):
        source = json.dumps({
            "name": "Test Agent",
            "url": "https://test.com",
            "skills": [{"id": "booking", "name": "Booking"}],
        })
        result = tk.translate_credential(source, "a2a_agent_card", "mcp_server_card")
        parsed = json.loads(result)
        assert "tools" in parsed
        assert len(parsed["tools"]) == 1

    def test_translate_invalid_json(self, tk):
        result = tk.translate_credential("not json", "a2a_agent_card", "mcp_server_card")
        assert "Invalid JSON" in result

    def test_translate_unsupported_format(self, tk):
        result = tk.translate_credential("{}", "fake_format", "mcp_server_card")
        assert "error" in result.lower()

    def test_check_policy_no_rules(self, tk):
        result = tk.check_policy("p1", "booking", "proxy")
        assert "ALLOWED" in result

    def test_check_policy_with_rules(self, tk):
        from aib.policy_engine import PolicyRule
        tk.policy_engine.add_rule(PolicyRule(
            rule_id="block-evil",
            rule_type="domain_block",
            blocked_domains=["evil.com"],
        ))
        result = tk.check_policy("p1", "booking", "proxy", target_url="https://evil.com/api")
        assert "DENIED" in result

    def test_get_supported_translations(self, tk):
        result = tk.get_supported_translations()
        assert "a2a_agent_card" in result
        assert "mcp_server_card" in result

    def test_translate_mcp_to_agui(self, tk):
        source = json.dumps({
            "name": "MCP Server",
            "url": "https://test.com",
            "tools": [{"name": "search", "description": "Search"}],
        })
        result = tk.translate_credential(source, "mcp_server_card", "ag_ui_descriptor")
        parsed = json.loads(result)
        assert "capabilities" in parsed

    def test_create_passport_default_capabilities(self, tk):
        result = tk.create_passport("org", "mybot")
        assert "mybot" in result  # default capability = agent slug

    def test_check_policy_spending_limit(self, tk):
        from aib.policy_engine import PolicyRule
        tk.policy_engine.add_rule(PolicyRule(
            rule_id="limit",
            rule_type="capability_limit",
            capability="payment",
            max_amount=100,
        ))
        allowed = tk.check_policy("p1", "payment", "proxy", amount=50)
        assert "ALLOWED" in allowed
        denied = tk.check_policy("p1", "payment", "proxy", amount=500)
        assert "DENIED" in denied


class TestLangChainIntegration:
    """Test LangChain tools without requiring langchain installed."""

    def test_toolkit_functions_match_langchain_pattern(self):
        """Verify all toolkit methods have proper docstrings (used by @tool)."""
        tk = AIBToolkit.__new__(AIBToolkit)
        methods = [
            "create_passport", "verify_passport", "revoke_passport",
            "list_passports", "translate_credential", "check_policy",
        ]
        for name in methods:
            method = getattr(tk, name)
            assert method.__doc__, f"{name} missing docstring (required for LangChain @tool)"
            assert len(method.__doc__) > 20, f"{name} docstring too short"

    def test_langchain_import_fails_gracefully(self):
        """If langchain not installed, get_langchain_tools raises ImportError with install instructions."""
        from aib.integrations import get_langchain_tools
        try:
            tools = get_langchain_tools()
            # If langchain is installed, tools should be a list
            assert isinstance(tools, list)
        except ImportError as e:
            assert "pip install" in str(e)

    def test_crewai_import_fails_gracefully(self):
        from aib.integrations import get_crewai_tools
        try:
            tools = get_crewai_tools()
            assert isinstance(tools, list)
        except ImportError as e:
            assert "pip install" in str(e)

    def test_openai_agents_import_fails_gracefully(self):
        from aib.integrations import get_openai_agents_tools
        try:
            tools = get_openai_agents_tools()
            assert isinstance(tools, list)
        except ImportError as e:
            assert "pip install" in str(e)
