"""
AIB Framework Integrations — LangChain, CrewAI, OpenAI Agents SDK.

Provides ready-to-use tools that let AI agents manage their own identity:
- Create/verify/revoke passports
- Translate credentials between protocols
- Check policies before acting
- Query audit trail

Usage with LangChain:

    from aib.integrations.langchain import get_aib_tools
    tools = get_aib_tools(secret_key="your-key")
    agent = create_react_agent(llm, tools, prompt)

Usage with CrewAI:

    from aib.integrations.crewai import get_aib_tools
    tools = get_aib_tools(secret_key="your-key")
    agent = Agent(role="Identity Manager", tools=tools)

Usage with OpenAI Agents SDK:

    from aib.integrations.openai_agents import get_aib_tools
    tools = get_aib_tools(secret_key="your-key")
    agent = Agent(name="Identity Manager", tools=tools)
"""

from typing import Optional
from ..passport import PassportService, McpBinding, A2aBinding, AnpBinding
from ..translator import CredentialTranslator
from ..policy_engine import PolicyEngine, PolicyContext, PolicyRule
from ..receipts import ReceiptStore


class AIBToolkit:
    """
    Base toolkit that provides AIB operations as plain functions.
    Framework-specific integrations wrap these into their tool format.
    """

    def __init__(
        self,
        secret_key: str = "aib-agent-key",
        storage_path: str = "",
    ):
        self.passport_service = PassportService(secret_key=secret_key, storage_path=storage_path)
        self.translator = CredentialTranslator()
        self.policy_engine = PolicyEngine()
        self.receipt_store = ReceiptStore()

    def create_passport(
        self,
        org: str,
        agent: str,
        protocols: str = "mcp,a2a",
        capabilities: str = "",
        display_name: str = "",
    ) -> str:
        """Create an Agent Passport with the given org, agent slug, protocols, and capabilities.
        Returns the passport ID and token."""
        proto_list = [p.strip() for p in protocols.split(",") if p.strip()]
        cap_list = [c.strip() for c in capabilities.split(",") if c.strip()] if capabilities else [agent]

        bindings = {}
        if "mcp" in proto_list:
            bindings["mcp"] = McpBinding(auth_method="oauth2")
        if "a2a" in proto_list:
            bindings["a2a"] = A2aBinding(auth_method="bearer")
        if "anp" in proto_list:
            bindings["anp"] = AnpBinding(auth_method="did-auth")

        passport, token = self.passport_service.create_passport(
            org_slug=org,
            agent_slug=agent,
            display_name=display_name or f"{org}/{agent}",
            capabilities=cap_list,
            bindings=bindings,
        )
        return f"Passport created: {passport.passport_id}\nProtocols: {', '.join(proto_list)}\nCapabilities: {', '.join(cap_list)}\nToken: {token[:60]}..."

    def verify_passport(self, token: str) -> str:
        """Verify an Agent Passport token. Returns whether it's valid and why."""
        valid, payload, reason = self.passport_service.verify_passport(token)
        if valid:
            return f"VALID: {reason}\nPassport ID: {payload.passport_id}\nCapabilities: {payload.capabilities}\nExpires: {payload.expires_at}"
        return f"INVALID: {reason}"

    def revoke_passport(self, passport_id: str) -> str:
        """Revoke an Agent Passport by its ID. This is permanent."""
        result = self.passport_service.revoke_passport(passport_id)
        if result:
            return f"Revoked: {passport_id}"
        return f"Already revoked or not found: {passport_id}"

    def list_passports(self) -> str:
        """List all Agent Passports with their status."""
        passports = self.passport_service.list_passports()
        if not passports:
            return "No passports found."
        lines = []
        for p in passports:
            status = "REVOKED" if p.get("revoked") else "ACTIVE"
            lines.append(f"[{status}] {p['passport_id']} — {', '.join(p.get('protocols', []))}")
        return "\n".join(lines)

    def translate_credential(
        self,
        source_json: str,
        from_format: str,
        to_format: str,
        domain: str = "",
        agent_slug: str = "",
    ) -> str:
        """Translate a credential between formats.
        Supported formats: a2a_agent_card, mcp_server_card, did_document, ag_ui_descriptor.
        Input is a JSON string."""
        import json
        try:
            source = json.loads(source_json)
        except json.JSONDecodeError as e:
            return f"Invalid JSON input: {e}"

        try:
            result = self.translator.translate(
                source, from_format, to_format,
                domain=domain, agent_slug=agent_slug,
            )
            return json.dumps(result, indent=2)
        except Exception as e:
            return f"Translation error: {e}"

    def check_policy(
        self,
        passport_id: str,
        capabilities: str,
        action: str,
        tier: str = "permanent",
        target_url: str = "",
        amount: float = 0,
    ) -> str:
        """Check if an action is allowed by the policy engine.
        Returns allowed/denied with reason."""
        cap_list = [c.strip() for c in capabilities.split(",")]
        ctx = PolicyContext(
            passport_id=passport_id,
            capabilities=cap_list,
            tier=tier,
            issuer="agent",
            action=action,
            target_url=target_url,
            amount=amount,
        )
        decision = self.policy_engine.evaluate(ctx)
        if decision.allowed:
            return f"ALLOWED ({decision.evaluation_ms:.2f}ms)"
        return f"DENIED: {decision.reason} ({decision.evaluation_ms:.2f}ms)"

    def get_supported_translations(self) -> str:
        """List all supported translation paths between identity formats."""
        paths = [
            ("a2a_agent_card", "mcp_server_card"),
            ("mcp_server_card", "a2a_agent_card"),
            ("a2a_agent_card", "did_document"),
            ("mcp_server_card", "did_document"),
            ("did_document", "a2a_agent_card"),
            ("ag_ui_descriptor", "a2a_agent_card"),
            ("a2a_agent_card", "ag_ui_descriptor"),
            ("ag_ui_descriptor", "mcp_server_card"),
            ("mcp_server_card", "ag_ui_descriptor"),
            ("ag_ui_descriptor", "did_document"),
            ("did_document", "ag_ui_descriptor"),
        ]
        return "\n".join(f"  {src} -> {dst}" for src, dst in paths)


# ═══════════════════════════════════════════════════════════════
# LANGCHAIN INTEGRATION
# ═══════════════════════════════════════════════════════════════

def get_langchain_tools(secret_key: str = "aib-agent-key", storage_path: str = ""):
    """
    Get AIB tools for LangChain agents.

    Usage:
        from aib.integrations import get_langchain_tools
        tools = get_langchain_tools(secret_key="your-key")

        from langchain.agents import create_react_agent
        agent = create_react_agent(llm, tools, prompt)

    Returns a list of LangChain-compatible tools (using @tool decorator pattern).
    Works with any LangChain agent type (ReAct, OpenAI Functions, etc.).
    """
    try:
        from langchain_core.tools import tool
    except ImportError:
        try:
            from langchain.tools import tool
        except ImportError:
            raise ImportError(
                "LangChain not installed. Run: pip install langchain-core\n"
                "Or: pip install langchain"
            )

    tk = AIBToolkit(secret_key=secret_key, storage_path=storage_path)

    @tool
    def aib_create_passport(org: str, agent: str, protocols: str = "mcp,a2a", capabilities: str = "") -> str:
        """Create an AI agent passport with portable identity across MCP, A2A, ANP, AG-UI protocols.
        Args: org (organization slug), agent (agent slug), protocols (comma-separated: mcp,a2a,anp,ag_ui), capabilities (comma-separated)."""
        return tk.create_passport(org, agent, protocols, capabilities)

    @tool
    def aib_verify_passport(token: str) -> str:
        """Verify an AI agent passport token. Returns validity, capabilities, and expiration."""
        return tk.verify_passport(token)

    @tool
    def aib_revoke_passport(passport_id: str) -> str:
        """Permanently revoke an AI agent passport. Format: urn:aib:agent:org:name"""
        return tk.revoke_passport(passport_id)

    @tool
    def aib_list_passports() -> str:
        """List all AI agent passports with their status (ACTIVE/REVOKED)."""
        return tk.list_passports()

    @tool
    def aib_translate_credential(source_json: str, from_format: str, to_format: str, domain: str = "", agent_slug: str = "") -> str:
        """Translate an identity credential between protocols.
        Formats: a2a_agent_card, mcp_server_card, did_document, ag_ui_descriptor.
        Input source_json is the credential as a JSON string."""
        return tk.translate_credential(source_json, from_format, to_format, domain, agent_slug)

    @tool
    def aib_check_policy(passport_id: str, capabilities: str, action: str, tier: str = "permanent", target_url: str = "", amount: float = 0) -> str:
        """Check if an action is allowed by identity policy rules.
        Returns ALLOWED or DENIED with reason."""
        return tk.check_policy(passport_id, capabilities, action, tier, target_url, amount)

    return [aib_create_passport, aib_verify_passport, aib_revoke_passport,
            aib_list_passports, aib_translate_credential, aib_check_policy]


# ═══════════════════════════════════════════════════════════════
# CREWAI INTEGRATION
# ═══════════════════════════════════════════════════════════════

def get_crewai_tools(secret_key: str = "aib-agent-key", storage_path: str = ""):
    """
    Get AIB tools for CrewAI agents.

    Usage:
        from aib.integrations import get_crewai_tools
        tools = get_crewai_tools(secret_key="your-key")

        from crewai import Agent
        agent = Agent(
            role="Identity Manager",
            goal="Manage agent identities across protocols",
            tools=tools,
        )

    Returns a list of CrewAI-compatible tools (BaseTool subclasses).
    """
    try:
        from crewai.tools import BaseTool as CrewBaseTool
    except ImportError:
        raise ImportError("CrewAI not installed. Run: pip install crewai")

    from pydantic import BaseModel, Field

    tk = AIBToolkit(secret_key=secret_key, storage_path=storage_path)

    class CreatePassportInput(BaseModel):
        org: str = Field(description="Organization slug")
        agent: str = Field(description="Agent slug")
        protocols: str = Field(default="mcp,a2a", description="Comma-separated protocols")
        capabilities: str = Field(default="", description="Comma-separated capabilities")

    class CreatePassportTool(CrewBaseTool):
        name: str = "aib_create_passport"
        description: str = "Create an AI agent passport with portable identity across MCP, A2A, ANP, AG-UI protocols"
        args_schema: type[BaseModel] = CreatePassportInput

        def _run(self, org: str, agent: str, protocols: str = "mcp,a2a", capabilities: str = "") -> str:
            return tk.create_passport(org, agent, protocols, capabilities)

    class VerifyPassportInput(BaseModel):
        token: str = Field(description="Passport token to verify")

    class VerifyPassportTool(CrewBaseTool):
        name: str = "aib_verify_passport"
        description: str = "Verify an AI agent passport token"
        args_schema: type[BaseModel] = VerifyPassportInput

        def _run(self, token: str) -> str:
            return tk.verify_passport(token)

    class RevokePassportInput(BaseModel):
        passport_id: str = Field(description="Passport ID (urn:aib:agent:org:name)")

    class RevokePassportTool(CrewBaseTool):
        name: str = "aib_revoke_passport"
        description: str = "Permanently revoke an AI agent passport"
        args_schema: type[BaseModel] = RevokePassportInput

        def _run(self, passport_id: str) -> str:
            return tk.revoke_passport(passport_id)

    class ListPassportsTool(CrewBaseTool):
        name: str = "aib_list_passports"
        description: str = "List all AI agent passports with status"

        def _run(self) -> str:
            return tk.list_passports()

    class TranslateInput(BaseModel):
        source_json: str = Field(description="Source credential as JSON string")
        from_format: str = Field(description="Source format: a2a_agent_card, mcp_server_card, did_document, ag_ui_descriptor")
        to_format: str = Field(description="Target format")
        domain: str = Field(default="", description="Domain for DID generation")
        agent_slug: str = Field(default="", description="Agent slug for DID generation")

    class TranslateCredentialTool(CrewBaseTool):
        name: str = "aib_translate_credential"
        description: str = "Translate identity credentials between AI protocols (A2A, MCP, DID, AG-UI)"
        args_schema: type[BaseModel] = TranslateInput

        def _run(self, source_json: str, from_format: str, to_format: str, domain: str = "", agent_slug: str = "") -> str:
            return tk.translate_credential(source_json, from_format, to_format, domain, agent_slug)

    class CheckPolicyInput(BaseModel):
        passport_id: str = Field(description="Passport ID")
        capabilities: str = Field(description="Comma-separated capabilities")
        action: str = Field(description="Action to check (proxy, translate, delegate)")
        tier: str = Field(default="permanent", description="Passport tier")
        target_url: str = Field(default="", description="Target URL")
        amount: float = Field(default=0, description="Amount for spending limits")

    class CheckPolicyTool(CrewBaseTool):
        name: str = "aib_check_policy"
        description: str = "Check if an action is allowed by identity policy rules"
        args_schema: type[BaseModel] = CheckPolicyInput

        def _run(self, passport_id: str, capabilities: str, action: str, tier: str = "permanent", target_url: str = "", amount: float = 0) -> str:
            return tk.check_policy(passport_id, capabilities, action, tier, target_url, amount)

    return [CreatePassportTool(), VerifyPassportTool(), RevokePassportTool(),
            ListPassportsTool(), TranslateCredentialTool(), CheckPolicyTool()]


# ═══════════════════════════════════════════════════════════════
# OPENAI AGENTS SDK INTEGRATION
# ═══════════════════════════════════════════════════════════════

def get_openai_agents_tools(secret_key: str = "aib-agent-key", storage_path: str = ""):
    """
    Get AIB tools for OpenAI Agents SDK.

    Usage:
        from aib.integrations import get_openai_agents_tools
        tools = get_openai_agents_tools(secret_key="your-key")

        from agents import Agent
        agent = Agent(name="Identity Manager", tools=tools)

    Returns a list of function tools compatible with OpenAI Agents SDK.
    """
    try:
        from agents import function_tool
    except ImportError:
        raise ImportError("OpenAI Agents SDK not installed. Run: pip install openai-agents")

    tk = AIBToolkit(secret_key=secret_key, storage_path=storage_path)

    @function_tool
    def aib_create_passport(org: str, agent: str, protocols: str = "mcp,a2a", capabilities: str = "") -> str:
        """Create an AI agent passport with portable identity across protocols."""
        return tk.create_passport(org, agent, protocols, capabilities)

    @function_tool
    def aib_verify_passport(token: str) -> str:
        """Verify an AI agent passport token."""
        return tk.verify_passport(token)

    @function_tool
    def aib_revoke_passport(passport_id: str) -> str:
        """Permanently revoke an AI agent passport."""
        return tk.revoke_passport(passport_id)

    @function_tool
    def aib_list_passports() -> str:
        """List all AI agent passports."""
        return tk.list_passports()

    @function_tool
    def aib_translate_credential(source_json: str, from_format: str, to_format: str) -> str:
        """Translate an identity credential between AI protocols."""
        return tk.translate_credential(source_json, from_format, to_format)

    @function_tool
    def aib_check_policy(passport_id: str, capabilities: str, action: str) -> str:
        """Check if an action is allowed by identity policies."""
        return tk.check_policy(passport_id, capabilities, action)

    return [aib_create_passport, aib_verify_passport, aib_revoke_passport,
            aib_list_passports, aib_translate_credential, aib_check_policy]
