"""
AIB — Sprint 7: AG-UI Protocol Binding.

Adds full AG-UI support to AIB:

1. AgUiBinding dataclass for passport protocol_bindings
2. AG-UI Agent Descriptor format (the AG-UI equivalent of Agent Card)
3. Bidirectional translation: AG-UI ↔ A2A, AG-UI ↔ MCP
4. JSON Schema validation for AG-UI descriptors
5. AG-UI event type registry (for audit trail integration)

AG-UI (Agent-User Interaction Protocol) by CopilotKit is the bi-directional
runtime connection between an agent and a user-facing application.
Unlike A2A (agent↔agent) and MCP (agent↔tools), AG-UI handles agent↔human
interactions via SSE (Server-Sent Events) streams.

Key concepts:
- Endpoint: HTTP POST that returns an SSE stream
- Events: TEXT_MESSAGE, TOOL_CALL, STATE_DELTA, etc.
- UI Surfaces: A2UI components rendered by the frontend
- Shared State: Bi-directional sync between agent and app
"""

from dataclasses import dataclass, field
from typing import Optional


# ═══════════════════════════════════════════════════════════════════
# 1. AG-UI BINDING FOR PASSPORTS
# ═══════════════════════════════════════════════════════════════════

@dataclass
class AgUiBinding:
    """
    AG-UI protocol binding for an Agent Passport.

    Usage in passport creation:
        passport, token = svc.create_passport(
            ...,
            bindings={
                "ag_ui": AgUiBinding(
                    auth_method="bearer",
                    endpoint_url="https://myapp.com/api/agent",
                    ui_capabilities=["text_message", "tool_call", "state_sync"],
                    supported_events=["TEXT_MESSAGE", "TOOL_CALL", "STATE_DELTA"],
                ),
            },
        )
    """
    auth_method: str = "bearer"
    credential_ref: Optional[str] = None
    endpoint_url: str = ""                    # SSE endpoint URL
    ui_capabilities: list[str] = field(default_factory=list)
    supported_events: list[str] = field(default_factory=list)
    a2ui_support: bool = False                # Does the agent emit A2UI surfaces?
    shared_state: bool = False                # Does the agent use shared state?

    def to_dict(self) -> dict:
        return {
            "auth_method": self.auth_method,
            "credential_ref": self.credential_ref,
            "endpoint_url": self.endpoint_url,
            "ui_capabilities": self.ui_capabilities,
            "supported_events": self.supported_events,
            "a2ui_support": self.a2ui_support,
            "shared_state": self.shared_state,
        }


# ═══════════════════════════════════════════════════════════════════
# 2. AG-UI AGENT DESCRIPTOR FORMAT
# ═══════════════════════════════════════════════════════════════════

# AG-UI event types (from the protocol spec)
AG_UI_EVENTS = [
    "RUN_STARTED",
    "RUN_FINISHED",
    "RUN_ERROR",
    "TEXT_MESSAGE_START",
    "TEXT_MESSAGE_CONTENT",
    "TEXT_MESSAGE_END",
    "TOOL_CALL_START",
    "TOOL_CALL_ARGS",
    "TOOL_CALL_RESULT",
    "TOOL_CALL_END",
    "STATE_SNAPSHOT",
    "STATE_DELTA",
    "CUSTOM",
]

# UI capability types
AG_UI_CAPABILITIES = [
    "text_message",       # Agent can send text messages
    "tool_call",          # Agent can call tools with progress
    "state_sync",         # Agent can sync shared state
    "generative_ui",      # Agent can emit A2UI surfaces
    "file_attachment",    # Agent can handle file attachments
    "voice",              # Agent supports voice/audio
    "human_in_loop",      # Agent supports approval workflows
]


def create_ag_ui_descriptor(
    name: str,
    endpoint_url: str,
    description: str = "",
    capabilities: Optional[list[str]] = None,
    supported_events: Optional[list[str]] = None,
    a2ui_support: bool = False,
    shared_state: bool = False,
    version: str = "1.0",
    metadata: Optional[dict] = None,
) -> dict:
    """
    Create an AG-UI Agent Descriptor.

    This is the AG-UI equivalent of an A2A Agent Card or MCP Server Card.
    It describes an AG-UI-compatible agent's capabilities and endpoint.

    Returns a dict that can be published as JSON for discovery.
    """
    return {
        "ag_ui_version": version,
        "name": name,
        "description": description,
        "endpoint_url": endpoint_url,
        "capabilities": capabilities or ["text_message"],
        "supported_events": supported_events or [
            "RUN_STARTED", "RUN_FINISHED",
            "TEXT_MESSAGE_START", "TEXT_MESSAGE_CONTENT", "TEXT_MESSAGE_END",
        ],
        "a2ui_support": a2ui_support,
        "shared_state": shared_state,
        "metadata": metadata or {},
    }


# ═══════════════════════════════════════════════════════════════════
# 3. TRANSLATION: AG-UI ↔ A2A ↔ MCP
# ═══════════════════════════════════════════════════════════════════

def ag_ui_to_a2a(ag_ui_descriptor: dict) -> dict:
    """
    Translate an AG-UI Agent Descriptor to an A2A Agent Card.

    Mapping:
    - name → name
    - endpoint_url → url
    - description → description
    - capabilities → skills (each capability becomes a skill)
    - supported_events are stored in metadata
    """
    skills = []
    for cap in ag_ui_descriptor.get("capabilities", []):
        skills.append({
            "id": cap,
            "name": _capability_display_name(cap),
        })

    card = {
        "name": ag_ui_descriptor.get("name", ""),
        "url": ag_ui_descriptor.get("endpoint_url", ""),
        "description": ag_ui_descriptor.get("description", ""),
        "skills": skills,
    }

    # Preserve AG-UI metadata
    provider = {}
    if ag_ui_descriptor.get("a2ui_support"):
        provider["a2ui_support"] = True
    if ag_ui_descriptor.get("shared_state"):
        provider["shared_state"] = True
    if ag_ui_descriptor.get("supported_events"):
        provider["ag_ui_events"] = ag_ui_descriptor["supported_events"]
    if provider:
        card["provider"] = provider

    return card


def a2a_to_ag_ui(agent_card: dict) -> dict:
    """
    Translate an A2A Agent Card to an AG-UI Agent Descriptor.

    Mapping:
    - name → name
    - url → endpoint_url
    - description → description
    - skills → capabilities (each skill.id becomes a capability)
    - provider.ag_ui_events → supported_events (if present)
    """
    capabilities = [
        s.get("id", s.get("name", "unknown"))
        for s in agent_card.get("skills", [])
    ]

    events = ["RUN_STARTED", "RUN_FINISHED",
              "TEXT_MESSAGE_START", "TEXT_MESSAGE_CONTENT", "TEXT_MESSAGE_END"]

    provider = agent_card.get("provider", {})
    if "ag_ui_events" in provider:
        events = provider["ag_ui_events"]

    return {
        "ag_ui_version": "1.0",
        "name": agent_card.get("name", ""),
        "description": agent_card.get("description", ""),
        "endpoint_url": agent_card.get("url", ""),
        "capabilities": capabilities,
        "supported_events": events,
        "a2ui_support": provider.get("a2ui_support", False),
        "shared_state": provider.get("shared_state", False),
        "metadata": {},
    }


def ag_ui_to_mcp(ag_ui_descriptor: dict) -> dict:
    """
    Translate an AG-UI Agent Descriptor to an MCP Server Card.

    Mapping:
    - name → name
    - endpoint_url → url
    - capabilities → tools (each capability becomes a tool)
    """
    tools = []
    for cap in ag_ui_descriptor.get("capabilities", []):
        tool = {
            "name": cap,
            "description": _capability_display_name(cap),
        }
        # Tool call capability maps to inputSchema
        if cap == "tool_call":
            tool["inputSchema"] = {
                "type": "object",
                "properties": {
                    "tool_name": {"type": "string"},
                    "arguments": {"type": "object"},
                },
            }
        tools.append(tool)

    return {
        "name": ag_ui_descriptor.get("name", ""),
        "url": ag_ui_descriptor.get("endpoint_url", ""),
        "description": ag_ui_descriptor.get("description", ""),
        "tools": tools,
    }


def mcp_to_ag_ui(server_card: dict) -> dict:
    """
    Translate an MCP Server Card to an AG-UI Agent Descriptor.

    Mapping:
    - name → name
    - url → endpoint_url
    - tools → capabilities (each tool.name becomes a capability)
    """
    capabilities = [
        t.get("name", "unknown") for t in server_card.get("tools", [])
    ]

    return {
        "ag_ui_version": "1.0",
        "name": server_card.get("name", ""),
        "description": server_card.get("description", ""),
        "endpoint_url": server_card.get("url", ""),
        "capabilities": capabilities,
        "supported_events": [
            "RUN_STARTED", "RUN_FINISHED",
            "TEXT_MESSAGE_START", "TEXT_MESSAGE_CONTENT", "TEXT_MESSAGE_END",
        ],
        "a2ui_support": False,
        "shared_state": False,
        "metadata": {},
    }


def _capability_display_name(cap: str) -> str:
    """Convert capability ID to display name."""
    names = {
        "text_message": "Text Messaging",
        "tool_call": "Tool Execution",
        "state_sync": "State Synchronization",
        "generative_ui": "Generative UI (A2UI)",
        "file_attachment": "File Attachments",
        "voice": "Voice / Audio",
        "human_in_loop": "Human-in-the-Loop Approval",
    }
    return names.get(cap, cap.replace("_", " ").title())


# ═══════════════════════════════════════════════════════════════════
# 4. JSON SCHEMA FOR AG-UI DESCRIPTOR
# ═══════════════════════════════════════════════════════════════════

AG_UI_DESCRIPTOR_SCHEMA = {
    "type": "object",
    "required": ["name", "endpoint_url"],
    "properties": {
        "ag_ui_version": {"type": "string"},
        "name": {"type": "string", "minLength": 1},
        "description": {"type": "string"},
        "endpoint_url": {"type": "string", "minLength": 1},
        "capabilities": {
            "type": "array",
            "items": {"type": "string"},
        },
        "supported_events": {
            "type": "array",
            "items": {
                "type": "string",
                "enum": AG_UI_EVENTS + ["CUSTOM"],
            },
        },
        "a2ui_support": {"type": "boolean"},
        "shared_state": {"type": "boolean"},
        "metadata": {"type": "object"},
    },
}


def validate_ag_ui_descriptor(descriptor: dict) -> list[str]:
    """
    Validate an AG-UI descriptor against the schema.

    Returns a list of error messages (empty = valid).
    """
    errors = []

    if not isinstance(descriptor, dict):
        return ["Descriptor must be a JSON object"]

    if not descriptor.get("name"):
        errors.append("Missing required field: name")

    if not descriptor.get("endpoint_url"):
        errors.append("Missing required field: endpoint_url")

    endpoint = descriptor.get("endpoint_url", "")
    if endpoint and not (endpoint.startswith("http://") or endpoint.startswith("https://")):
        errors.append(f"endpoint_url must be HTTP(S), got: {endpoint}")

    events = descriptor.get("supported_events", [])
    valid_events = set(AG_UI_EVENTS + ["CUSTOM"])
    for event in events:
        if event not in valid_events:
            errors.append(f"Unknown event type: {event}")

    caps = descriptor.get("capabilities", [])
    if not isinstance(caps, list):
        errors.append("capabilities must be an array")

    return errors


# ═══════════════════════════════════════════════════════════════════
# 5. AG-UI EVENT AUDIT INTEGRATION
# ═══════════════════════════════════════════════════════════════════

AG_UI_EVENT_TO_ACTION = {
    "RUN_STARTED": "ag_ui_run_start",
    "RUN_FINISHED": "ag_ui_run_finish",
    "RUN_ERROR": "ag_ui_run_error",
    "TEXT_MESSAGE_START": "ag_ui_message",
    "TOOL_CALL_START": "ag_ui_tool_call",
    "TOOL_CALL_END": "ag_ui_tool_result",
    "STATE_SNAPSHOT": "ag_ui_state_snapshot",
    "STATE_DELTA": "ag_ui_state_delta",
}


def map_ag_ui_event_to_audit_action(event_type: str) -> str:
    """Map an AG-UI event type to an AIB audit action for receipt generation."""
    return AG_UI_EVENT_TO_ACTION.get(event_type, f"ag_ui_{event_type.lower()}")
