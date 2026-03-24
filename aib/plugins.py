"""
AIB — Plugin System with Auto-Discovery.

Add support for a new protocol by dropping a single Python file
in the bindings/ directory. Zero changes to the core.

How it works:
1. Place a file in aib/bindings/ (e.g. binding_ucp.py)
2. The file defines a class that inherits from ProtocolBinding
3. On startup, the PluginRegistry scans the directory and registers all bindings
4. The gateway, translator, and CLI automatically see the new protocol

Example binding (50 lines):

    # aib/bindings/binding_ucp.py
    from aib.plugins import ProtocolBinding

    class UcpBinding(ProtocolBinding):
        protocol_name = "ucp"
        display_name = "Universal Commerce Protocol"
        version = "1.0"

        def to_passport_binding(self, native_card):
            return {"endpoint_url": native_card["service_url"], ...}

        def from_passport_binding(self, binding):
            return {"service_url": binding["endpoint_url"], ...}

        def detect_protocol(self, url):
            return "/ucp/" in url or "/.well-known/ucp.json" in url

        def translate_to(self, source, source_format):
            # Convert from another format TO this protocol's native format
            return {...}

        def translate_from(self, native_card):
            # Convert FROM this protocol's native format to canonical AIB
            return {...}

That's it. The gateway now routes UCP traffic, the translator handles
UCP↔MCP/A2A/ANP conversion, and `aib create --protocols ucp` works.
"""

import importlib
import inspect
import pkgutil
from pathlib import Path
from typing import Optional, Any
from abc import ABC, abstractmethod


# ── Base Protocol Binding ─────────────────────────────────────────

class ProtocolBinding(ABC):
    """
    Abstract base class for protocol bindings.

    Implement this to add support for a new AI protocol.
    Drop your file in aib/bindings/ and it's auto-discovered.
    """

    # Required class attributes (override in subclass)
    protocol_name: str = ""       # Short identifier: "mcp", "a2a", "anp", "ucp"
    display_name: str = ""        # Human readable: "Model Context Protocol"
    version: str = "1.0"          # Protocol version supported
    description: str = ""         # Brief description

    @abstractmethod
    def to_passport_binding(self, native_card: dict) -> dict:
        """
        Convert a protocol-native identity document to AIB passport binding format.

        Input: the protocol's native card (Agent Card, Server Card, etc.)
        Output: dict with at minimum:
            - endpoint_url: str
            - auth_method: str
            - credential_ref: str (vault reference)
        """
        ...

    @abstractmethod
    def from_passport_binding(self, binding: dict) -> dict:
        """
        Convert an AIB passport binding back to the protocol's native format.

        Input: AIB passport binding dict
        Output: protocol-native card dict
        """
        ...

    @abstractmethod
    def detect_protocol(self, url: str) -> bool:
        """
        Detect if a URL targets this protocol.

        Used by the gateway to route requests to the correct protocol handler.
        """
        ...

    def translate_to(self, source: dict, source_format: str) -> dict:
        """
        Convert from another format TO this protocol's native format.

        Override for custom translation logic. Default returns source as-is.
        """
        return source

    def translate_from(self, native_card: dict) -> dict:
        """
        Convert FROM this protocol's native format to canonical AIB format.

        Override for custom translation logic. Default returns card as-is.
        """
        return native_card

    def validate_card(self, card: dict) -> tuple[bool, str]:
        """
        Validate a native card. Override for protocol-specific validation.

        Returns (is_valid, error_message).
        """
        return True, ""

    def health_check(self, endpoint_url: str) -> tuple[bool, str]:
        """
        Check if a protocol endpoint is reachable.

        Override for protocol-specific health checks.
        """
        return True, "Not implemented"

    def __repr__(self):
        return f"<{self.__class__.__name__} protocol={self.protocol_name}>"


# ── Built-in Bindings ────────────────────────────────────────────

class McpBinding(ProtocolBinding):
    """Built-in MCP (Model Context Protocol) binding."""

    protocol_name = "mcp"
    display_name = "Model Context Protocol"
    version = "2025-03"
    description = "Agent-to-tool communication (Anthropic/AAIF). OAuth 2.1 auth, Server Cards."

    def to_passport_binding(self, native_card: dict) -> dict:
        return {
            "endpoint_url": native_card.get("server_url", native_card.get("url", "")),
            "auth_method": native_card.get("auth", {}).get("type", "oauth2"),
            "credential_ref": f"vault://aib/mcp/{native_card.get('name', 'unknown')}",
            "server_card_url": native_card.get("server_url", ""),
            "tools": [t.get("name", "") for t in native_card.get("tools", [])],
        }

    def from_passport_binding(self, binding: dict) -> dict:
        return {
            "name": binding.get("endpoint_url", "").split("/")[-1] or "agent",
            "server_url": binding.get("endpoint_url", ""),
            "version": "1.0.0",
            "tools": [],
            "auth": {"type": binding.get("auth_method", "oauth2")},
            "transport": "streamable-http",
        }

    def detect_protocol(self, url: str) -> bool:
        indicators = ["/mcp/", "/.well-known/mcp.json", "/mcp-server", "/tools/list", "/tools/call"]
        return any(ind in url.lower() for ind in indicators)


class A2aBinding(ProtocolBinding):
    """Built-in A2A (Agent-to-Agent) binding."""

    protocol_name = "a2a"
    display_name = "Agent-to-Agent Protocol"
    version = "0.3"
    description = "Agent-to-agent delegation (Google/Linux Foundation). Agent Cards, JSON-RPC."

    def to_passport_binding(self, native_card: dict) -> dict:
        return {
            "endpoint_url": native_card.get("url", ""),
            "auth_method": native_card.get("authentication", {}).get("schemes", ["bearer"])[0] if isinstance(native_card.get("authentication", {}).get("schemes"), list) else "bearer",
            "credential_ref": f"vault://aib/a2a/{native_card.get('name', 'unknown')}",
            "agent_card_url": native_card.get("url", ""),
            "skills": [s.get("name", "") for s in native_card.get("skills", [])],
        }

    def from_passport_binding(self, binding: dict) -> dict:
        return {
            "name": binding.get("endpoint_url", "").split("/")[-1] or "agent",
            "url": binding.get("endpoint_url", ""),
            "version": "1.0.0",
            "skills": [],
            "authentication": {"schemes": [binding.get("auth_method", "bearer")]},
        }

    def detect_protocol(self, url: str) -> bool:
        indicators = ["/a2a/", "/.well-known/agent.json", "/agent-card", "/tasks/send"]
        return any(ind in url.lower() for ind in indicators)


class AnpBinding(ProtocolBinding):
    """Built-in ANP (Agent Network Protocol) binding."""

    protocol_name = "anp"
    display_name = "Agent Network Protocol"
    version = "1.0"
    description = "Peer-to-peer agents (W3C DID). End-to-end encryption, decentralized identity."

    def to_passport_binding(self, native_card: dict) -> dict:
        did = native_card.get("id", "")
        services = native_card.get("service", [])
        endpoint = services[0].get("serviceEndpoint", "") if services else ""
        return {
            "endpoint_url": endpoint,
            "auth_method": "did-auth",
            "credential_ref": f"vault://aib/anp/{did}",
            "did": did,
        }

    def from_passport_binding(self, binding: dict) -> dict:
        did = binding.get("did", f"did:web:agent:{binding.get('endpoint_url', 'unknown')}")
        return {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "controller": did,
            "service": [{
                "id": f"{did}#agent-service",
                "type": "AIBAgent",
                "serviceEndpoint": binding.get("endpoint_url", ""),
            }],
        }

    def detect_protocol(self, url: str) -> bool:
        indicators = ["/anp/", "did:web:", "did:key:", "/.well-known/did.json"]
        return any(ind in url.lower() for ind in indicators)


class AgUiBinding(ProtocolBinding):
    """Built-in AG-UI (Agent-User Interface) binding."""

    protocol_name = "ag-ui"
    display_name = "Agent-User Interface Protocol"
    version = "1.0"
    description = "Agent-to-human communication. Event-driven, no native identity layer."

    def to_passport_binding(self, native_card: dict) -> dict:
        return {
            "endpoint_url": native_card.get("url", native_card.get("endpoint", "")),
            "auth_method": native_card.get("auth_method", "none"),
            "credential_ref": None,
        }

    def from_passport_binding(self, binding: dict) -> dict:
        return {
            "endpoint": binding.get("endpoint_url", ""),
            "type": "ag-ui",
            "events": ["message", "state_update", "tool_call"],
        }

    def detect_protocol(self, url: str) -> bool:
        indicators = ["/ag-ui/", "/agent-ui/", "/events/subscribe"]
        return any(ind in url.lower() for ind in indicators)


# ── Plugin Registry ───────────────────────────────────────────────

class PluginRegistry:
    """
    Registry for protocol bindings with auto-discovery.

    Usage:
        registry = PluginRegistry()
        registry.auto_discover()  # Scans aib/bindings/ directory

        # Or manually register
        registry.register(MyCustomBinding())

        # Use
        binding = registry.get("mcp")
        protocol = registry.detect("https://example.com/mcp/tools/list")
        all_protos = registry.list_protocols()
    """

    def __init__(self, auto_discover: bool = True):
        self._bindings: dict[str, ProtocolBinding] = {}
        self._register_builtins()
        if auto_discover:
            self.auto_discover()

    def _register_builtins(self):
        """Register the 4 built-in protocol bindings."""
        for binding_cls in [McpBinding, A2aBinding, AnpBinding, AgUiBinding]:
            instance = binding_cls()
            self._bindings[instance.protocol_name] = instance

    def auto_discover(self):
        """
        Scan the aib/bindings/ directory for plugin files.

        Any .py file containing a class that inherits from ProtocolBinding
        is automatically instantiated and registered.
        """
        bindings_dir = Path(__file__).parent / "bindings"
        if not bindings_dir.exists():
            bindings_dir.mkdir(parents=True, exist_ok=True)
            # Create __init__.py
            (bindings_dir / "__init__.py").write_text(
                '"""AIB Protocol Bindings — drop .py files here to add protocol support."""\n'
            )
            return

        for finder, module_name, _ in pkgutil.iter_modules([str(bindings_dir)]):
            if module_name.startswith("_"):
                continue
            try:
                module = importlib.import_module(f"aib.bindings.{module_name}")
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if (
                        issubclass(obj, ProtocolBinding)
                        and obj is not ProtocolBinding
                        and hasattr(obj, "protocol_name")
                        and obj.protocol_name
                    ):
                        instance = obj()
                        self._bindings[instance.protocol_name] = instance
            except Exception as e:
                print(f"Warning: Failed to load binding {module_name}: {e}")

    def register(self, binding: ProtocolBinding):
        """Manually register a protocol binding."""
        if not binding.protocol_name:
            raise ValueError("Binding must have a protocol_name")
        self._bindings[binding.protocol_name] = binding

    def unregister(self, protocol_name: str) -> bool:
        """Remove a binding. Returns True if it existed."""
        return self._bindings.pop(protocol_name, None) is not None

    def get(self, protocol_name: str) -> Optional[ProtocolBinding]:
        """Get a binding by protocol name."""
        return self._bindings.get(protocol_name)

    def detect(self, url: str) -> Optional[str]:
        """
        Detect which protocol a URL targets.

        Returns the protocol name or None if no match.
        """
        for name, binding in self._bindings.items():
            try:
                if binding.detect_protocol(url):
                    return name
            except Exception:
                continue
        return None

    def list_protocols(self) -> list[dict]:
        """List all registered protocols with metadata."""
        return [
            {
                "name": b.protocol_name,
                "display_name": b.display_name,
                "version": b.version,
                "description": b.description,
                "builtin": b.protocol_name in ("mcp", "a2a", "anp", "ag-ui"),
            }
            for b in self._bindings.values()
        ]

    def supported_protocols(self) -> list[str]:
        """List of supported protocol names."""
        return list(self._bindings.keys())

    @property
    def count(self) -> int:
        return len(self._bindings)

    def __contains__(self, protocol_name: str) -> bool:
        return protocol_name in self._bindings

    def __repr__(self):
        names = ", ".join(self._bindings.keys())
        return f"PluginRegistry({self.count} protocols: {names})"
