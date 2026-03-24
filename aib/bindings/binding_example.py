"""
Example protocol binding — copy this file to create your own.

Rename to binding_yourprotocol.py, update the class, and drop in aib/bindings/.
The registry auto-discovers it on startup.
"""

from aib.plugins import ProtocolBinding


class ExampleProtocolBinding(ProtocolBinding):
    """Example binding for a fictional protocol. Copy and modify."""

    protocol_name = "example"
    display_name = "Example Protocol"
    version = "0.1"
    description = "A template binding. Copy this file to add your own protocol."

    def to_passport_binding(self, native_card: dict) -> dict:
        return {
            "endpoint_url": native_card.get("url", ""),
            "auth_method": native_card.get("auth_type", "api_key"),
            "credential_ref": f"vault://aib/example/{native_card.get('id', 'unknown')}",
        }

    def from_passport_binding(self, binding: dict) -> dict:
        return {
            "url": binding.get("endpoint_url", ""),
            "auth_type": binding.get("auth_method", "api_key"),
            "version": "0.1",
        }

    def detect_protocol(self, url: str) -> bool:
        return "/example-protocol/" in url.lower()
