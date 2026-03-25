"""
AIB — JSON Schema Validation for protocol identity formats.

Formal schemas for every format the translator handles:
  - A2A Agent Card (Google Agent-to-Agent)
  - MCP Server Card (Anthropic Model Context Protocol)
  - W3C DID Document (Decentralized Identifiers)
  - AIB Agent Passport (our own format)

Usage:
    from aib.schema_validator import SchemaValidator

    validator = SchemaValidator()

    # Validate before translation (input)
    errors = validator.validate("a2a_agent_card", agent_card)
    if errors:
        raise ValueError(f"Invalid A2A Agent Card: {errors}")

    # Translate
    mcp_card = translator.a2a_to_mcp(agent_card)

    # Validate after translation (output)
    errors = validator.validate("mcp_server_card", mcp_card)
    if errors:
        raise ValueError(f"Translation produced invalid MCP card: {errors}")

    # Validate a passport
    errors = validator.validate("aib_passport", passport_dict)

Each schema is permissive enough to accept real-world documents
(which often have extra fields) but strict enough to catch
structural errors before they propagate through translation.

References: OPT-TRANS-01 in Security Audit document.
"""

from typing import Optional
from jsonschema import validate, ValidationError, Draft7Validator


# ═══════════════════════════════════════════════════════════════════
# SCHEMAS
# ═══════════════════════════════════════════════════════════════════

A2A_AGENT_CARD_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "A2A Agent Card",
    "description": "Google Agent-to-Agent protocol Agent Card",
    "type": "object",
    "required": ["name"],
    "properties": {
        "name": {"type": "string", "minLength": 1, "maxLength": 200},
        "description": {"type": "string", "maxLength": 2000},
        "url": {"type": "string", "format": "uri", "maxLength": 2048},
        "version": {"type": "string", "maxLength": 20},
        "skills": {
            "type": "array",
            "maxItems": 50,
            "items": {
                "type": "object",
                "required": ["id", "name"],
                "properties": {
                    "id": {"type": "string", "minLength": 1, "maxLength": 100},
                    "name": {"type": "string", "minLength": 1, "maxLength": 200},
                    "description": {"type": "string", "maxLength": 2000},
                },
            },
        },
        "authentication": {
            "type": "object",
            "properties": {
                "schemes": {
                    "type": "array",
                    "maxItems": 10,
                    "items": {
                        "oneOf": [
                            {"type": "string"},
                            {
                                "type": "object",
                                "properties": {
                                    "scheme": {"type": "string"},
                                },
                            },
                        ],
                    },
                },
                "flows": {"type": "object"},
            },
        },
        "capabilities": {
            "type": "object",
            "properties": {
                "streaming": {"type": "boolean"},
                "pushNotifications": {"type": "boolean"},
            },
        },
    },
    "additionalProperties": True,
}

MCP_SERVER_CARD_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "MCP Server Card",
    "description": "Anthropic Model Context Protocol Server Card",
    "type": "object",
    "required": ["name"],
    "properties": {
        "name": {"type": "string", "minLength": 1, "maxLength": 200},
        "description": {"type": "string", "maxLength": 2000},
        "server_url": {"type": "string", "maxLength": 2048},
        "version": {"type": "string", "maxLength": 20},
        "tools": {
            "type": "array",
            "maxItems": 50,
            "items": {
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": {"type": "string", "minLength": 1, "maxLength": 200},
                    "description": {"type": "string", "maxLength": 2000},
                    "inputSchema": {"type": "object"},
                },
            },
        },
        "auth": {
            "type": "object",
            "properties": {
                "type": {
                    "type": "string",
                    "enum": ["none", "bearer", "oauth2", "api_key"],
                },
            },
        },
        "transport": {
            "type": "string",
            "enum": ["streamable-http", "stdio", "sse"],
        },
        "metadata": {"type": "object"},
        # AIB metadata fields (added by translator)
        "_aib_source": {"type": "string"},
        "_aib_translated_at": {"type": "string"},
    },
    "additionalProperties": True,
}

DID_DOCUMENT_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "W3C DID Document",
    "description": "Decentralized Identifier Document (simplified)",
    "type": "object",
    "required": ["id"],
    "properties": {
        "id": {
            "type": "string",
            "pattern": "^did:[a-z]+:",
            "maxLength": 500,
        },
        "@context": {
            "oneOf": [
                {"type": "string"},
                {"type": "array", "items": {"type": "string"}},
            ],
        },
        "verificationMethod": {
            "type": "array",
            "maxItems": 20,
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "type": {"type": "string"},
                    "controller": {"type": "string"},
                },
            },
        },
        "authentication": {
            "type": "array",
            "items": {
                "oneOf": [
                    {"type": "string"},
                    {"type": "object"},
                ],
            },
        },
        "service": {
            "type": "array",
            "maxItems": 20,
            "items": {
                "type": "object",
                "required": ["id", "type", "serviceEndpoint"],
                "properties": {
                    "id": {"type": "string"},
                    "type": {"type": "string"},
                    "serviceEndpoint": {"type": "string", "maxLength": 2048},
                },
            },
        },
        # AIB metadata
        "_aib_source": {"type": "string"},
        "_aib_translated_at": {"type": "string"},
        "_aib_passport_id": {"type": "string"},
    },
    "additionalProperties": True,
}

AIB_PASSPORT_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "AIB Agent Passport",
    "description": "Agent Identity Bridge portable identity document",
    "type": "object",
    "required": ["passport_id", "issuer", "capabilities", "protocol_bindings"],
    "properties": {
        "aib_version": {"type": "string"},
        "passport_id": {
            "type": "string",
            "pattern": "^urn:aib:agent:",
            "maxLength": 200,
        },
        "display_name": {"type": "string", "maxLength": 200},
        "issuer": {
            "type": "string",
            "pattern": "^urn:aib:org:",
            "maxLength": 200,
        },
        "capabilities": {
            "type": "array",
            "items": {"type": "string", "maxLength": 100},
            "maxItems": 50,
        },
        "protocol_bindings": {
            "type": "object",
            "propertyNames": {
                "enum": ["mcp", "a2a", "anp", "ag-ui", "ag_ui"],
            },
            "additionalProperties": {
                "type": "object",
                "properties": {
                    "auth_method": {"type": "string"},
                },
            },
        },
        "tier": {
            "type": "string",
            "enum": ["permanent", "session", "ephemeral"],
        },
        "issued_at": {"type": "string"},
        "expires_at": {"type": "string"},
        "jti": {"type": "string"},
        "delegation": {
            "type": ["object", "null"],
            "properties": {
                "parent_passport_id": {"type": "string"},
                "delegation_chain": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "max_depth": {"type": "integer", "minimum": 1, "maximum": 10},
            },
        },
        "metadata": {"type": "object"},
    },
    "additionalProperties": True,
}

# Schema for the .well-known/aib.json discovery document
AIB_DISCOVERY_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "AIB Discovery Document",
    "type": "object",
    "required": ["aib_version", "issuer", "domain"],
    "properties": {
        "aib_version": {"type": "string"},
        "issuer": {"type": "string", "pattern": "^urn:aib:org:"},
        "domain": {"type": "string"},
        "organization": {"type": "string"},
        "supported_protocols": {
            "type": "array",
            "items": {"type": "string"},
        },
        "gateway_url": {"type": "string"},
        "endpoints": {"type": "object"},
        "discovery": {"type": "object"},
        "features": {"type": "array", "items": {"type": "string"}},
        "security": {"type": "object"},
    },
    "additionalProperties": True,
}


# ═══════════════════════════════════════════════════════════════════
# SCHEMA REGISTRY
# ═══════════════════════════════════════════════════════════════════

SCHEMA_REGISTRY = {
    "a2a_agent_card": A2A_AGENT_CARD_SCHEMA,
    "a2a": A2A_AGENT_CARD_SCHEMA,
    "mcp_server_card": MCP_SERVER_CARD_SCHEMA,
    "mcp": MCP_SERVER_CARD_SCHEMA,
    "did_document": DID_DOCUMENT_SCHEMA,
    "did": DID_DOCUMENT_SCHEMA,
    "aib_passport": AIB_PASSPORT_SCHEMA,
    "passport": AIB_PASSPORT_SCHEMA,
    "aib_discovery": AIB_DISCOVERY_SCHEMA,
    "discovery": AIB_DISCOVERY_SCHEMA,
}


# ═══════════════════════════════════════════════════════════════════
# VALIDATOR
# ═══════════════════════════════════════════════════════════════════

class SchemaValidationError(ValueError):
    """Raised when a document fails schema validation."""
    def __init__(self, format_name: str, errors: list[str]):
        self.format_name = format_name
        self.errors = errors
        super().__init__(f"Schema validation failed for {format_name}: {'; '.join(errors)}")


class SchemaValidator:
    """
    Validates protocol identity documents against JSON Schema.

    Wraps jsonschema with:
    - Named format registry (a2a, mcp, did, passport, discovery)
    - Collect ALL errors (not just the first one)
    - Clean error messages (strip jsonschema internals)
    - Optional strict mode (fail on unknown formats)

    Usage:
        v = SchemaValidator()

        # Returns list of error strings (empty = valid)
        errors = v.validate("a2a_agent_card", card)

        # Raises SchemaValidationError if invalid
        v.validate_or_raise("mcp_server_card", card)

        # Check without exceptions
        if v.is_valid("did_document", doc):
            ...
    """

    def __init__(self, strict: bool = False):
        """
        Args:
            strict: If True, validate() raises on unknown format names.
                    If False, unknown formats return no errors (pass-through).
        """
        self.strict = strict
        self._schemas = dict(SCHEMA_REGISTRY)

    def register_schema(self, name: str, schema: dict):
        """Register a custom schema (for plugin protocols)."""
        self._schemas[name] = schema

    def get_schema(self, name: str) -> Optional[dict]:
        """Get a schema by name."""
        return self._schemas.get(name)

    def list_formats(self) -> list[str]:
        """List all registered format names."""
        return sorted(set(self._schemas.keys()))

    def validate(self, format_name: str, document: dict) -> list[str]:
        """
        Validate a document against a named schema.

        Returns a list of error messages. Empty list = valid.
        """
        schema = self._schemas.get(format_name)
        if not schema:
            if self.strict:
                return [f"Unknown format: {format_name}"]
            return []  # Unknown format, pass-through

        errors = []
        validator = Draft7Validator(schema)
        for error in sorted(validator.iter_errors(document), key=lambda e: list(e.path)):
            path = ".".join(str(p) for p in error.absolute_path) or "(root)"
            msg = error.message
            # Clean up common verbose jsonschema messages
            if len(msg) > 200:
                msg = msg[:200] + "..."
            errors.append(f"{path}: {msg}")

        return errors

    def validate_or_raise(self, format_name: str, document: dict):
        """Validate and raise SchemaValidationError if invalid."""
        errors = self.validate(format_name, document)
        if errors:
            raise SchemaValidationError(format_name, errors)

    def is_valid(self, format_name: str, document: dict) -> bool:
        """Check if a document is valid (no exceptions)."""
        return len(self.validate(format_name, document)) == 0

    def validate_translation(
        self,
        source: dict,
        source_format: str,
        result: dict,
        result_format: str,
    ) -> dict:
        """
        Validate both sides of a translation.

        Returns:
            {
                "source_valid": bool,
                "source_errors": [...],
                "result_valid": bool,
                "result_errors": [...],
                "valid": bool  (both valid)
            }
        """
        source_errors = self.validate(source_format, source)
        result_errors = self.validate(result_format, result)
        return {
            "source_valid": len(source_errors) == 0,
            "source_errors": source_errors,
            "result_valid": len(result_errors) == 0,
            "result_errors": result_errors,
            "valid": len(source_errors) == 0 and len(result_errors) == 0,
        }
