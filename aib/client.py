"""
AIB SDK — One-liner client for Agent Identity Bridge.

Usage:
    from aib.client import AIBClient

    client = AIBClient(api_key="aib_sk_...")

    # Send a request through the AIB gateway — protocol auto-detected
    result = client.send("https://partner.com/agent", {"task": "Book 3pm tomorrow"})
    print(result.protocol)    # "a2a"
    print(result.trace_id)    # "7f3a...b2c1"
    print(result.data)        # response payload

    # Create a passport
    passport = client.create_passport(org="mycompany", agent="booking", protocols=["mcp", "a2a"])

    # Translate identity formats
    mcp_card = client.translate(source=a2a_card, from_format="a2a", to_format="mcp")

    # Verify a passport token
    is_valid, info = client.verify(token="eyJ...")

    # Revoke an agent
    client.revoke("urn:aib:agent:mycompany:booking")

    # List all passports
    passports = client.list_passports()

Works with both the self-hosted gateway (aib serve) and AIB Cloud (gateway.aib.cloud).
"""

import json
import time
from dataclasses import dataclass, field
from typing import Optional, Any
from urllib.parse import urljoin


# ── Response objects ──────────────────────────────────────────────

@dataclass
class SendResult:
    """Response from a gateway proxy call."""
    success: bool
    protocol: str
    trace_id: str
    status_code: int
    data: Any
    latency_ms: float
    passport_id: Optional[str] = None

    def __repr__(self):
        return (
            f"SendResult(success={self.success}, protocol='{self.protocol}', "
            f"trace_id='{self.trace_id[:12]}...', latency={self.latency_ms:.0f}ms)"
        )


@dataclass
class Passport:
    """A created or retrieved passport."""
    passport_id: str
    display_name: str
    protocols: list[str]
    capabilities: list[str]
    expires_at: str
    token: Optional[str] = None
    raw: dict = field(default_factory=dict)

    def __repr__(self):
        return (
            f"Passport(id='{self.passport_id}', protocols={self.protocols}, "
            f"expires='{self.expires_at[:10]}')"
        )


@dataclass
class VerifyResult:
    """Passport verification result."""
    valid: bool
    passport_id: Optional[str] = None
    issuer: Optional[str] = None
    protocols: Optional[list[str]] = None
    expires_at: Optional[str] = None
    reason: str = ""

    def __bool__(self):
        return self.valid


@dataclass
class TranslateResult:
    """Translation result between identity formats."""
    source_format: str
    target_format: str
    data: dict
    tools_count: int = 0
    skills_count: int = 0

    def __repr__(self):
        return f"TranslateResult({self.source_format} → {self.target_format})"


# ── Main client ───────────────────────────────────────────────────

class AIBClient:
    """
    One-liner client for Agent Identity Bridge.

    Works with:
    - Self-hosted gateway: AIBClient(gateway_url="http://localhost:8420")
    - AIB Cloud: AIBClient(api_key="aib_sk_...")

    All methods are synchronous by default. Use AIBAsyncClient for async.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        gateway_url: str = "http://localhost:8420",
        timeout: float = 30.0,
    ):
        self.api_key = api_key
        self.gateway_url = gateway_url.rstrip("/")
        self.timeout = timeout

        # If api_key starts with aib_sk_, use AIB Cloud
        if api_key and api_key.startswith("aib_sk_"):
            self.gateway_url = "https://gateway.aib.cloud"

        try:
            import httpx
            self._http = httpx.Client(
                base_url=self.gateway_url,
                timeout=timeout,
                headers=self._headers(),
            )
        except ImportError:
            raise ImportError(
                "httpx is required for AIBClient. Install with: "
                "pip install agent-identity-bridge"
            )

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json", "User-Agent": "aib-sdk/0.3.0"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def _url(self, path: str) -> str:
        return path

    # ── Gateway Proxy ─────────────────────────────────────────

    def send(
        self,
        target_url: str,
        body: dict,
        passport_id: Optional[str] = None,
        method: str = "POST",
    ) -> SendResult:
        """
        Send a request through the AIB gateway.

        The gateway auto-detects the target protocol (MCP, A2A, ANP),
        injects the right credentials, and logs the interaction.

            result = client.send("https://partner.com/agent", {"task": "..."})
            print(result.protocol)  # "a2a"
        """
        t0 = time.time()

        payload = {
            "target_url": target_url,
            "method": method,
            "body": body,
        }
        if passport_id:
            payload["passport_id"] = passport_id

        resp = self._http.post(self._url("/gateway/proxy"), json=payload)
        latency = (time.time() - t0) * 1000

        if resp.status_code == 200:
            data = resp.json()
            return SendResult(
                success=True,
                protocol=data.get("detected_protocol", "unknown"),
                trace_id=data.get("trace_id", ""),
                status_code=data.get("upstream_status", 200),
                data=data.get("response", data),
                latency_ms=latency,
                passport_id=data.get("passport_id"),
            )
        else:
            return SendResult(
                success=False,
                protocol="unknown",
                trace_id="",
                status_code=resp.status_code,
                data=resp.text,
                latency_ms=latency,
            )

    # ── Passport Management ───────────────────────────────────

    def create_passport(
        self,
        org: str,
        agent: str,
        protocols: list[str],
        capabilities: Optional[list[str]] = None,
        name: Optional[str] = None,
        ttl_days: int = 365,
    ) -> Passport:
        """
        Create a new Agent Passport.

            passport = client.create_passport(
                org="mycompany",
                agent="booking",
                protocols=["mcp", "a2a"]
            )
        """
        payload = {
            "org_slug": org,
            "agent_slug": agent,
            "protocols": protocols,
            "capabilities": capabilities or [agent],
            "display_name": name or f"{org}/{agent}",
            "ttl_days": ttl_days,
        }

        resp = self._http.post(self._url("/passports"), json=payload)
        resp.raise_for_status()
        data = resp.json()

        passport_data = data.get("passport", data)
        return Passport(
            passport_id=passport_data.get("passport_id", ""),
            display_name=passport_data.get("display_name", ""),
            protocols=list(passport_data.get("protocol_bindings", {}).keys()),
            capabilities=passport_data.get("capabilities", []),
            expires_at=passport_data.get("expires_at", ""),
            token=data.get("token"),
            raw=passport_data,
        )

    def verify(self, token: str) -> VerifyResult:
        """
        Verify a passport token.

            result = client.verify("eyJ...")
            if result:
                print(f"Valid: {result.passport_id}")
        """
        resp = self._http.post(
            self._url("/passports/verify"),
            json={"token": token}
        )
        data = resp.json()

        if data.get("valid"):
            passport = data.get("passport", {})
            return VerifyResult(
                valid=True,
                passport_id=passport.get("passport_id"),
                issuer=passport.get("issuer"),
                protocols=list(passport.get("protocol_bindings", {}).keys()),
                expires_at=passport.get("expires_at"),
                reason="Valid",
            )
        else:
            return VerifyResult(
                valid=False,
                reason=data.get("reason", "Unknown error"),
            )

    def revoke(self, passport_id: str) -> bool:
        """
        Revoke a passport. One call, all protocols.

            client.revoke("urn:aib:agent:mycompany:booking")
        """
        resp = self._http.post(
            self._url("/passports/revoke"),
            json={"passport_id": passport_id}
        )
        return resp.status_code == 200

    def list_passports(self) -> list[Passport]:
        """
        List all passports.

            for p in client.list_passports():
                print(p.passport_id, p.protocols)
        """
        resp = self._http.get(self._url("/passports"))
        resp.raise_for_status()
        data = resp.json()

        items = data if isinstance(data, list) else data.get("passports", [])
        return [
            Passport(
                passport_id=p.get("passport_id", ""),
                display_name=p.get("display_name", ""),
                protocols=p.get("protocols", list(p.get("protocol_bindings", {}).keys())),
                capabilities=p.get("capabilities", []),
                expires_at=p.get("expires_at", ""),
                raw=p,
            )
            for p in items
        ]

    # ── Credential Translation ────────────────────────────────

    def translate(
        self,
        source: dict,
        from_format: str,
        to_format: str,
        domain: Optional[str] = None,
        agent_slug: Optional[str] = None,
    ) -> TranslateResult:
        """
        Translate between identity formats.

            mcp_card = client.translate(
                source=a2a_agent_card,
                from_format="a2a",
                to_format="mcp"
            )
            print(mcp_card.data)  # MCP Server Card
        """
        format_map = {
            "a2a": "a2a_agent_card",
            "mcp": "mcp_server_card",
            "did": "did_document",
        }

        payload = {
            "source": source,
            "from_format": format_map.get(from_format, from_format),
            "to_format": format_map.get(to_format, to_format),
        }
        if domain:
            payload["domain"] = domain
        if agent_slug:
            payload["agent_slug"] = agent_slug

        resp = self._http.post(self._url("/translate"), json=payload)
        resp.raise_for_status()
        data = resp.json()

        return TranslateResult(
            source_format=from_format,
            target_format=to_format,
            data=data,
            tools_count=len(data.get("tools", [])),
            skills_count=len(data.get("skills", [])),
        )

    # ── Audit Trail ───────────────────────────────────────────

    def get_audit(
        self,
        passport_id: Optional[str] = None,
        protocol: Optional[str] = None,
        limit: int = 50,
    ) -> list[dict]:
        """
        Query the audit trail.

            traces = client.get_audit(passport_id="urn:aib:agent:myco:bot")
            for t in traces:
                print(t["timestamp"], t["action"], t["protocol"])
        """
        params = {"limit": limit}
        if passport_id:
            params["passport_id"] = passport_id
        if protocol:
            params["protocol"] = protocol

        resp = self._http.get(self._url("/audit"), params=params)
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, list) else data.get("entries", [])

    # ── Health ────────────────────────────────────────────────

    def health(self) -> dict:
        """Check gateway health."""
        resp = self._http.get(self._url("/health"))
        return resp.json()

    # ── Context manager ───────────────────────────────────────

    def close(self):
        """Close the HTTP client."""
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __repr__(self):
        target = "AIB Cloud" if "aib.cloud" in self.gateway_url else self.gateway_url
        return f"AIBClient(gateway='{target}')"
