"""
AIB Cloud SDK — Python client for AIB Cloud managed gateway.

Usage:
    from aib.cloud import AIBCloud

    client = AIBCloud("aib_sk_live_...")
    passport = client.create_passport("my-bot", protocols=["mcp", "a2a"])
    translated = client.translate(source, "a2a_agent_card", "mcp_server_card")
    usage = client.usage()
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Any, Optional


DEFAULT_BASE_URL = "https://vempwtzknixfnvysmiwo.supabase.co/functions/v1"


class AIBCloudError(Exception):
    """Error from AIB Cloud API."""

    def __init__(self, message: str, code: str = "", status: int = 0, violations: list | None = None):
        super().__init__(message)
        self.code = code
        self.status = status
        self.violations = violations or []


class AIBCloud:
    """Client for AIB Cloud managed gateway.

    Authenticate with an API key or an access token (from login).

    Args:
        api_key: API key (aib_sk_live_...). Preferred method.
        access_token: Bearer token from auth/login. Alternative.
        base_url: Override the default API base URL.
        timeout: Request timeout in seconds (default 30).
    """

    def __init__(
        self,
        api_key: str = "",
        access_token: str = "",
        base_url: str = DEFAULT_BASE_URL,
        timeout: int = 30,
    ):
        if not api_key and not access_token:
            raise AIBCloudError("Provide api_key or access_token")
        self.api_key = api_key
        self.access_token = access_token
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(self, endpoint: str, method: str = "GET", body: dict | None = None) -> dict:
        """Make an HTTP request to the AIB Cloud API."""
        url = f"{self.base_url}/{endpoint}"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["x-api-key"] = self.api_key
        elif self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"

        data = json.dumps(body).encode("utf-8") if body else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                return result
        except urllib.error.HTTPError as e:
            try:
                err_body = json.loads(e.read().decode("utf-8"))
            except Exception:
                err_body = {"error": str(e)}
            raise AIBCloudError(
                message=err_body.get("error", str(e)),
                code=err_body.get("code", ""),
                status=e.code,
                violations=err_body.get("violations", []),
            ) from None
        except urllib.error.URLError as e:
            raise AIBCloudError(f"Connection error: {e.reason}") from None

    # ── Auth ──────────────────────────────────────────────

    @classmethod
    def signup(cls, email: str, password: str, full_name: str = "", base_url: str = DEFAULT_BASE_URL) -> dict:
        """Create a new account. Returns user, org, api_key, access_token.

        Example:
            result = AIBCloud.signup("user@example.com", "MyPassword123")
            client = AIBCloud(api_key=result["api_key"])
        """
        tmp = cls.__new__(cls)
        tmp.api_key = ""
        tmp.access_token = ""
        tmp.base_url = base_url.rstrip("/")
        tmp.timeout = 30
        return tmp._request("auth", "POST", {
            "action": "signup", "email": email, "password": password, "full_name": full_name,
        })

    @classmethod
    def login(cls, email: str, password: str, base_url: str = DEFAULT_BASE_URL) -> dict:
        """Login to an existing account. Returns access_token and api_keys list.

        Example:
            result = AIBCloud.login("user@example.com", "MyPassword123")
            client = AIBCloud(access_token=result["access_token"])
        """
        tmp = cls.__new__(cls)
        tmp.api_key = ""
        tmp.access_token = ""
        tmp.base_url = base_url.rstrip("/")
        tmp.timeout = 30
        return tmp._request("auth", "POST", {
            "action": "login", "email": email, "password": password,
        })

    def generate_key(self, name: str = "API Key") -> str:
        """Generate a new API key for the current org.

        Returns the raw API key string. Save it — it won't be shown again.
        """
        body: dict[str, Any] = {"action": "generate_key", "key_name": name}
        if self.api_key:
            body["api_key"] = self.api_key
        if self.access_token:
            body["access_token"] = self.access_token
        result = self._request("auth", "POST", body)
        return result.get("api_key", "")

    # ── Passports ─────────────────────────────────────────

    def create_passport(
        self,
        agent_slug: str,
        protocols: list[str] | None = None,
        capabilities: list[str] | None = None,
        display_name: str = "",
        tier: str = "permanent",
        ttl_days: int = 365,
    ) -> dict:
        """Create an Agent Passport.

        Args:
            agent_slug: Unique identifier for the agent (e.g. "my-bot").
            protocols: List of protocols (default: ["mcp", "a2a"]).
            capabilities: Agent capabilities (e.g. ["booking", "support"]).
            display_name: Human-readable name.
            tier: Passport tier (default: "permanent").
            ttl_days: Time to live in days (default: 365).

        Returns:
            Passport dict with passport_id, protocols, capabilities, bindings, signature.

        Raises:
            AIBCloudError: On policy violation (code AIB-601) or duplicate (AIB-301).
        """
        body: dict[str, Any] = {"agent_slug": agent_slug}
        if protocols:
            body["protocols"] = protocols
        if capabilities:
            body["capabilities"] = capabilities
        if display_name:
            body["display_name"] = display_name
        if tier != "permanent":
            body["tier"] = tier
        if ttl_days != 365:
            body["ttl_days"] = ttl_days
        return self._request("passport-create", "POST", body)

    def list_passports(self, status: str = "", limit: int = 50, offset: int = 0) -> dict:
        """List passports for the current org.

        Args:
            status: Filter by status ("active", "revoked", "expired"). Empty = all.
            limit: Max results (default 50, max 200).
            offset: Pagination offset.

        Returns:
            Dict with count, passports list.
        """
        params = f"?limit={limit}&offset={offset}"
        if status:
            params += f"&status={status}"
        return self._request(f"passport-list{params}")

    def revoke_passport(self, passport_id: str, reason: str = "") -> dict:
        """Revoke a passport and cascade-revoke its children.

        Args:
            passport_id: The passport URN (e.g. "urn:aib:agent:org:my-bot").
            reason: Optional revocation reason.

        Returns:
            Dict with revoked passport_id, cascaded_children count, signature.
        """
        body: dict[str, Any] = {"passport_id": passport_id}
        if reason:
            body["reason"] = reason
        return self._request("passport-revoke", "POST", body)

    # ── Translate ─────────────────────────────────────────

    def translate(self, source: dict, from_format: str, to_format: str) -> dict:
        """Translate credentials between protocol formats.

        Supported formats: a2a_agent_card, mcp_server_card, ag_ui_descriptor.

        Args:
            source: The source credential object.
            from_format: Source format name.
            to_format: Target format name.

        Returns:
            Dict with from_format, to_format, latency_ms, result.
        """
        return self._request("translate", "POST", {
            "source": source, "from_format": from_format, "to_format": to_format,
        })

    # ── Usage & Analytics ─────────────────────────────────

    def usage(self) -> dict:
        """Get current usage, quotas, and org details.

        Returns:
            Dict with org, month, usage (transactions, passports, translations, webhooks), totals.
        """
        return self._request("usage-check")

    def usage_history(self, days: int = 30) -> dict:
        """Get daily activity history for analytics.

        Args:
            days: Number of days to look back (default 30, max 90).

        Returns:
            Dict with daily activity, action breakdown, recent activity.
        """
        return self._request(f"usage-history?days={days}")

    # ── Policies ──────────────────────────────────────────

    def list_policies(self, active_only: bool = True) -> dict:
        """List policy rules for the current org.

        Returns:
            Dict with rules list and count.
        """
        params = "" if active_only else "?active=false"
        return self._request(f"policy-manage{params}")

    def create_policy(
        self,
        rule_type: str,
        config: dict,
        description: str = "",
        severity: str = "block",
    ) -> dict:
        """Create a new policy rule.

        Supported rule types:
            deliverable_gate, separation_of_duties, attestation_required,
            capability_required, domain_block, domain_allow,
            protocol_restrict, tier_restrict, time_restrict, rate_limit.

        Args:
            rule_type: One of the supported rule types.
            config: Rule configuration (varies by type).
            description: Human-readable description.
            severity: "block", "warn", or "log".

        Returns:
            Created rule dict with rule_id.
        """
        body: dict[str, Any] = {"rule_type": rule_type, "config": config, "severity": severity}
        if description:
            body["description"] = description
        return self._request("policy-manage", "POST", body)

    def delete_policy(self, rule_id: str) -> dict:
        """Deactivate a policy rule.

        Args:
            rule_id: The rule ID to deactivate.

        Returns:
            Dict with deactivated rule_id.
        """
        return self._request(f"policy-manage?rule_id={rule_id}", "DELETE")

    # ── Convenience ───────────────────────────────────────

    def health(self) -> dict:
        """Quick health check — calls usage-check and returns org info."""
        u = self.usage()
        return {
            "status": "ok",
            "org": u.get("org", {}),
            "month": u.get("month", ""),
            "transactions": u.get("usage", {}).get("transactions", {}),
        }

    # ── Webhooks ──────────────────────────────────────────

    def list_webhooks(self) -> dict:
        """List all webhooks for the current org.

        Returns:
            Dict with webhooks list and count.
        """
        return self._request("webhook-manage")

    def create_webhook(
        self,
        url: str,
        events: list[str] | None = None,
        secret: str = "",
        timeout_ms: int = 5000,
    ) -> dict:
        """Create a new webhook.

        Args:
            url: The URL to POST events to (must be HTTPS in production).
            events: List of events to subscribe to. Default: ["passport.created", "passport.revoked"].
                Valid events: passport.created, passport.revoked, policy.violation, translate.completed.
            secret: Optional HMAC secret for signature verification.
            timeout_ms: Request timeout in ms (default 5000).

        Returns:
            Created webhook dict with id, url, events, status.
        """
        body: dict[str, Any] = {"url": url, "timeout_ms": timeout_ms}
        if events:
            body["events"] = events
        if secret:
            body["secret"] = secret
        return self._request("webhook-manage", "POST", body)

    def delete_webhook(self, webhook_id: str) -> dict:
        """Delete a webhook.

        Args:
            webhook_id: The webhook UUID to delete.

        Returns:
            Dict with deleted webhook_id.
        """
        return self._request(f"webhook-manage?id={webhook_id}", "DELETE")

    def __repr__(self) -> str:
        auth = f"api_key={self.api_key[:18]}..." if self.api_key else "access_token=***"
        return f"AIBCloud({auth})"
