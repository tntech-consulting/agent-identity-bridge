"""
AIB Cloud SDK — Python client for AIB Cloud managed gateway.

Usage:
    from aib.cloud import AIBCloud

    client = AIBCloud("aib_sk_live_...")
    passport = client.create_passport("my-bot", protocols=["mcp", "a2a"])
    translated = client.translate(source, "a2a_agent_card", "mcp_server_card")
    audit = client.audit_trail(passport_id="urn:aib:agent:myorg:my-bot")
    intent = client.intent_analyze("Accessing user calendar to schedule meeting")
    vc = client.vc_issue(passport_id="urn:aib:agent:myorg:my-bot", claims={"role": "assistant"})
    usage = client.usage()
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Any, Optional


DEFAULT_BASE_URL = "https://aib-tech.fr/api"


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

    # ── Audit Trail ───────────────────────────────────────

    def audit_trail(
        self,
        passport_id: str = "",
        limit: int = 50,
        offset: int = 0,
        compliance_format: bool = False,
    ) -> dict:
        """Query signed cryptographic receipts (audit trail).

        Each receipt is an immutable, signed proof of every operation
        (passport creation, revocation, translation, policy check).

        Args:
            passport_id: Filter by passport URN. Empty = all org receipts.
            limit: Max results (default 50, max 200).
            offset: Pagination offset.
            compliance_format: If True, returns EU AI Act Article 12 compliance report.

        Returns:
            Dict with receipts list, count, and optional compliance_report.

        Example:
            # Get all receipts for a specific agent
            trail = client.audit_trail("urn:aib:agent:myorg:my-bot")

            # Get Article 12 compliance report
            report = client.audit_trail(compliance_format=True)
        """
        params = f"?limit={limit}&offset={offset}"
        if passport_id:
            params += f"&passport_id={passport_id}"
        if compliance_format:
            params += "&format=compliance"
        return self._request(f"audit-trail{params}")

    # ── Intent Analysis (EU AI Act) ───────────────────────

    def intent_analyze(
        self,
        description: str,
        passport_id: str = "",
        context: dict | None = None,
        mode: str = "auto",
    ) -> dict:
        """Analyze agent intent for EU AI Act compliance.

        Uses Claude Haiku (LLM mode) or rule-based fallback to infer intent,
        assess risk level, detect anomalies, and check EU AI Act compliance.

        Args:
            description: Natural language description of the agent's action.
            passport_id: Optional passport URN to enrich analysis with passport context.
            context: Optional extra context dict (data_accessed, invocation_chain, etc.).
            mode: "llm" (Claude Haiku), "rules" (fast, no LLM), or "auto" (default).

        Returns:
            Dict with:
                intent: Inferred intent category
                risk_level: "low" | "medium" | "high" | "critical"
                eu_ai_act: compliance assessment per article
                anomalies: list of detected anomalies
                recommendations: list of suggested policy actions
                latency_ms: analysis duration

        Example:
            result = client.intent_analyze(
                "Accessing user calendar to schedule a meeting",
                passport_id="urn:aib:agent:myorg:scheduler",
                context={"data_accessed": ["calendar", "contacts"]},
            )
            print(result["risk_level"])   # "low"
            print(result["eu_ai_act"])    # {"article_13": "compliant", ...}
        """
        body: dict[str, Any] = {"description": description, "mode": mode}
        if passport_id:
            body["passport_id"] = passport_id
        if context:
            body["context"] = context
        return self._request("intent-analyze", "POST", body)

    # ── Verifiable Credentials ────────────────────────────

    def vc_issue(
        self,
        passport_id: str,
        claims: dict,
        credential_type: str = "AgentIdentityCredential",
        ttl_days: int = 365,
    ) -> dict:
        """Issue a W3C Verifiable Credential for an agent passport.

        The VC is signed with Ed25519Signature2020 and anchored to the passport.
        It can be verified by any third party without contacting AIB Cloud.

        Args:
            passport_id: The passport URN to anchor the credential to.
            claims: Credential subject claims (e.g. {"role": "assistant", "clearance": "L2"}).
            credential_type: VC type (default: "AgentIdentityCredential").
            ttl_days: Validity in days (default: 365).

        Returns:
            Dict with:
                vc: The full W3C Verifiable Credential object
                vc_id: Unique credential identifier
                proof: Ed25519Signature2020 proof block
                status_url: URL to check revocation status

        Example:
            vc = client.vc_issue(
                passport_id="urn:aib:agent:myorg:my-bot",
                claims={"role": "data-analyst", "clearance": "level-2"},
            )
            print(vc["vc"]["proof"]["type"])  # "Ed25519Signature2020"
        """
        body: dict[str, Any] = {
            "passport_id": passport_id,
            "claims": claims,
            "credential_type": credential_type,
        }
        if ttl_days != 365:
            body["ttl_days"] = ttl_days
        return self._request("vc-issue", "POST", body)

    def vc_verify(self, vc_id: str) -> dict:
        """Check the revocation status of a Verifiable Credential.

        This endpoint is public — no API key required.

        Args:
            vc_id: The VC identifier (from vc_issue response).

        Returns:
            Dict with status ("active" | "revoked"), vc_id, issued_at, expires_at.
        """
        return self._request(f"vc-issue?vc_id={vc_id}")

    # ── DID Resolution ────────────────────────────────────

    def did_resolve(self, did: str) -> dict:
        """Resolve a DID to its DID Document.

        Supports did:web and did:key methods.

        Args:
            did: The DID to resolve (e.g. "did:web:aib-tech.fr:agents:my-bot"
                 or "did:key:z6Mk...").

        Returns:
            W3C DID Document dict with id, verificationMethod, authentication, etc.

        Example:
            doc = client.did_resolve("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
            print(doc["verificationMethod"][0]["type"])  # "Ed25519VerificationKey2020"
        """
        return self._request(f"did-resolve?did={did}")

    # ── Ed25519 Key Generation ────────────────────────────

    def keygen(self, admin_key: str) -> dict:
        """Generate an Ed25519 key pair.

        Requires an admin key. The private key is returned once — store it securely.

        Args:
            admin_key: Admin key (X-Admin-Key header value).

        Returns:
            Dict with public_key_hex, private_key_hex, did_key, jwk.

        Example:
            keys = client.keygen(admin_key="your-admin-key")
            print(keys["did_key"])       # "did:key:z6Mk..."
            print(keys["public_key_hex"])
        """
        url = f"{self.base_url}/ed25519-keygen"
        headers = {
            "Content-Type": "application/json",
            "X-Admin-Key": admin_key,
        }
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            try:
                err_body = json.loads(e.read().decode("utf-8"))
            except Exception:
                err_body = {"error": str(e)}
            raise AIBCloudError(
                message=err_body.get("error", str(e)),
                code=err_body.get("code", ""),
                status=e.code,
            ) from None

    # ── Passport Templates ────────────────────────────────

    def list_templates(self, protocol: str = "", use_case: str = "") -> dict:
        """List available passport templates.

        Templates are pre-configured passport definitions for common use cases
        (customer support bot, data analyst, CI/CD agent, etc.).

        Args:
            protocol: Filter by protocol ("mcp", "a2a", "anp"). Empty = all.
            use_case: Filter by use case keyword.

        Returns:
            Dict with templates list, each with id, name, description,
            protocols, capabilities, suggested_policies.

        Example:
            templates = client.list_templates(protocol="mcp")
            for t in templates["templates"]:
                print(t["name"], t["protocols"])
        """
        params = "?"
        if protocol:
            params += f"protocol={protocol}&"
        if use_case:
            params += f"use_case={use_case}&"
        return self._request(f"template-list{params.rstrip('?&')}")

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

    def __repr__(self) -> str:
        auth = f"api_key={self.api_key[:18]}..." if self.api_key else "access_token=***"
        return f"AIBCloud({auth})"
