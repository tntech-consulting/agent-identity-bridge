"""
AIB — Sprint 9: Webhook pre/post action system.

Enables external systems (guardrails, monitoring, billing, SIEM) to
hook into the gateway request lifecycle without modifying AIB code.

Flow:
  1. Agent sends request to AIB gateway
  2. AIB sends pre-action webhook → external system (Galileo, APort, NeMo, custom)
  3. External system responds: allow / deny / allow-with-modifications
  4. If allowed → AIB proxies the request
  5. AIB sends post-action webhook → external system (audit, billing, monitoring)

This makes AIB the identity + routing layer, while guardrails stay external.
Best of both worlds: AIB doesn't compete with guardrails, it integrates all of them.
"""

import json
import time
import uuid
import hashlib
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Any, Callable
from enum import Enum


# ═══════════════════════════════════════════════════════════════════
# WEBHOOK TYPES
# ═══════════════════════════════════════════════════════════════════

class WebhookEvent(str, Enum):
    PRE_ACTION = "pre_action"       # Before proxy/translate/delegate
    POST_ACTION = "post_action"     # After action completes
    PASSPORT_CREATED = "passport_created"
    PASSPORT_REVOKED = "passport_revoked"
    PASSPORT_RENEWED = "passport_renewed"
    DELEGATION = "delegation"
    RATE_LIMITED = "rate_limited"
    FEDERATION_REQUEST = "federation_request"
    ERROR = "error"


class WebhookDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    MODIFY = "modify"             # Allow but with modified parameters


# ═══════════════════════════════════════════════════════════════════
# WEBHOOK PAYLOAD
# ═══════════════════════════════════════════════════════════════════

@dataclass
class WebhookPayload:
    """Payload sent to the external system on each webhook event."""
    event_id: str
    event: str                      # WebhookEvent value
    timestamp: str
    passport_id: str
    issuer: str = ""
    capabilities: list = field(default_factory=list)
    action: str = ""                # proxy, translate, delegate, etc.
    protocol: str = ""
    target_url: str = ""
    method: str = "POST"
    body_hash: str = ""             # SHA-256 of body (privacy: no raw body)
    tier: str = ""
    trace_id: str = ""
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "event": self.event,
            "timestamp": self.timestamp,
            "passport_id": self.passport_id,
            "issuer": self.issuer,
            "capabilities": self.capabilities,
            "action": self.action,
            "protocol": self.protocol,
            "target_url": self.target_url,
            "method": self.method,
            "body_hash": self.body_hash,
            "tier": self.tier,
            "trace_id": self.trace_id,
            "metadata": self.metadata,
        }


@dataclass
class WebhookResponse:
    """Response from the external system."""
    decision: str = "allow"          # allow, deny, modify
    reason: str = ""
    modifications: dict = field(default_factory=dict)  # For "modify" decisions
    metadata: dict = field(default_factory=dict)        # Extra data from webhook
    latency_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "modifications": self.modifications,
            "metadata": self.metadata,
            "latency_ms": self.latency_ms,
        }


@dataclass
class PostActionPayload(WebhookPayload):
    """Extended payload for post-action webhooks (includes result)."""
    status_code: int = 0
    success: bool = True
    latency_ms: float = 0.0
    receipt_id: str = ""
    error_code: str = ""

    def to_dict(self) -> dict:
        d = super().to_dict()
        d["status_code"] = self.status_code
        d["success"] = self.success
        d["latency_ms"] = self.latency_ms
        d["receipt_id"] = self.receipt_id
        d["error_code"] = self.error_code
        return d


# ═══════════════════════════════════════════════════════════════════
# WEBHOOK REGISTRATION
# ═══════════════════════════════════════════════════════════════════

@dataclass
class WebhookRegistration:
    """A registered webhook endpoint."""
    webhook_id: str
    url: str
    events: list                    # Which events trigger this webhook
    secret: str = ""                # HMAC secret for signature verification
    active: bool = True
    timeout_ms: int = 5000          # Max wait for response
    retry_count: int = 0
    max_retries: int = 2
    created_at: str = ""
    description: str = ""
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "webhook_id": self.webhook_id,
            "url": self.url,
            "events": self.events,
            "active": self.active,
            "timeout_ms": self.timeout_ms,
            "max_retries": self.max_retries,
            "created_at": self.created_at,
            "description": self.description,
        }


# ═══════════════════════════════════════════════════════════════════
# WEBHOOK MANAGER
# ═══════════════════════════════════════════════════════════════════

class WebhookDeniedError(Exception):
    """Raised when a pre-action webhook denies the request."""
    def __init__(self, reason: str, webhook_id: str = ""):
        self.reason = reason
        self.webhook_id = webhook_id
        super().__init__(f"Webhook denied: {reason}")


class WebhookManager:
    """
    Manages webhook registrations and dispatching.

    Usage:
        wm = WebhookManager()

        # Register a guardrail webhook (APort, Galileo, custom)
        wm.register(
            url="https://guardrails.mycompany.com/aib/pre-action",
            events=["pre_action"],
            secret="hmac-shared-secret",
            description="APort policy check",
        )

        # Register a monitoring webhook (Datadog, SIEM)
        wm.register(
            url="https://siem.mycompany.com/aib/events",
            events=["post_action", "error", "rate_limited"],
            description="SIEM audit feed",
        )

        # In the gateway, before proxying:
        response = wm.dispatch_pre_action(
            passport_id="urn:aib:agent:acme:bot",
            action="proxy",
            target_url="https://partner.com/a2a",
            capabilities=["booking"],
        )
        if response.decision == "deny":
            return error_403(response.reason)

        # After the action:
        wm.dispatch_post_action(
            passport_id="urn:aib:agent:acme:bot",
            action="proxy",
            status_code=200,
            success=True,
            latency_ms=45.2,
        )
    """

    def __init__(self, http_sender: Optional[Callable] = None):
        self._webhooks: dict[str, WebhookRegistration] = {}
        self._lock = threading.Lock()
        self._history: list[dict] = []
        self._max_history = 1000
        self._http_sender = http_sender or self._default_sender

    # ── Registration ──────────────────────────────────────────────

    def register(
        self,
        url: str,
        events: list[str],
        secret: str = "",
        timeout_ms: int = 5000,
        max_retries: int = 2,
        description: str = "",
        metadata: Optional[dict] = None,
    ) -> WebhookRegistration:
        webhook = WebhookRegistration(
            webhook_id=f"wh_{uuid.uuid4().hex[:12]}",
            url=url,
            events=events,
            secret=secret,
            timeout_ms=timeout_ms,
            max_retries=max_retries,
            created_at=datetime.now(timezone.utc).isoformat(),
            description=description,
            metadata=metadata or {},
        )
        with self._lock:
            self._webhooks[webhook.webhook_id] = webhook
        return webhook

    def unregister(self, webhook_id: str) -> bool:
        with self._lock:
            if webhook_id in self._webhooks:
                del self._webhooks[webhook_id]
                return True
            return False

    def enable(self, webhook_id: str) -> bool:
        with self._lock:
            wh = self._webhooks.get(webhook_id)
            if wh:
                wh.active = True
                return True
            return False

    def disable(self, webhook_id: str) -> bool:
        with self._lock:
            wh = self._webhooks.get(webhook_id)
            if wh:
                wh.active = False
                return True
            return False

    def list_webhooks(self) -> list[dict]:
        with self._lock:
            return [wh.to_dict() for wh in self._webhooks.values()]

    def get_webhook(self, webhook_id: str) -> Optional[dict]:
        with self._lock:
            wh = self._webhooks.get(webhook_id)
            return wh.to_dict() if wh else None

    # ── Dispatching ───────────────────────────────────────────────

    def _get_webhooks_for_event(self, event: str) -> list[WebhookRegistration]:
        with self._lock:
            return [
                wh for wh in self._webhooks.values()
                if wh.active and event in wh.events
            ]

    def _build_payload(
        self,
        event: str,
        passport_id: str,
        action: str = "",
        protocol: str = "",
        target_url: str = "",
        method: str = "POST",
        body: Any = None,
        capabilities: Optional[list] = None,
        issuer: str = "",
        tier: str = "",
        trace_id: str = "",
        metadata: Optional[dict] = None,
    ) -> WebhookPayload:
        body_hash = ""
        if body:
            body_hash = hashlib.sha256(
                json.dumps(body, sort_keys=True, default=str).encode()
            ).hexdigest()

        return WebhookPayload(
            event_id=f"evt_{uuid.uuid4().hex[:12]}",
            event=event,
            timestamp=datetime.now(timezone.utc).isoformat(),
            passport_id=passport_id,
            issuer=issuer,
            capabilities=capabilities or [],
            action=action,
            protocol=protocol,
            target_url=target_url,
            method=method,
            body_hash=body_hash,
            tier=tier,
            trace_id=trace_id or f"aib_{uuid.uuid4().hex[:16]}",
            metadata=metadata or {},
        )

    def _sign_payload(self, payload_dict: dict, secret: str) -> str:
        """HMAC-SHA256 signature for webhook payload verification."""
        if not secret:
            return ""
        canonical = json.dumps(payload_dict, sort_keys=True, separators=(",", ":"))
        import hmac as hmac_mod
        return hmac_mod.new(
            secret.encode("utf-8"),
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _default_sender(self, url: str, payload: dict, headers: dict, timeout_ms: int) -> dict:
        """
        Default HTTP sender (no-op for testing).
        In production, replace with httpx/aiohttp POST.
        Returns a simulated "allow" response.
        """
        return {"decision": "allow", "reason": "default (no external system)"}

    def _dispatch_to_webhook(
        self, wh: WebhookRegistration, payload: WebhookPayload,
    ) -> WebhookResponse:
        payload_dict = payload.to_dict()
        signature = self._sign_payload(payload_dict, wh.secret)

        headers = {
            "Content-Type": "application/json",
            "X-AIB-Event": payload.event,
            "X-AIB-Signature": signature,
            "X-AIB-Webhook-ID": wh.webhook_id,
            "X-AIB-Timestamp": payload.timestamp,
        }

        start = time.time()
        try:
            response_data = self._http_sender(
                wh.url, payload_dict, headers, wh.timeout_ms,
            )
            latency = (time.time() - start) * 1000

            return WebhookResponse(
                decision=response_data.get("decision", "allow"),
                reason=response_data.get("reason", ""),
                modifications=response_data.get("modifications", {}),
                metadata=response_data.get("metadata", {}),
                latency_ms=round(latency, 2),
            )
        except Exception as e:
            latency = (time.time() - start) * 1000
            # Webhook failure = allow (fail-open for availability)
            return WebhookResponse(
                decision="allow",
                reason=f"Webhook error (fail-open): {str(e)}",
                latency_ms=round(latency, 2),
            )

    def _record_history(self, event: str, webhook_id: str, decision: str, latency_ms: float):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "webhook_id": webhook_id,
            "decision": decision,
            "latency_ms": latency_ms,
        }
        with self._lock:
            self._history.append(entry)
            if len(self._history) > self._max_history:
                self._history = self._history[-self._max_history:]

    # ── Public dispatch methods ───────────────────────────────────

    def dispatch_pre_action(
        self,
        passport_id: str,
        action: str = "proxy",
        protocol: str = "",
        target_url: str = "",
        method: str = "POST",
        body: Any = None,
        capabilities: Optional[list] = None,
        issuer: str = "",
        tier: str = "",
        trace_id: str = "",
        metadata: Optional[dict] = None,
    ) -> WebhookResponse:
        """
        Dispatch pre-action webhook. Blocks if any webhook denies.

        Returns the combined response. If multiple webhooks are registered,
        ALL must allow. One deny = request blocked.
        """
        webhooks = self._get_webhooks_for_event(WebhookEvent.PRE_ACTION)
        if not webhooks:
            return WebhookResponse(decision="allow", reason="No pre-action webhooks registered")

        payload = self._build_payload(
            event=WebhookEvent.PRE_ACTION,
            passport_id=passport_id,
            action=action,
            protocol=protocol,
            target_url=target_url,
            method=method,
            body=body,
            capabilities=capabilities,
            issuer=issuer,
            tier=tier,
            trace_id=trace_id,
            metadata=metadata,
        )

        combined_modifications = {}
        total_latency = 0.0
        fail_open = False
        fail_open_reason = ""

        for wh in webhooks:
            response = self._dispatch_to_webhook(wh, payload)
            total_latency += response.latency_ms
            self._record_history(
                WebhookEvent.PRE_ACTION, wh.webhook_id,
                response.decision, response.latency_ms,
            )

            if response.decision == WebhookDecision.DENY:
                return WebhookResponse(
                    decision="deny",
                    reason=response.reason,
                    latency_ms=total_latency,
                    metadata={"denied_by": wh.webhook_id},
                )

            if response.decision == WebhookDecision.MODIFY:
                combined_modifications.update(response.modifications)

            if "fail-open" in response.reason.lower():
                fail_open = True
                fail_open_reason = response.reason

        if combined_modifications:
            return WebhookResponse(
                decision="modify",
                reason="Modified by webhook(s)",
                modifications=combined_modifications,
                latency_ms=total_latency,
            )

        reason = fail_open_reason if fail_open else f"Allowed by {len(webhooks)} webhook(s)"
        return WebhookResponse(
            decision="allow",
            reason=reason,
            latency_ms=total_latency,
        )

    def dispatch_post_action(
        self,
        passport_id: str,
        action: str = "proxy",
        protocol: str = "",
        target_url: str = "",
        status_code: int = 200,
        success: bool = True,
        latency_ms: float = 0.0,
        receipt_id: str = "",
        error_code: str = "",
        trace_id: str = "",
        metadata: Optional[dict] = None,
    ):
        """
        Dispatch post-action webhook. Fire-and-forget (non-blocking).

        Post-action webhooks never block the response to the caller.
        They are for audit, billing, monitoring, and SIEM feeds.
        """
        webhooks = self._get_webhooks_for_event(WebhookEvent.POST_ACTION)
        if not webhooks:
            return

        payload = PostActionPayload(
            event_id=f"evt_{uuid.uuid4().hex[:12]}",
            event=WebhookEvent.POST_ACTION,
            timestamp=datetime.now(timezone.utc).isoformat(),
            passport_id=passport_id,
            action=action,
            protocol=protocol,
            target_url=target_url,
            trace_id=trace_id,
            status_code=status_code,
            success=success,
            latency_ms=latency_ms,
            receipt_id=receipt_id,
            error_code=error_code,
            metadata=metadata or {},
        )

        for wh in webhooks:
            response = self._dispatch_to_webhook(wh, payload)
            self._record_history(
                WebhookEvent.POST_ACTION, wh.webhook_id,
                "delivered", response.latency_ms,
            )

    def dispatch_event(
        self,
        event: str,
        passport_id: str,
        metadata: Optional[dict] = None,
    ):
        """
        Dispatch a lifecycle event (passport_created, revoked, etc.).
        Fire-and-forget.
        """
        webhooks = self._get_webhooks_for_event(event)
        if not webhooks:
            return

        payload = self._build_payload(
            event=event,
            passport_id=passport_id,
            metadata=metadata,
        )

        for wh in webhooks:
            response = self._dispatch_to_webhook(wh, payload)
            self._record_history(event, wh.webhook_id, "delivered", response.latency_ms)

    # ── Stats ─────────────────────────────────────────────────────

    def get_history(self, limit: int = 50) -> list[dict]:
        with self._lock:
            return list(reversed(self._history[-limit:]))

    def get_stats(self) -> dict:
        with self._lock:
            total = len(self._history)
            by_event = {}
            by_decision = {}
            total_latency = 0.0
            for entry in self._history:
                ev = entry["event"]
                by_event[ev] = by_event.get(ev, 0) + 1
                dec = entry["decision"]
                by_decision[dec] = by_decision.get(dec, 0) + 1
                total_latency += entry.get("latency_ms", 0)

            return {
                "total_dispatched": total,
                "by_event": by_event,
                "by_decision": by_decision,
                "avg_latency_ms": round(total_latency / max(total, 1), 2),
                "registered_webhooks": len(self._webhooks),
                "active_webhooks": sum(1 for w in self._webhooks.values() if w.active),
            }

    @property
    def webhook_count(self) -> int:
        with self._lock:
            return len(self._webhooks)
