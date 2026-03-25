"""Tests for Sprint 9 — Webhook pre/post action system."""

import json
import time
import threading
import pytest
from aib.webhooks import (
    WebhookManager, WebhookEvent, WebhookDecision,
    WebhookPayload, WebhookResponse, PostActionPayload,
    WebhookRegistration, WebhookDeniedError,
)


# ═══════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════

def make_allow_sender():
    """Sender that always allows."""
    log = []
    def sender(url, payload, headers, timeout_ms):
        log.append({"url": url, "payload": payload, "headers": headers})
        return {"decision": "allow", "reason": "Policy passed"}
    return sender, log


def make_deny_sender(reason="Blocked by policy"):
    """Sender that always denies."""
    def sender(url, payload, headers, timeout_ms):
        return {"decision": "deny", "reason": reason}
    return sender


def make_modify_sender(modifications):
    """Sender that modifies the request."""
    def sender(url, payload, headers, timeout_ms):
        return {"decision": "modify", "reason": "Modified", "modifications": modifications}
    return sender


def make_error_sender():
    """Sender that crashes (simulates webhook down)."""
    def sender(url, payload, headers, timeout_ms):
        raise ConnectionError("Webhook unreachable")
    return sender


# ═══════════════════════════════════════════════════════════════════
# REGISTRATION
# ═══════════════════════════════════════════════════════════════════

class TestRegistration:

    def test_register(self):
        wm = WebhookManager()
        wh = wm.register(
            url="https://guardrails.test/pre",
            events=["pre_action"],
            description="Test guardrail",
        )
        assert wh.webhook_id.startswith("wh_")
        assert wh.url == "https://guardrails.test/pre"
        assert wh.active is True

    def test_list_webhooks(self):
        wm = WebhookManager()
        wm.register(url="https://a.test", events=["pre_action"])
        wm.register(url="https://b.test", events=["post_action"])
        hooks = wm.list_webhooks()
        assert len(hooks) == 2

    def test_unregister(self):
        wm = WebhookManager()
        wh = wm.register(url="https://a.test", events=["pre_action"])
        assert wm.unregister(wh.webhook_id) is True
        assert wm.webhook_count == 0

    def test_unregister_nonexistent(self):
        wm = WebhookManager()
        assert wm.unregister("wh_nonexistent") is False

    def test_disable_enable(self):
        wm = WebhookManager()
        wh = wm.register(url="https://a.test", events=["pre_action"])
        assert wm.disable(wh.webhook_id) is True
        info = wm.get_webhook(wh.webhook_id)
        assert info["active"] is False

        assert wm.enable(wh.webhook_id) is True
        info = wm.get_webhook(wh.webhook_id)
        assert info["active"] is True

    def test_get_webhook(self):
        wm = WebhookManager()
        wh = wm.register(url="https://a.test", events=["pre_action"], description="My hook")
        info = wm.get_webhook(wh.webhook_id)
        assert info["description"] == "My hook"

    def test_get_nonexistent(self):
        wm = WebhookManager()
        assert wm.get_webhook("wh_nope") is None


# ═══════════════════════════════════════════════════════════════════
# PRE-ACTION DISPATCH
# ═══════════════════════════════════════════════════════════════════

class TestPreAction:

    def test_no_webhooks_allows(self):
        wm = WebhookManager()
        resp = wm.dispatch_pre_action(passport_id="p1", action="proxy")
        assert resp.decision == "allow"

    def test_allow(self):
        sender, log = make_allow_sender()
        wm = WebhookManager(http_sender=sender)
        wm.register(url="https://guard.test", events=["pre_action"])

        resp = wm.dispatch_pre_action(
            passport_id="urn:aib:agent:acme:bot",
            action="proxy",
            target_url="https://partner.com/a2a",
            capabilities=["booking"],
        )
        assert resp.decision == "allow"
        assert len(log) == 1
        assert log[0]["payload"]["passport_id"] == "urn:aib:agent:acme:bot"

    def test_deny(self):
        sender = make_deny_sender("Agent lacks payment capability")
        wm = WebhookManager(http_sender=sender)
        wm.register(url="https://guard.test", events=["pre_action"])

        resp = wm.dispatch_pre_action(passport_id="p1", action="proxy")
        assert resp.decision == "deny"
        assert "payment" in resp.reason

    def test_modify(self):
        sender = make_modify_sender({"max_amount": 100, "currency": "EUR"})
        wm = WebhookManager(http_sender=sender)
        wm.register(url="https://guard.test", events=["pre_action"])

        resp = wm.dispatch_pre_action(passport_id="p1", action="proxy")
        assert resp.decision == "modify"
        assert resp.modifications["max_amount"] == 100

    def test_multiple_webhooks_all_must_allow(self):
        sender, _ = make_allow_sender()
        wm = WebhookManager(http_sender=sender)
        wm.register(url="https://guard1.test", events=["pre_action"])
        wm.register(url="https://guard2.test", events=["pre_action"])
        wm.register(url="https://guard3.test", events=["pre_action"])

        resp = wm.dispatch_pre_action(passport_id="p1")
        assert resp.decision == "allow"
        assert "3 webhook" in resp.reason

    def test_one_deny_blocks_all(self):
        call_count = {"n": 0}

        def mixed_sender(url, payload, headers, timeout_ms):
            call_count["n"] += 1
            if "deny" in url:
                return {"decision": "deny", "reason": "Nope"}
            return {"decision": "allow"}

        wm = WebhookManager(http_sender=mixed_sender)
        wm.register(url="https://allow.test", events=["pre_action"])
        wm.register(url="https://deny.test", events=["pre_action"])

        resp = wm.dispatch_pre_action(passport_id="p1")
        assert resp.decision == "deny"

    def test_fail_open_on_webhook_error(self):
        sender = make_error_sender()
        wm = WebhookManager(http_sender=sender)
        wm.register(url="https://broken.test", events=["pre_action"])

        resp = wm.dispatch_pre_action(passport_id="p1")
        assert resp.decision == "allow"
        assert "fail-open" in resp.reason.lower()

    def test_disabled_webhook_skipped(self):
        sender = make_deny_sender("Should not fire")
        wm = WebhookManager(http_sender=sender)
        wh = wm.register(url="https://guard.test", events=["pre_action"])
        wm.disable(wh.webhook_id)

        resp = wm.dispatch_pre_action(passport_id="p1")
        assert resp.decision == "allow"  # No active webhooks

    def test_body_hash_not_raw_body(self):
        sender, log = make_allow_sender()
        wm = WebhookManager(http_sender=sender)
        wm.register(url="https://guard.test", events=["pre_action"])

        wm.dispatch_pre_action(
            passport_id="p1",
            body={"secret": "credit-card-number", "amount": 500},
        )
        payload = log[0]["payload"]
        assert "credit-card" not in json.dumps(payload)
        assert len(payload["body_hash"]) == 64  # SHA-256 hex

    def test_payload_has_signature_header(self):
        sender, log = make_allow_sender()
        wm = WebhookManager(http_sender=sender)
        wm.register(
            url="https://guard.test", events=["pre_action"],
            secret="my-shared-secret",
        )

        wm.dispatch_pre_action(passport_id="p1")
        headers = log[0]["headers"]
        assert "X-AIB-Signature" in headers
        assert len(headers["X-AIB-Signature"]) == 64  # HMAC-SHA256 hex
        assert headers["X-AIB-Event"] == "pre_action"
        assert "X-AIB-Webhook-ID" in headers


# ═══════════════════════════════════════════════════════════════════
# POST-ACTION DISPATCH
# ═══════════════════════════════════════════════════════════════════

class TestPostAction:

    def test_post_action_fires(self):
        sender, log = make_allow_sender()
        wm = WebhookManager(http_sender=sender)
        wm.register(url="https://siem.test", events=["post_action"])

        wm.dispatch_post_action(
            passport_id="p1",
            action="proxy",
            status_code=200,
            success=True,
            latency_ms=42.5,
            receipt_id="rcpt_abc123",
        )
        assert len(log) == 1
        payload = log[0]["payload"]
        assert payload["status_code"] == 200
        assert payload["latency_ms"] == 42.5
        assert payload["receipt_id"] == "rcpt_abc123"

    def test_post_action_no_webhooks(self):
        wm = WebhookManager()
        # Should not crash
        wm.dispatch_post_action(passport_id="p1", status_code=200)

    def test_post_action_error(self):
        sender, log = make_allow_sender()
        wm = WebhookManager(http_sender=sender)
        wm.register(url="https://siem.test", events=["post_action"])

        wm.dispatch_post_action(
            passport_id="p1",
            action="proxy",
            status_code=502,
            success=False,
            error_code="AIB-305",
        )
        payload = log[0]["payload"]
        assert payload["success"] is False
        assert payload["error_code"] == "AIB-305"


# ═══════════════════════════════════════════════════════════════════
# LIFECYCLE EVENTS
# ═══════════════════════════════════════════════════════════════════

class TestLifecycleEvents:

    def test_passport_created(self):
        sender, log = make_allow_sender()
        wm = WebhookManager(http_sender=sender)
        wm.register(url="https://monitor.test", events=["passport_created"])

        wm.dispatch_event("passport_created", "urn:aib:agent:acme:new",
                          metadata={"tier": "permanent", "capabilities": ["booking"]})
        assert len(log) == 1
        assert log[0]["payload"]["event"] == "passport_created"

    def test_passport_revoked(self):
        sender, log = make_allow_sender()
        wm = WebhookManager(http_sender=sender)
        wm.register(url="https://monitor.test", events=["passport_revoked"])

        wm.dispatch_event("passport_revoked", "urn:aib:agent:acme:old",
                          metadata={"reason": "Key compromised"})
        assert len(log) == 1

    def test_event_routing(self):
        sender, log = make_allow_sender()
        wm = WebhookManager(http_sender=sender)
        wm.register(url="https://guard.test", events=["pre_action"])
        wm.register(url="https://siem.test", events=["post_action", "error"])

        # Pre-action → only guard.test
        wm.dispatch_pre_action(passport_id="p1")
        assert len(log) == 1
        assert log[0]["url"] == "https://guard.test"

        # Post-action → only siem.test
        wm.dispatch_post_action(passport_id="p1", status_code=200)
        assert len(log) == 2
        assert log[1]["url"] == "https://siem.test"


# ═══════════════════════════════════════════════════════════════════
# STATS & HISTORY
# ═══════════════════════════════════════════════════════════════════

class TestStatsHistory:

    def test_history_recorded(self):
        sender, _ = make_allow_sender()
        wm = WebhookManager(http_sender=sender)
        wm.register(url="https://guard.test", events=["pre_action"])

        wm.dispatch_pre_action(passport_id="p1")
        wm.dispatch_pre_action(passport_id="p2")

        history = wm.get_history(limit=10)
        assert len(history) == 2
        assert history[0]["event"] == "pre_action"

    def test_stats(self):
        sender, _ = make_allow_sender()
        wm = WebhookManager(http_sender=sender)
        wm.register(url="https://guard.test", events=["pre_action", "post_action"])

        wm.dispatch_pre_action(passport_id="p1")
        wm.dispatch_post_action(passport_id="p1", status_code=200)

        stats = wm.get_stats()
        assert stats["total_dispatched"] == 2
        assert stats["registered_webhooks"] == 1
        assert stats["active_webhooks"] == 1
        assert stats["by_event"]["pre_action"] == 1
        assert stats["by_event"]["post_action"] == 1

    def test_deny_recorded_in_stats(self):
        sender = make_deny_sender("Nope")
        wm = WebhookManager(http_sender=sender)
        wm.register(url="https://guard.test", events=["pre_action"])

        wm.dispatch_pre_action(passport_id="p1")
        stats = wm.get_stats()
        assert stats["by_decision"]["deny"] == 1


# ═══════════════════════════════════════════════════════════════════
# END-TO-END SCENARIO
# ═══════════════════════════════════════════════════════════════════

class TestEndToEnd:

    def test_full_lifecycle(self):
        """Simulate: register hooks → pre-action → proxy → post-action."""
        pre_log = []
        post_log = []

        def smart_sender(url, payload, headers, timeout_ms):
            if "pre" in url:
                pre_log.append(payload)
                caps = payload.get("capabilities", [])
                if "admin" in caps:
                    return {"decision": "deny", "reason": "Admin not allowed via webhook"}
                return {"decision": "allow"}
            else:
                post_log.append(payload)
                return {"decision": "allow"}

        wm = WebhookManager(http_sender=smart_sender)
        wm.register(url="https://pre.guard.test", events=["pre_action"])
        wm.register(url="https://post.siem.test", events=["post_action"])

        # Allowed request
        resp = wm.dispatch_pre_action(
            passport_id="urn:aib:agent:acme:bot",
            action="proxy",
            target_url="https://partner.com/a2a",
            capabilities=["booking"],
        )
        assert resp.decision == "allow"

        wm.dispatch_post_action(
            passport_id="urn:aib:agent:acme:bot",
            action="proxy",
            status_code=200,
            success=True,
            latency_ms=35.0,
        )

        # Denied request (admin capability)
        resp2 = wm.dispatch_pre_action(
            passport_id="urn:aib:agent:acme:admin",
            capabilities=["admin"],
        )
        assert resp2.decision == "deny"
        assert "admin" in resp2.reason.lower()

        # Verify logs
        assert len(pre_log) == 2
        assert len(post_log) == 1
        assert post_log[0]["status_code"] == 200

        # Stats
        stats = wm.get_stats()
        assert stats["total_dispatched"] == 3
        assert stats["by_decision"].get("allow", 0) + stats["by_decision"].get("delivered", 0) == 2
        assert stats["by_decision"]["deny"] == 1
