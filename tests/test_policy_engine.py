"""Tests for Sprint 14 — Policy Engine + Deliverable Contracts."""

import pytest
from aib.policy_engine import (
    PolicyEngine, PolicyRule, PolicyContext, PolicyDecision, RuleType,
    ContractManager, DeliverableContract, Criterion, CriterionStatus,
)


# ═══════════════════════════════════════════════════════════════════
# 1. POLICY ENGINE — CAPABILITY RULES
# ═══════════════════════════════════════════════════════════════════

class TestCapabilityRules:

    @pytest.fixture
    def engine(self):
        e = PolicyEngine()
        e.add_rule(PolicyRule(
            rule_id="need-payment",
            rule_type=RuleType.CAPABILITY_REQUIRED,
            capability="payment",
            action="proxy",
            description="Payment capability required for proxy",
        ))
        return e

    def test_has_capability(self, engine):
        ctx = PolicyContext(passport_id="p1", capabilities=["payment", "booking"],
                           tier="permanent", issuer="org", action="proxy")
        d = engine.evaluate(ctx)
        assert d.allowed is True

    def test_missing_capability(self, engine):
        ctx = PolicyContext(passport_id="p1", capabilities=["booking"],
                           tier="permanent", issuer="org", action="proxy")
        d = engine.evaluate(ctx)
        assert d.allowed is False
        assert "payment" in d.reason

    def test_rule_doesnt_apply_wrong_action(self, engine):
        ctx = PolicyContext(passport_id="p1", capabilities=["booking"],
                           tier="permanent", issuer="org", action="translate")
        d = engine.evaluate(ctx)
        assert d.allowed is True  # Rule only applies to "proxy"


class TestCapabilityLimits:

    @pytest.fixture
    def engine(self):
        e = PolicyEngine()
        e.add_rule(PolicyRule(
            rule_id="payment-cap",
            rule_type=RuleType.CAPABILITY_LIMIT,
            capability="payment",
            max_amount=500,
            currency="EUR",
        ))
        return e

    def test_within_limit(self, engine):
        ctx = PolicyContext(passport_id="p1", capabilities=["payment"],
                           tier="permanent", issuer="org", action="proxy",
                           amount=200, currency="EUR")
        assert engine.evaluate(ctx).allowed is True

    def test_exceeds_limit(self, engine):
        ctx = PolicyContext(passport_id="p1", capabilities=["payment"],
                           tier="permanent", issuer="org", action="proxy",
                           amount=1000, currency="EUR")
        d = engine.evaluate(ctx)
        assert d.allowed is False
        assert "1000" in d.reason and "500" in d.reason

    def test_no_payment_capability_skips(self, engine):
        ctx = PolicyContext(passport_id="p1", capabilities=["booking"],
                           tier="permanent", issuer="org", action="proxy",
                           amount=1000)
        assert engine.evaluate(ctx).allowed is True  # Rule doesn't apply


# ═══════════════════════════════════════════════════════════════════
# 2. DOMAIN & PROTOCOL RULES
# ═══════════════════════════════════════════════════════════════════

class TestDomainRules:

    def test_blocked_domain(self):
        engine = PolicyEngine()
        engine.add_rule(PolicyRule(
            rule_id="block-evil",
            rule_type=RuleType.DOMAIN_BLOCK,
            blocked_domains=["evil.com", "malware.org"],
        ))
        ctx = PolicyContext(passport_id="p1", capabilities=["booking"],
                           tier="permanent", issuer="org", action="proxy",
                           target_url="https://evil.com/api")
        assert engine.evaluate(ctx).allowed is False

    def test_allowed_domain(self):
        engine = PolicyEngine()
        engine.add_rule(PolicyRule(
            rule_id="block-evil",
            rule_type=RuleType.DOMAIN_BLOCK,
            blocked_domains=["evil.com"],
        ))
        ctx = PolicyContext(passport_id="p1", capabilities=["booking"],
                           tier="permanent", issuer="org", action="proxy",
                           target_url="https://good.com/api")
        assert engine.evaluate(ctx).allowed is True

    def test_subdomain_blocked(self):
        engine = PolicyEngine()
        engine.add_rule(PolicyRule(
            rule_id="block-evil",
            rule_type=RuleType.DOMAIN_BLOCK,
            blocked_domains=["evil.com"],
        ))
        ctx = PolicyContext(passport_id="p1", capabilities=[], tier="permanent",
                           issuer="org", action="proxy",
                           target_url="https://api.evil.com/data")
        assert engine.evaluate(ctx).allowed is False

    def test_domain_allowlist(self):
        engine = PolicyEngine()
        engine.add_rule(PolicyRule(
            rule_id="only-partner",
            rule_type=RuleType.DOMAIN_ALLOW,
            allowed_domains=["partner.com", "trusted.io"],
        ))
        ctx = PolicyContext(passport_id="p1", capabilities=[], tier="permanent",
                           issuer="org", action="proxy",
                           target_url="https://unknown.com/api")
        assert engine.evaluate(ctx).allowed is False

    def test_domain_in_allowlist(self):
        engine = PolicyEngine()
        engine.add_rule(PolicyRule(
            rule_id="only-partner",
            rule_type=RuleType.DOMAIN_ALLOW,
            allowed_domains=["partner.com"],
        ))
        ctx = PolicyContext(passport_id="p1", capabilities=[], tier="permanent",
                           issuer="org", action="proxy",
                           target_url="https://partner.com/a2a")
        assert engine.evaluate(ctx).allowed is True


class TestProtocolRules:

    def test_protocol_allowed(self):
        engine = PolicyEngine()
        engine.add_rule(PolicyRule(
            rule_id="mcp-a2a-only",
            rule_type=RuleType.PROTOCOL_RESTRICT,
            allowed_protocols=["mcp", "a2a"],
        ))
        ctx = PolicyContext(passport_id="p1", capabilities=[], tier="permanent",
                           issuer="org", action="proxy", protocol="a2a")
        assert engine.evaluate(ctx).allowed is True

    def test_protocol_blocked(self):
        engine = PolicyEngine()
        engine.add_rule(PolicyRule(
            rule_id="mcp-a2a-only",
            rule_type=RuleType.PROTOCOL_RESTRICT,
            allowed_protocols=["mcp", "a2a"],
        ))
        ctx = PolicyContext(passport_id="p1", capabilities=[], tier="permanent",
                           issuer="org", action="proxy", protocol="anp")
        d = engine.evaluate(ctx)
        assert d.allowed is False
        assert "anp" in d.reason


# ═══════════════════════════════════════════════════════════════════
# 3. TIER & ACTION RULES
# ═══════════════════════════════════════════════════════════════════

class TestTierRules:

    def test_ephemeral_no_delegate(self):
        engine = PolicyEngine()
        engine.add_rule(PolicyRule(
            rule_id="eph-restrict",
            rule_type=RuleType.TIER_RESTRICT,
            tier="ephemeral",
            blocked_actions=["delegate", "revoke"],
        ))
        ctx = PolicyContext(passport_id="p1", capabilities=[], tier="ephemeral",
                           issuer="org", action="delegate")
        assert engine.evaluate(ctx).allowed is False

    def test_permanent_can_delegate(self):
        engine = PolicyEngine()
        engine.add_rule(PolicyRule(
            rule_id="eph-restrict",
            rule_type=RuleType.TIER_RESTRICT,
            tier="ephemeral",
            blocked_actions=["delegate"],
        ))
        ctx = PolicyContext(passport_id="p1", capabilities=[], tier="permanent",
                           issuer="org", action="delegate")
        assert engine.evaluate(ctx).allowed is True  # Rule doesn't apply

    def test_action_block(self):
        engine = PolicyEngine()
        engine.add_rule(PolicyRule(
            rule_id="no-delete",
            rule_type=RuleType.ACTION_BLOCK,
            blocked_actions=["delete", "purge"],
        ))
        ctx = PolicyContext(passport_id="p1", capabilities=[], tier="permanent",
                           issuer="org", action="delete")
        assert engine.evaluate(ctx).allowed is False


# ═══════════════════════════════════════════════════════════════════
# 4. MULTIPLE RULES
# ═══════════════════════════════════════════════════════════════════

class TestMultipleRules:

    def test_all_pass(self):
        engine = PolicyEngine()
        engine.add_rule(PolicyRule(rule_id="r1", rule_type=RuleType.CAPABILITY_REQUIRED,
                                   capability="booking"))
        engine.add_rule(PolicyRule(rule_id="r2", rule_type=RuleType.DOMAIN_BLOCK,
                                   blocked_domains=["evil.com"]))
        ctx = PolicyContext(passport_id="p1", capabilities=["booking"],
                           tier="permanent", issuer="org", action="proxy",
                           target_url="https://good.com")
        assert engine.evaluate(ctx).allowed is True

    def test_one_blocks(self):
        engine = PolicyEngine()
        engine.add_rule(PolicyRule(rule_id="r1", rule_type=RuleType.CAPABILITY_REQUIRED,
                                   capability="booking"))
        engine.add_rule(PolicyRule(rule_id="r2", rule_type=RuleType.DOMAIN_BLOCK,
                                   blocked_domains=["evil.com"]))
        ctx = PolicyContext(passport_id="p1", capabilities=["booking"],
                           tier="permanent", issuer="org", action="proxy",
                           target_url="https://evil.com")
        d = engine.evaluate(ctx)
        assert d.allowed is False
        assert "r2" in d.matched_rules

    def test_warning_severity(self):
        engine = PolicyEngine()
        engine.add_rule(PolicyRule(rule_id="warn-rule", rule_type=RuleType.DOMAIN_BLOCK,
                                   blocked_domains=["risky.com"], severity="warn"))
        ctx = PolicyContext(passport_id="p1", capabilities=[], tier="permanent",
                           issuer="org", action="proxy",
                           target_url="https://risky.com")
        d = engine.evaluate(ctx)
        assert d.allowed is True  # Warn doesn't block
        assert len(d.warnings) == 1

    def test_inactive_rule_skipped(self):
        engine = PolicyEngine()
        engine.add_rule(PolicyRule(rule_id="r1", rule_type=RuleType.ACTION_BLOCK,
                                   blocked_actions=["proxy"], active=False))
        ctx = PolicyContext(passport_id="p1", capabilities=[], tier="permanent",
                           issuer="org", action="proxy")
        assert engine.evaluate(ctx).allowed is True

    def test_evaluation_speed(self):
        engine = PolicyEngine()
        for i in range(100):
            engine.add_rule(PolicyRule(rule_id=f"r{i}", rule_type=RuleType.DOMAIN_BLOCK,
                                       blocked_domains=[f"evil{i}.com"]))
        ctx = PolicyContext(passport_id="p1", capabilities=[], tier="permanent",
                           issuer="org", action="proxy",
                           target_url="https://good.com")
        d = engine.evaluate(ctx)
        assert d.allowed is True
        assert d.evaluation_ms < 10  # 100 rules in <10ms


# ═══════════════════════════════════════════════════════════════════
# 5. ENGINE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════

class TestEngineManagement:

    def test_remove_rule(self):
        engine = PolicyEngine()
        engine.add_rule(PolicyRule(rule_id="r1", rule_type=RuleType.ACTION_BLOCK,
                                   blocked_actions=["proxy"]))
        assert engine.remove_rule("r1") is True
        assert engine.rule_count == 0

    def test_get_rules(self):
        engine = PolicyEngine()
        engine.add_rule(PolicyRule(rule_id="r1", rule_type=RuleType.DOMAIN_BLOCK,
                                   blocked_domains=["evil.com"]))
        rules = engine.get_rules()
        assert len(rules) == 1
        assert rules[0]["rule_id"] == "r1"

    def test_load_rules(self):
        engine = PolicyEngine()
        engine.load_rules([
            {"rule_id": "r1", "rule_type": "domain_block", "blocked_domains": ["evil.com"]},
            {"rule_id": "r2", "rule_type": "capability_required", "capability": "admin"},
        ])
        assert engine.rule_count == 2

    def test_context_auto_domain(self):
        ctx = PolicyContext(passport_id="p1", capabilities=[], tier="permanent",
                           issuer="org", action="proxy",
                           target_url="https://api.partner.com/v2/agents")
        assert ctx.target_domain == "api.partner.com"


# ═══════════════════════════════════════════════════════════════════
# 6. DELIVERABLE CONTRACTS
# ═══════════════════════════════════════════════════════════════════

class TestDeliverableContracts:

    @pytest.fixture
    def cm(self):
        return ContractManager()

    def test_create_contract(self, cm):
        c = cm.create("deploy-v2", "urn:aib:agent:acme:deployer", "Deploy v2")
        assert c.contract_id == "deploy-v2"
        assert c.status == "open"

    def test_add_criterion(self, cm):
        cm.create("c1", "p1")
        cm.add_criterion("c1", Criterion(
            criterion_id="tests", description="Coverage ≥ 80%",
            check_type="threshold", target_field="coverage", target_value=80, operator=">=",
        ))
        c = cm.get("c1")
        assert len(c["criteria"]) == 1

    def test_submit_evidence_met(self, cm):
        cm.create("c1", "p1")
        cm.add_criterion("c1", Criterion(
            criterion_id="tests", description="Coverage ≥ 80%",
            check_type="threshold", target_field="coverage", target_value=80, operator=">=",
        ))
        cm.submit_evidence("c1", "tests", {"coverage": 85})
        c = cm.get("c1")
        assert c["criteria"][0]["status"] == "met"
        assert c["criteria"][0]["actual_value"] == 85

    def test_submit_evidence_failed(self, cm):
        cm.create("c1", "p1")
        cm.add_criterion("c1", Criterion(
            criterion_id="tests", description="Coverage ≥ 80%",
            check_type="threshold", target_field="coverage", target_value=80, operator=">=",
        ))
        cm.submit_evidence("c1", "tests", {"coverage": 42})
        c = cm.get("c1")
        assert c["criteria"][0]["status"] == "failed"

    def test_auto_complete(self, cm):
        cm.create("c1", "p1")
        cm.add_criterion("c1", Criterion(
            criterion_id="tests", description="Coverage",
            check_type="threshold", target_field="cov", target_value=80, operator=">=",
        ))
        cm.add_criterion("c1", Criterion(
            criterion_id="review", description="Reviewed",
            check_type="boolean", target_field="reviewed", target_value=True, operator="==",
        ))
        cm.submit_evidence("c1", "tests", {"cov": 90})
        assert cm.get("c1")["status"] == "open"  # Still one pending
        cm.submit_evidence("c1", "review", {"reviewed": True})
        assert cm.get("c1")["status"] == "met"

    def test_progress(self, cm):
        cm.create("c1", "p1")
        cm.add_criterion("c1", Criterion(criterion_id="a", description="A",
                                          check_type="boolean", target_field="v", target_value=True, operator="=="))
        cm.add_criterion("c1", Criterion(criterion_id="b", description="B",
                                          check_type="boolean", target_field="v", target_value=True, operator="=="))
        cm.submit_evidence("c1", "a", {"v": True})
        p = cm.get("c1")["progress"]
        assert p["met"] == 1
        assert p["remaining"] == 1
        assert p["percent"] == 50

    def test_boolean_criterion(self, cm):
        cm.create("c1", "p1")
        cm.add_criterion("c1", Criterion(criterion_id="review", description="Reviewed",
                                          check_type="boolean", target_field="ok", target_value=True, operator="=="))
        cm.submit_evidence("c1", "review", {"ok": True})
        assert cm.get("c1")["criteria"][0]["status"] == "met"

    def test_not_equal_criterion(self, cm):
        cm.create("c1", "p1")
        cm.add_criterion("c1", Criterion(criterion_id="author", description="Reviewer ≠ author",
                                          check_type="match", target_field="reviewer", target_value="author_bot", operator="!="))
        cm.submit_evidence("c1", "author", {"reviewer": "review_bot"})
        assert cm.get("c1")["criteria"][0]["status"] == "met"

    def test_contains_criterion(self, cm):
        cm.create("c1", "p1")
        cm.add_criterion("c1", Criterion(criterion_id="logs", description="Has success",
                                          check_type="match", target_field="output", target_value="SUCCESS", operator="contains"))
        cm.submit_evidence("c1", "logs", {"output": "Build SUCCESS in 42s"})
        assert cm.get("c1")["criteria"][0]["status"] == "met"

    def test_get_by_passport(self, cm):
        cm.create("c1", "p1")
        cm.create("c2", "p1")
        cm.create("c3", "p2")
        result = cm.get_by_passport("p1")
        assert len(result) == 2

    def test_list_open(self, cm):
        cm.create("c1", "p1")
        cm.create("c2", "p1")
        cm.add_criterion("c2", Criterion(criterion_id="x", description="X",
                                          check_type="boolean", target_field="v", target_value=True, operator="=="))
        cm.submit_evidence("c2", "x", {"v": True})
        open_contracts = cm.list_open()
        assert len(open_contracts) == 1

    def test_mark_failed(self, cm):
        cm.create("c1", "p1")
        cm.mark_failed("c1", reason="Deadline exceeded")
        assert cm.get("c1")["status"] == "failed"


# ═══════════════════════════════════════════════════════════════════
# 7. END-TO-END
# ═══════════════════════════════════════════════════════════════════

class TestEndToEnd:

    def test_policy_plus_contract(self):
        """Full scenario: policy check → action → verify contract."""
        # Setup policy
        engine = PolicyEngine()
        engine.add_rule(PolicyRule(
            rule_id="need-deploy-cap", rule_type=RuleType.CAPABILITY_REQUIRED,
            capability="deploy", action="proxy",
        ))
        engine.add_rule(PolicyRule(
            rule_id="payment-cap", rule_type=RuleType.CAPABILITY_LIMIT,
            capability="payment", max_amount=1000,
        ))
        engine.add_rule(PolicyRule(
            rule_id="no-evil", rule_type=RuleType.DOMAIN_BLOCK,
            blocked_domains=["evil.com"],
        ))

        # Setup contract
        cm = ContractManager()
        cm.create("release-v3", "urn:aib:agent:acme:deployer", "Release v3")
        cm.add_criterion("release-v3", Criterion(
            criterion_id="tests", description="Coverage ≥ 90%",
            check_type="threshold", target_field="coverage", target_value=90, operator=">=",
        ))
        cm.add_criterion("release-v3", Criterion(
            criterion_id="review", description="Reviewed",
            check_type="boolean", target_field="reviewed", target_value=True, operator="==",
        ))

        # Step 1: Policy allows
        ctx = PolicyContext(
            passport_id="urn:aib:agent:acme:deployer",
            capabilities=["deploy", "payment"],
            tier="permanent", issuer="urn:aib:org:acme",
            action="proxy", target_url="https://ci.acme.com/deploy",
            amount=50,
        )
        d = engine.evaluate(ctx)
        assert d.allowed is True

        # Step 2: Agent completes task, submits evidence
        cm.submit_evidence("release-v3", "tests", {"coverage": 95})
        cm.submit_evidence("release-v3", "review", {"reviewed": True})

        # Step 3: Contract met
        assert cm.is_complete("release-v3") is True
        c = cm.get("release-v3")
        assert c["status"] == "met"
        assert c["progress"]["percent"] == 100
