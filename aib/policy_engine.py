"""
AIB — Sprint 14: Policy Engine + Deliverable Contracts.

Identity-based guardrails — NOT content guardrails.
This doesn't compete with Galileo/NeMo (prompt injection, toxicity).
This leverages AIB passport data to enforce:
  - Which capabilities are required for an action
  - Which protocols/domains are allowed
  - Spending limits per capability
  - Tier-based restrictions (ephemeral can't delegate)
  - Deliverable contracts (task completion criteria)

The policy engine reads the passport and the action context,
then returns allow/deny with a reason. No LLM involved.
Pure deterministic evaluation — <1ms per check.
"""

import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Any
from enum import Enum


# ═══════════════════════════════════════════════════════════════════
# 1. POLICY RULES
# ═══════════════════════════════════════════════════════════════════

class RuleType(str, Enum):
    CAPABILITY_REQUIRED = "capability_required"
    CAPABILITY_LIMIT = "capability_limit"
    PROTOCOL_RESTRICT = "protocol_restrict"
    DOMAIN_BLOCK = "domain_block"
    DOMAIN_ALLOW = "domain_allow"
    TIER_RESTRICT = "tier_restrict"
    ACTION_BLOCK = "action_block"
    TIME_RESTRICT = "time_restrict"


@dataclass
class PolicyRule:
    """A single policy rule."""
    rule_id: str
    rule_type: str
    description: str = ""
    # Matching conditions
    capability: str = ""
    capabilities: list = field(default_factory=list)
    action: str = ""
    protocol: str = ""
    tier: str = ""
    # Constraints
    max_amount: float = 0
    currency: str = ""
    allowed_protocols: list = field(default_factory=list)
    blocked_protocols: list = field(default_factory=list)
    allowed_domains: list = field(default_factory=list)
    blocked_domains: list = field(default_factory=list)
    blocked_actions: list = field(default_factory=list)
    allowed_hours: list = field(default_factory=list)  # [9, 17] = 9am-5pm
    # Metadata
    active: bool = True
    severity: str = "block"  # block, warn, log

    def to_dict(self) -> dict:
        d = {"rule_id": self.rule_id, "rule_type": self.rule_type, "active": self.active}
        if self.description:
            d["description"] = self.description
        if self.capability:
            d["capability"] = self.capability
        if self.capabilities:
            d["capabilities"] = self.capabilities
        if self.action:
            d["action"] = self.action
        if self.max_amount:
            d["max_amount"] = self.max_amount
        if self.allowed_protocols:
            d["allowed_protocols"] = self.allowed_protocols
        if self.blocked_domains:
            d["blocked_domains"] = self.blocked_domains
        if self.blocked_actions:
            d["blocked_actions"] = self.blocked_actions
        if self.tier:
            d["tier"] = self.tier
        return d


# ═══════════════════════════════════════════════════════════════════
# 2. POLICY EVALUATION CONTEXT
# ═══════════════════════════════════════════════════════════════════

@dataclass
class PolicyContext:
    """Everything the policy engine needs to evaluate a request."""
    passport_id: str
    capabilities: list[str]
    tier: str
    issuer: str
    action: str           # proxy, translate, delegate, revoke
    protocol: str = ""
    target_url: str = ""
    target_domain: str = ""
    method: str = "POST"
    amount: float = 0.0
    currency: str = ""
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.target_url and not self.target_domain:
            try:
                from urllib.parse import urlparse
                self.target_domain = urlparse(self.target_url).hostname or ""
            except Exception:
                pass


@dataclass
class PolicyDecision:
    """Result of policy evaluation."""
    allowed: bool
    reason: str
    matched_rules: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    evaluation_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "matched_rules": self.matched_rules,
            "warnings": self.warnings,
            "evaluation_ms": self.evaluation_ms,
        }


# ═══════════════════════════════════════════════════════════════════
# 3. POLICY ENGINE
# ═══════════════════════════════════════════════════════════════════

class PolicyEngine:
    """
    Deterministic policy engine for identity-based guardrails.

    Evaluates rules against passport data + action context.
    No LLM, no AI — pure rule matching. <1ms per evaluation.

    Usage:
        engine = PolicyEngine()

        # Add rules
        engine.add_rule(PolicyRule(
            rule_id="payment-cap",
            rule_type="capability_limit",
            capability="payment",
            max_amount=500,
            currency="EUR",
            description="Max 500€ per payment action",
        ))

        engine.add_rule(PolicyRule(
            rule_id="no-evil",
            rule_type="domain_block",
            blocked_domains=["evil.com", "malware.org"],
        ))

        engine.add_rule(PolicyRule(
            rule_id="ephemeral-no-delegate",
            rule_type="tier_restrict",
            tier="ephemeral",
            blocked_actions=["delegate", "revoke"],
        ))

        # Evaluate
        ctx = PolicyContext(
            passport_id="urn:aib:agent:acme:bot",
            capabilities=["booking", "payment"],
            tier="permanent",
            issuer="urn:aib:org:acme",
            action="proxy",
            target_url="https://partner.com/a2a",
            amount=200, currency="EUR",
        )

        decision = engine.evaluate(ctx)
        if not decision.allowed:
            return error_403(decision.reason)
    """

    def __init__(self):
        self._rules: list[PolicyRule] = []

    def add_rule(self, rule: PolicyRule):
        self._rules.append(rule)

    def remove_rule(self, rule_id: str) -> bool:
        before = len(self._rules)
        self._rules = [r for r in self._rules if r.rule_id != rule_id]
        return len(self._rules) < before

    def get_rules(self) -> list[dict]:
        return [r.to_dict() for r in self._rules]

    def load_rules(self, rules_list: list[dict]):
        """Load rules from a list of dicts (e.g. parsed from JSON config)."""
        for rd in rules_list:
            self._rules.append(PolicyRule(**rd))

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def evaluate(self, ctx: PolicyContext) -> PolicyDecision:
        """
        Evaluate all active rules against the context.

        Returns allow if no rule blocks. One block = deny.
        Warnings are collected but don't block.
        """
        start = time.time()
        matched = []
        warnings = []

        for rule in self._rules:
            if not rule.active:
                continue

            result = self._evaluate_rule(rule, ctx)
            if result is None:
                continue  # Rule doesn't apply to this context

            if result["blocked"]:
                if rule.severity == "block":
                    elapsed = (time.time() - start) * 1000
                    return PolicyDecision(
                        allowed=False,
                        reason=result["reason"],
                        matched_rules=[rule.rule_id],
                        evaluation_ms=round(elapsed, 3),
                    )
                elif rule.severity == "warn":
                    warnings.append({"rule_id": rule.rule_id, "reason": result["reason"]})
                else:
                    matched.append(rule.rule_id)

        elapsed = (time.time() - start) * 1000
        return PolicyDecision(
            allowed=True,
            reason="All policies passed",
            matched_rules=matched,
            warnings=warnings,
            evaluation_ms=round(elapsed, 3),
        )

    def _evaluate_rule(self, rule: PolicyRule, ctx: PolicyContext) -> Optional[dict]:
        """Evaluate a single rule. Returns None if rule doesn't apply."""

        if rule.rule_type == RuleType.CAPABILITY_REQUIRED:
            return self._check_capability_required(rule, ctx)
        elif rule.rule_type == RuleType.CAPABILITY_LIMIT:
            return self._check_capability_limit(rule, ctx)
        elif rule.rule_type == RuleType.PROTOCOL_RESTRICT:
            return self._check_protocol_restrict(rule, ctx)
        elif rule.rule_type == RuleType.DOMAIN_BLOCK:
            return self._check_domain_block(rule, ctx)
        elif rule.rule_type == RuleType.DOMAIN_ALLOW:
            return self._check_domain_allow(rule, ctx)
        elif rule.rule_type == RuleType.TIER_RESTRICT:
            return self._check_tier_restrict(rule, ctx)
        elif rule.rule_type == RuleType.ACTION_BLOCK:
            return self._check_action_block(rule, ctx)
        elif rule.rule_type == RuleType.TIME_RESTRICT:
            return self._check_time_restrict(rule, ctx)
        return None

    def _check_capability_required(self, rule, ctx):
        required = rule.capabilities or ([rule.capability] if rule.capability else [])
        if not required:
            return None
        # Check if action matches (if specified)
        if rule.action and rule.action != ctx.action:
            return None
        missing = [c for c in required if c not in ctx.capabilities]
        if missing:
            return {"blocked": True, "reason": f"Missing capabilities: {missing}"}
        return {"blocked": False, "reason": "Capabilities present"}

    def _check_capability_limit(self, rule, ctx):
        if rule.capability and rule.capability not in ctx.capabilities:
            return None  # Rule doesn't apply — agent doesn't have this capability
        if not rule.capability and rule.action and rule.action != ctx.action:
            return None
        if rule.max_amount > 0 and ctx.amount > rule.max_amount:
            return {
                "blocked": True,
                "reason": f"Amount {ctx.amount} exceeds limit {rule.max_amount} "
                          f"for capability '{rule.capability}'",
            }
        return {"blocked": False, "reason": "Within limits"}

    def _check_protocol_restrict(self, rule, ctx):
        if not ctx.protocol:
            return None
        if rule.allowed_protocols and ctx.protocol not in rule.allowed_protocols:
            return {
                "blocked": True,
                "reason": f"Protocol '{ctx.protocol}' not in allowed list: {rule.allowed_protocols}",
            }
        if rule.blocked_protocols and ctx.protocol in rule.blocked_protocols:
            return {
                "blocked": True,
                "reason": f"Protocol '{ctx.protocol}' is blocked",
            }
        return {"blocked": False, "reason": "Protocol allowed"}

    def _check_domain_block(self, rule, ctx):
        if not ctx.target_domain or not rule.blocked_domains:
            return None
        for blocked in rule.blocked_domains:
            if ctx.target_domain == blocked or ctx.target_domain.endswith(f".{blocked}"):
                return {"blocked": True, "reason": f"Domain '{ctx.target_domain}' is blocked"}
        return {"blocked": False, "reason": "Domain not blocked"}

    def _check_domain_allow(self, rule, ctx):
        if not ctx.target_domain or not rule.allowed_domains:
            return None
        for allowed in rule.allowed_domains:
            if ctx.target_domain == allowed or ctx.target_domain.endswith(f".{allowed}"):
                return {"blocked": False, "reason": "Domain allowed"}
        return {"blocked": True, "reason": f"Domain '{ctx.target_domain}' not in allowed list"}

    def _check_tier_restrict(self, rule, ctx):
        if rule.tier and rule.tier != ctx.tier:
            return None  # Rule doesn't apply to this tier
        if rule.blocked_actions and ctx.action in rule.blocked_actions:
            return {
                "blocked": True,
                "reason": f"Action '{ctx.action}' blocked for tier '{ctx.tier}'",
            }
        return {"blocked": False, "reason": "Tier action allowed"}

    def _check_action_block(self, rule, ctx):
        if rule.blocked_actions and ctx.action in rule.blocked_actions:
            return {"blocked": True, "reason": f"Action '{ctx.action}' is globally blocked"}
        return None

    def _check_time_restrict(self, rule, ctx):
        if not rule.allowed_hours or len(rule.allowed_hours) != 2:
            return None
        hour = datetime.now(timezone.utc).hour
        start_h, end_h = rule.allowed_hours
        if not (start_h <= hour < end_h):
            return {
                "blocked": True,
                "reason": f"Action blocked outside allowed hours ({start_h}:00-{end_h}:00 UTC)",
            }
        return {"blocked": False, "reason": "Within allowed hours"}


# ═══════════════════════════════════════════════════════════════════
# 4. DELIVERABLE CONTRACTS
# ═══════════════════════════════════════════════════════════════════

class CriterionStatus(str, Enum):
    PENDING = "pending"
    MET = "met"
    FAILED = "failed"


@dataclass
class Criterion:
    """A single verifiable criterion in a deliverable contract."""
    criterion_id: str
    description: str
    check_type: str        # threshold, boolean, match, custom
    target_field: str = ""
    target_value: Any = None
    operator: str = ">="   # >=, <=, ==, !=, contains, matches
    status: str = CriterionStatus.PENDING
    actual_value: Any = None
    verified_at: str = ""

    def to_dict(self) -> dict:
        return {
            "criterion_id": self.criterion_id,
            "description": self.description,
            "check_type": self.check_type,
            "target_field": self.target_field,
            "target_value": self.target_value,
            "operator": self.operator,
            "status": self.status,
            "actual_value": self.actual_value,
            "verified_at": self.verified_at,
        }


@dataclass
class DeliverableContract:
    """
    A set of criteria that must be met before a task is considered done.

    Usage:
        contract = DeliverableContract(
            contract_id="deploy-v2",
            passport_id="urn:aib:agent:acme:deployer",
            description="Deploy v2 to production",
        )
        contract.add_criterion(Criterion(
            criterion_id="tests",
            description="Test coverage ≥ 80%",
            check_type="threshold",
            target_field="coverage_percent",
            target_value=80,
            operator=">=",
        ))
        contract.add_criterion(Criterion(
            criterion_id="review",
            description="Code reviewed by different agent",
            check_type="boolean",
            target_field="reviewed",
            target_value=True,
            operator="==",
        ))
    """
    contract_id: str
    passport_id: str
    description: str = ""
    criteria: list[Criterion] = field(default_factory=list)
    status: str = "open"   # open, met, failed
    created_at: str = ""
    completed_at: str = ""

    def add_criterion(self, criterion: Criterion):
        self.criteria.append(criterion)

    @property
    def is_met(self) -> bool:
        return all(c.status == CriterionStatus.MET for c in self.criteria) and len(self.criteria) > 0

    @property
    def progress(self) -> dict:
        total = len(self.criteria)
        met = sum(1 for c in self.criteria if c.status == CriterionStatus.MET)
        return {"total": total, "met": met, "remaining": total - met, "percent": round(met / max(total, 1) * 100)}

    def to_dict(self) -> dict:
        return {
            "contract_id": self.contract_id,
            "passport_id": self.passport_id,
            "description": self.description,
            "status": self.status,
            "criteria": [c.to_dict() for c in self.criteria],
            "progress": self.progress,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
        }


class ContractManager:
    """
    Manages deliverable contracts and verifies completion.

    Usage:
        cm = ContractManager()

        # Create contract
        contract = cm.create("deploy-v2", "urn:aib:agent:acme:deployer",
                             "Deploy v2 to production")
        cm.add_criterion("deploy-v2", Criterion(...))

        # Agent submits evidence
        cm.submit_evidence("deploy-v2", "tests", {"coverage_percent": 85})

        # Check if done
        if cm.is_complete("deploy-v2"):
            cm.mark_complete("deploy-v2")
    """

    def __init__(self):
        self._contracts: dict[str, DeliverableContract] = {}

    def create(
        self, contract_id: str, passport_id: str, description: str = "",
    ) -> DeliverableContract:
        contract = DeliverableContract(
            contract_id=contract_id,
            passport_id=passport_id,
            description=description,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._contracts[contract_id] = contract
        return contract

    def add_criterion(self, contract_id: str, criterion: Criterion) -> bool:
        contract = self._contracts.get(contract_id)
        if not contract:
            return False
        contract.add_criterion(criterion)
        return True

    def submit_evidence(self, contract_id: str, criterion_id: str, evidence: dict) -> bool:
        """
        Submit evidence for a criterion. Auto-evaluates.

        evidence: dict with field values, e.g. {"coverage_percent": 85}
        """
        contract = self._contracts.get(contract_id)
        if not contract:
            return False

        criterion = next((c for c in contract.criteria if c.criterion_id == criterion_id), None)
        if not criterion:
            return False

        actual = evidence.get(criterion.target_field, evidence.get("value"))
        criterion.actual_value = actual
        criterion.verified_at = datetime.now(timezone.utc).isoformat()

        if self._check_criterion(criterion, actual):
            criterion.status = CriterionStatus.MET
        else:
            criterion.status = CriterionStatus.FAILED

        # Auto-complete if all met
        if contract.is_met:
            contract.status = "met"
            contract.completed_at = datetime.now(timezone.utc).isoformat()

        return True

    def _check_criterion(self, criterion: Criterion, actual: Any) -> bool:
        target = criterion.target_value
        op = criterion.operator

        if actual is None:
            return False

        try:
            if op == ">=":
                return float(actual) >= float(target)
            elif op == "<=":
                return float(actual) <= float(target)
            elif op == "==":
                return actual == target
            elif op == "!=":
                return actual != target
            elif op == ">":
                return float(actual) > float(target)
            elif op == "<":
                return float(actual) < float(target)
            elif op == "contains":
                return str(target) in str(actual)
            elif op == "matches":
                return bool(re.match(str(target), str(actual)))
        except (ValueError, TypeError):
            return False
        return False

    def is_complete(self, contract_id: str) -> bool:
        contract = self._contracts.get(contract_id)
        return contract.is_met if contract else False

    def mark_complete(self, contract_id: str) -> bool:
        contract = self._contracts.get(contract_id)
        if contract and contract.is_met:
            contract.status = "met"
            contract.completed_at = datetime.now(timezone.utc).isoformat()
            return True
        return False

    def mark_failed(self, contract_id: str, reason: str = "") -> bool:
        contract = self._contracts.get(contract_id)
        if contract:
            contract.status = "failed"
            contract.completed_at = datetime.now(timezone.utc).isoformat()
            return True
        return False

    def get(self, contract_id: str) -> Optional[dict]:
        c = self._contracts.get(contract_id)
        return c.to_dict() if c else None

    def get_by_passport(self, passport_id: str) -> list[dict]:
        return [
            c.to_dict() for c in self._contracts.values()
            if c.passport_id == passport_id
        ]

    def list_open(self) -> list[dict]:
        return [c.to_dict() for c in self._contracts.values() if c.status == "open"]

    @property
    def count(self) -> int:
        return len(self._contracts)
