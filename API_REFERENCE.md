# AIB API Reference

> Auto-generated from source code. This is the truth — not the README.

> **Version**: 2.13 · **Modules**: 26 · **Generated**: March 2026

---

## Table of Contents

- [Passport](#aibpassport)
- [Translator](#aibtranslator)
- [AG-UI Binding](#aibag-ui-binding)
- [Lifecycle](#aiblifecycle)
- [Policy Engine](#aibpolicy-engine)
- [Renewal](#aibrenewal)
- [Webhooks](#aibwebhooks)
- [Protocol Health](#aibprotocol-health)
- [Diagnostics](#aibdiagnostics)
- [Gateway](#aibgateway)
- [Client SDK](#aibclient)
- [CLI](#aibcli)
- [Receipts](#aibreceipts)
- [Merkle](#aibmerkle)
- [Crypto](#aibcrypto)
- [Security](#aibsecurity)
- [Rate Limiter](#aibrate-limiter)
- [Schema Validator](#aibschema-validator)
- [OIDC](#aiboidc)
- [Discovery](#aibdiscovery)
- [GDPR](#aibgdpr)
- [Migration](#aibmigration)
- [Plugins](#aibplugins)
- [Error Codes](#aibhardening-sprint1)
- [Enterprise](#aibsprint5-enterprise)
- [Security Final](#aibsprint6-final)


---

## Passport — Agent identity creation, signing, verification

`import` : `from aib.passport import ...`


### `A2aBinding`

A2aBinding(auth_method: str, credential_ref: Optional[str] = None, agent_card_url: str = '', skills: list[str] = <factory>)

**Constructor**: `A2aBinding(auth_method, credential_ref, agent_card_url, skills)`


### `AgentPassport`

The core identity document for an AI agent.

**Constructor**: `AgentPassport(passport_id, display_name, issuer, capabilities, protocol_bindings, issued_at, expires_at, aib_version, revocation_endpoint, audit_endpoint, metadata)`

- `to_dict()` → `<class 'dict'>`


### `AnpBinding`

AnpBinding(auth_method: str, credential_ref: Optional[str] = None, did: str = '')

**Constructor**: `AnpBinding(auth_method, credential_ref, did)`


### `McpBinding`

McpBinding(auth_method: str, credential_ref: Optional[str] = None, server_card_url: str = '', scopes: list[str] = <factory>)

**Constructor**: `McpBinding(auth_method, credential_ref, server_card_url, scopes)`


### `PassportService`

Creates, signs, verifies, stores, and revokes Agent Passports.

**Constructor**: `PassportService(secret_key, storage_path)`

- `create_passport(org_slug, agent_slug, display_name, capabilities, bindings, ttl_days, metadata)` → `tuple[aib.passport.AgentPassport, str]`
- `list_passports()` → `list[dict]`
- `revoke_passport(passport_id)` → `<class 'bool'>`
- `verify_passport(token)` → `tuple[bool, typing.Optional[aib.passport.AgentPassport], str]`


### `ProtocolBinding`

Credentials for a single protocol.

**Constructor**: `ProtocolBinding(auth_method, credential_ref)`


---

## Translator — Cross-protocol format conversion

`import` : `from aib.translator import ...`


### `CredentialTranslator`

Translates identity/capability documents between AI protocols.

- `a2a_to_mcp(agent_card)` → `<class 'dict'>`
- `did_to_a2a(did_doc)` → `<class 'dict'>`
- `mcp_to_a2a(server_card)` → `<class 'dict'>`
- `to_did_document(card, source_protocol, domain, agent_slug)` → `<class 'dict'>`
- `translate(source, from_format, to_format, domain, agent_slug)` → `<class 'dict'>`


---

## AG-UI Binding — AG-UI protocol support

`import` : `from aib.ag_ui_binding import ...`


### `AgUiBinding`

AG-UI protocol binding for an Agent Passport.

**Constructor**: `AgUiBinding(auth_method, credential_ref, endpoint_url, ui_capabilities, supported_events, a2ui_support, shared_state)`

- `to_dict()` → `<class 'dict'>`


### Functions

#### `a2a_to_ag_ui(agent_card)` → `<class 'dict'>`

Translate an A2A Agent Card to an AG-UI Agent Descriptor.

#### `ag_ui_to_a2a(ag_ui_descriptor)` → `<class 'dict'>`

Translate an AG-UI Agent Descriptor to an A2A Agent Card.

#### `ag_ui_to_mcp(ag_ui_descriptor)` → `<class 'dict'>`

Translate an AG-UI Agent Descriptor to an MCP Server Card.

#### `create_ag_ui_descriptor(name, endpoint_url, description, capabilities, supported_events, a2ui_support, shared_state, version, metadata)` → `<class 'dict'>`

Create an AG-UI Agent Descriptor.

#### `map_ag_ui_event_to_audit_action(event_type)` → `<class 'str'>`

Map an AG-UI event type to an AIB audit action for receipt generation.

#### `mcp_to_ag_ui(server_card)` → `<class 'dict'>`

Translate an MCP Server Card to an AG-UI Agent Descriptor.

#### `validate_ag_ui_descriptor(descriptor)` → `list[str]`

Validate an AG-UI descriptor against the schema.


---

## Lifecycle — Passport tiers, delegation, cascade revocation

`import` : `from aib.lifecycle import ...`


### `CapabilityEscalationError`

Raised when a child requests capabilities not held by the parent.

**Constructor**: `CapabilityEscalationError(args, kwargs)`


### `DelegationError`

Raised when a delegation request is invalid.

**Constructor**: `DelegationError(args, kwargs)`


### `DelegationLink`

Cryptographic link to a parent passport.

**Constructor**: `DelegationLink(parent_passport_id, parent_tier, delegated_at, delegated_capabilities, delegation_chain, max_depth)`


### `LifecyclePassport`

A passport with lifecycle tier and delegation support.

**Constructor**: `LifecyclePassport(passport_id, display_name, issuer, tier, capabilities, protocol_bindings, issued_at, expires_at, jti, delegation, metadata, aib_version)`

- `to_dict()` → `<class 'dict'>`

**Properties**: `delegation_depth`, `is_root`, `parent_id`, `root_passport_id`


### `MaxDepthExceededError`

Raised when the delegation chain is too deep.

**Constructor**: `MaxDepthExceededError(args, kwargs)`


### `PassportLifecycleManager`

Manages passport creation, delegation, and lifecycle enforcement.

- `create_ephemeral(parent_id, kwargs)` → `<class 'aib.lifecycle.LifecyclePassport'>`
- `create_permanent(org, agent, capabilities, protocol_bindings, display_name, ttl, metadata)` → `<class 'aib.lifecycle.LifecyclePassport'>`
- `create_session(parent_id, kwargs)` → `<class 'aib.lifecycle.LifecyclePassport'>`
- `delegate(parent_id, child_tier, capabilities, protocol_bindings, child_slug, ttl, metadata)` → `<class 'aib.lifecycle.LifecyclePassport'>`
- `get(passport_id)` → `typing.Optional[aib.lifecycle.LifecyclePassport]`
- `get_chain(passport_id)` → `list[aib.lifecycle.LifecyclePassport]`
- `get_children(passport_id)` → `list[aib.lifecycle.LifecyclePassport]`
- `list_all()` → `list[dict]`
- `revoke(passport_id)` → `list[str]`
- `verify(passport_id)` → `tuple[bool, str]`


### `PassportTier`

Passport lifecycle tier.

**Constructor**: `PassportTier(args, kwds)`


### `TierViolationError`

Raised when a tier tries to create a child it's not allowed to.

**Constructor**: `TierViolationError(args, kwargs)`


---

## Policy Engine — Identity-based guardrails + Deliverable contracts

`import` : `from aib.policy_engine import ...`


### `ContractManager`

Manages deliverable contracts and verifies completion.

- `add_criterion(contract_id, criterion)` → `<class 'bool'>`
- `create(contract_id, passport_id, description)` → `<class 'aib.policy_engine.DeliverableContract'>`
- `get(contract_id)` → `typing.Optional[dict]`
- `get_by_passport(passport_id)` → `list[dict]`
- `is_complete(contract_id)` → `<class 'bool'>`
- `list_open()` → `list[dict]`
- `mark_complete(contract_id)` → `<class 'bool'>`
- `mark_failed(contract_id, reason)` → `<class 'bool'>`
- `submit_evidence(contract_id, criterion_id, evidence)` → `<class 'bool'>`

**Properties**: `count`


### `Criterion`

A single verifiable criterion in a deliverable contract.

**Constructor**: `Criterion(criterion_id, description, check_type, target_field, target_value, operator, status, actual_value, verified_at)`

- `to_dict()` → `<class 'dict'>`


### `CriterionStatus`

**Constructor**: `CriterionStatus(args, kwds)`


### `DeliverableContract`

A set of criteria that must be met before a task is considered done.

**Constructor**: `DeliverableContract(contract_id, passport_id, description, criteria, status, created_at, completed_at)`

- `add_criterion(criterion)`
- `to_dict()` → `<class 'dict'>`

**Properties**: `is_met`, `progress`


### `PolicyContext`

Everything the policy engine needs to evaluate a request.

**Constructor**: `PolicyContext(passport_id, capabilities, tier, issuer, action, protocol, target_url, target_domain, method, amount, currency, metadata)`


### `PolicyDecision`

Result of policy evaluation.

**Constructor**: `PolicyDecision(allowed, reason, matched_rules, warnings, evaluation_ms)`

- `to_dict()` → `<class 'dict'>`


### `PolicyEngine`

Deterministic policy engine for identity-based guardrails.

- `add_rule(rule)`
- `evaluate(ctx)` → `<class 'aib.policy_engine.PolicyDecision'>`
- `get_rules()` → `list[dict]`
- `load_rules(rules_list)`
- `remove_rule(rule_id)` → `<class 'bool'>`

**Properties**: `rule_count`


### `PolicyRule`

A single policy rule.

**Constructor**: `PolicyRule(rule_id, rule_type, description, capability, capabilities, action, protocol, tier, max_amount, currency, allowed_protocols, blocked_protocols, allowed_domains, blocked_domains, blocked_actions, allowed_hours, active, severity)`

- `to_dict()` → `<class 'dict'>`


### `RuleType`

**Constructor**: `RuleType(args, kwds)`


---

## Renewal — Hot-update passports without revocation

`import` : `from aib.renewal import ...`


### `CapabilityEscalationError`

Raised when renewal tries to add capabilities beyond the original scope.

**Constructor**: `CapabilityEscalationError(args, kwargs)`


### `PassportNotFoundError`

**Constructor**: `PassportNotFoundError(args, kwargs)`


### `PassportRenewalManager`

Manages passport renewal and hot-update lifecycle.

**Constructor**: `PassportRenewalManager(max_capabilities)`

- `get(passport_id)` → `typing.Optional[aib.renewal.RenewablePassport]`
- `get_dict(passport_id)` → `typing.Optional[dict]`
- `get_history(passport_id)` → `list[dict]`
- `get_version(passport_id)` → `<class 'int'>`
- `is_revoked(passport_id)` → `<class 'bool'>`
- `list_passports()` → `list[dict]`
- `register(passport_id, display_name, issuer, capabilities, protocol_bindings, tier, ttl_days, metadata)` → `<class 'aib.renewal.RenewablePassport'>`
- `renew(passport_id, ttl_days, reason, renewed_by)` → `<class 'aib.renewal.RenewablePassport'>`
- `revoke(passport_id, reason)`
- `update_bindings(passport_id, add, remove, reason, renewed_by)` → `<class 'aib.renewal.RenewablePassport'>`
- `update_capabilities(passport_id, add, remove, reason, renewed_by)` → `<class 'aib.renewal.RenewablePassport'>`
- `update_metadata(passport_id, display_name, metadata, reason, renewed_by)` → `<class 'aib.renewal.RenewablePassport'>`

**Properties**: `count`


### `PassportRevokedError`

**Constructor**: `PassportRevokedError(args, kwargs)`


### `RenewablePassport`

A passport that supports in-place renewal without revocation.

**Constructor**: `RenewablePassport(passport_id, display_name, issuer, capabilities, protocol_bindings, issued_at, expires_at, version, renewal_history, metadata, tier)`

- `to_dict()` → `<class 'dict'>`


### `RenewalError`

Base error for renewal operations.

**Constructor**: `RenewalError(args, kwargs)`


### `RenewalRecord`

Tracks a single renewal event.

**Constructor**: `RenewalRecord(renewal_id, passport_id, version, renewed_at, reason, changes, previous_expires_at, new_expires_at, renewed_by)`

- `to_dict()` → `<class 'dict'>`


---

## Webhooks — Pre/post action hooks for external integrations

`import` : `from aib.webhooks import ...`


### `PostActionPayload`

Extended payload for post-action webhooks (includes result).

**Constructor**: `PostActionPayload(event_id, event, timestamp, passport_id, issuer, capabilities, action, protocol, target_url, method, body_hash, tier, trace_id, metadata, status_code, success, latency_ms, receipt_id, error_code)`

- `to_dict()` → `<class 'dict'>`


### `WebhookDecision`

**Constructor**: `WebhookDecision(args, kwds)`


### `WebhookDeniedError`

Raised when a pre-action webhook denies the request.

**Constructor**: `WebhookDeniedError(reason, webhook_id)`


### `WebhookEvent`

**Constructor**: `WebhookEvent(args, kwds)`


### `WebhookManager`

Manages webhook registrations and dispatching.

**Constructor**: `WebhookManager(http_sender)`

- `disable(webhook_id)` → `<class 'bool'>`
- `dispatch_event(event, passport_id, metadata)`
- `dispatch_post_action(passport_id, action, protocol, target_url, status_code, success, latency_ms, receipt_id, error_code, trace_id, metadata)`
- `dispatch_pre_action(passport_id, action, protocol, target_url, method, body, capabilities, issuer, tier, trace_id, metadata)` → `<class 'aib.webhooks.WebhookResponse'>`
- `enable(webhook_id)` → `<class 'bool'>`
- `get_history(limit)` → `list[dict]`
- `get_stats()` → `<class 'dict'>`
- `get_webhook(webhook_id)` → `typing.Optional[dict]`
- `list_webhooks()` → `list[dict]`
- `register(url, events, secret, timeout_ms, max_retries, description, metadata)` → `<class 'aib.webhooks.WebhookRegistration'>`
- `unregister(webhook_id)` → `<class 'bool'>`

**Properties**: `webhook_count`


### `WebhookPayload`

Payload sent to the external system on each webhook event.

**Constructor**: `WebhookPayload(event_id, event, timestamp, passport_id, issuer, capabilities, action, protocol, target_url, method, body_hash, tier, trace_id, metadata)`

- `to_dict()` → `<class 'dict'>`


### `WebhookRegistration`

A registered webhook endpoint.

**Constructor**: `WebhookRegistration(webhook_id, url, events, secret, active, timeout_ms, retry_count, max_retries, created_at, description, metadata)`

- `to_dict()` → `<class 'dict'>`


### `WebhookResponse`

Response from the external system.

**Constructor**: `WebhookResponse(decision, reason, modifications, metadata, latency_ms)`

- `to_dict()` → `<class 'dict'>`


---

## Protocol Health — Endpoint monitoring + status page

`import` : `from aib.protocol_health import ...`


### `EndpointMetrics`

Rolling metrics for a single protocol endpoint.

**Constructor**: `EndpointMetrics(target, protocol, status, total_requests, successful, failed, last_status_code, last_error, last_request_at, last_success_at, last_failure_at, latencies, status_changed_at, consecutive_failures, consecutive_successes, _max_latencies)`

- `record_failure(latency_ms, status_code, error)`
- `record_success(latency_ms, status_code)`
- `to_dict()` → `<class 'dict'>`
- `uptime_percent()` → `<class 'float'>`

**Properties**: `avg_latency`, `error_rate`, `p50`, `p95`, `p99`, `success_rate`


### `EndpointStatus`

**Constructor**: `EndpointStatus(args, kwds)`


### `ProtocolHealthMonitor`

Tracks health of every protocol endpoint the gateway talks to.

**Constructor**: `ProtocolHealthMonitor(on_status_change)`

- `get_all_endpoints()` → `list[dict]`
- `get_degraded_endpoints()` → `list[dict]`
- `get_down_endpoints()` → `list[dict]`
- `get_endpoint(target)` → `typing.Optional[dict]`
- `get_endpoints_by_protocol(protocol)` → `list[dict]`
- `get_endpoints_by_status(status)` → `list[dict]`
- `get_status()` → `<class 'dict'>`
- `get_status_changes(limit)` → `list[dict]`
- `record_failure(target, protocol, latency_ms, status_code, error)`
- `record_success(target, protocol, latency_ms, status_code)`
- `reset_endpoint(target)`

**Properties**: `endpoint_count`, `protocols_tracked`


### `StatusChangeEvent`

Emitted when an endpoint's status changes.

**Constructor**: `StatusChangeEvent(target, protocol, old_status, new_status, timestamp, consecutive_failures, last_error)`

- `to_dict()` → `<class 'dict'>`


---

## Diagnostics — Component health checks + Trust scoring

`import` : `from aib.diagnostics import ...`


### `Component`

**Constructor**: `Component(args, kwds)`


### `DiagnosticLevel`

**Constructor**: `DiagnosticLevel(args, kwds)`


### `DiagnosticResult`

Result of a single component check.

**Constructor**: `DiagnosticResult(component, level, message, latency_ms, detail, suggestion, timestamp)`

- `to_dict()` → `<class 'dict'>`


### `DiagnosticRunner`

Runs health checks on all AIB components and reports which
brick is broken when something fails.

- `check_one(component)` → `<class 'aib.diagnostics.DiagnosticResult'>`
- `register(component, check_fn, description, suggestion_on_fail)`
- `run_all()` → `list[aib.diagnostics.DiagnosticResult]`
- `summary()` → `<class 'dict'>`

**Properties**: `registered_components`


### `FederationTrustScorer`

Computes trust scores (0-100) for federated organizations.

**Constructor**: `FederationTrustScorer(min_score_to_trust)`

- `compute_score(issuer)` → `<class 'aib.diagnostics.TrustScore'>`
- `get_metrics(issuer)` → `typing.Optional[dict]`
- `list_by_grade(grade)` → `list[dict]`
- `list_scores()` → `list[dict]`
- `record_jwks_failure(issuer)`
- `record_revocation(issuer)`
- `record_transaction(issuer, success, latency_ms)`
- `set_crl_size(issuer, size)`
- `should_trust(issuer)` → `tuple[bool, aib.diagnostics.TrustScore]`

**Properties**: `issuer_count`


### `TrustMetrics`

Raw metrics for computing a trust score.

**Constructor**: `TrustMetrics(issuer, total_transactions, successful_transactions, failed_transactions, revocations_received, avg_response_ms, first_seen, last_seen, jwks_fetch_failures, crl_size)`

- `age_days()` → `<class 'int'>`
- `success_rate()` → `<class 'float'>`
- `to_dict()` → `<class 'dict'>`


### `TrustScore`

Computed trust score for a federated issuer.

**Constructor**: `TrustScore(issuer, score, grade, factors, computed_at)`

- `to_dict()` → `<class 'dict'>`


### Functions

#### `diagnose_error(error, context)` → `<class 'aib.diagnostics.DiagnosticResult'>`

Given an exception, identify which AIB component is responsible.


---

## Gateway — Protocol-aware reverse proxy

`import` : `from aib.gateway import ...`


### `Gateway`

Reverse proxy that routes requests through the appropriate protocol
and injects credentials from the agent's passport.

**Constructor**: `Gateway(timeout)`

- `detect_protocol(url, passport_bindings)` → `<class 'str'>`
- `proxy_request(passport_id, passport_bindings, target_url, method, body, extra_headers)` → `<class 'aib.gateway.ProxyResult'>`
- `register_credential(passport_id, protocol, token)`


### `ProxyResult`

ProxyResult(status_code: int, body: Optional[dict], headers: dict, protocol_used: str, trace_id: str = '')

**Constructor**: `ProxyResult(status_code, body, headers, protocol_used, trace_id)`


---

## Client SDK — Python SDK for gateway interaction

`import` : `from aib.client import ...`


### `AIBClient`

One-liner client for Agent Identity Bridge.

**Constructor**: `AIBClient(api_key, gateway_url, timeout)`

- `close()`
- `create_passport(org, agent, protocols, capabilities, name, ttl_days)` → `<class 'aib.client.Passport'>`
- `get_audit(passport_id, protocol, limit)` → `list[dict]`
- `health()` → `<class 'dict'>`
- `list_passports()` → `list[aib.client.Passport]`
- `revoke(passport_id)` → `<class 'bool'>`
- `send(target_url, body, passport_id, method)` → `<class 'aib.client.SendResult'>`
- `translate(source, from_format, to_format, domain, agent_slug)` → `<class 'aib.client.TranslateResult'>`
- `verify(token)` → `<class 'aib.client.VerifyResult'>`


### `Passport`

A created or retrieved passport.

**Constructor**: `Passport(passport_id, display_name, protocols, capabilities, expires_at, token, raw)`


### `SendResult`

Response from a gateway proxy call.

**Constructor**: `SendResult(success, protocol, trace_id, status_code, data, latency_ms, passport_id)`


### `TranslateResult`

Translation result between identity formats.

**Constructor**: `TranslateResult(source_format, target_format, data, tools_count, skills_count)`


### `VerifyResult`

Passport verification result.

**Constructor**: `VerifyResult(valid, passport_id, issuer, protocols, expires_at, reason)`


---

## CLI — Command line interface

`import` : `from aib.cli import ...`


### Functions

#### `cmd_create(args)`

Create a new Agent Passport.

#### `cmd_inspect(args)`

Show full details of a passport.

#### `cmd_keygen(args)`

Generate or rotate RS256 signing keys.

#### `cmd_list(args)`

List all passports.

#### `cmd_quickstart(args)`

Run a complete demo in 30 seconds. Tests every core feature.

#### `cmd_revoke(args)`

Revoke a passport.

#### `cmd_serve(args)`

Start the AIB Gateway server.

#### `cmd_translate(args)`

Translate between protocol identity formats.

#### `cmd_verify(args)`

Verify a passport token.

#### `error(msg)`

#### `get_crypto()`

#### `get_passport_service()`

#### `get_translator()`

#### `header(msg)`

#### `info(msg)`

#### `main()`

#### `success(msg)`


---

## Receipts — Audit trail with hash chaining

`import` : `from aib.receipts import ...`


### `ActionReceipt`

Cryptographic proof of a single agent action.

**Constructor**: `ActionReceipt(receipt_id, passport_id, root_passport_id, action, status, timestamp, timestamp_unix, target_url, target_protocol, request_hash, request_method, response_hash, response_status, latency_ms, capabilities_used, delegation_depth, previous_hash, sequence_number, receipt_hash, signature, signing_key_id, metadata)`

- `to_dict()` → `<class 'dict'>`


### `ActionStatus`

**Constructor**: `ActionStatus(args, kwds)`


### `ActionType`

Types of actions that generate receipts.

**Constructor**: `ActionType(args, kwds)`


### `ReceiptStore`

Append-only store for Action Receipts with hash chaining.

- `emit(passport_id, action, status, target_url, target_protocol, request_body, response_body, request_method, response_status, latency_ms, capabilities_used, delegation_depth, root_passport_id, metadata)` → `<class 'aib.receipts.ActionReceipt'>`
- `export_json(receipts)` → `<class 'str'>`
- `get(receipt_id)` → `typing.Optional[aib.receipts.ActionReceipt]`
- `get_by_passport(passport_id, limit, action_filter)` → `list[aib.receipts.ActionReceipt]`
- `get_by_root(root_passport_id, limit)` → `list[aib.receipts.ActionReceipt]`
- `get_errors(limit)` → `list[aib.receipts.ActionReceipt]`
- `get_recent(limit)` → `list[aib.receipts.ActionReceipt]`
- `stats()` → `<class 'dict'>`
- `verify_chain()` → `tuple[bool, int, str]`

**Properties**: `count`, `last_hash`


### Functions

#### `compute_receipt_hash(receipt)` → `<class 'str'>`

Compute the canonical hash of a receipt.

#### `hash_content(content)` → `<class 'str'>`

SHA-256 hash of any content (string, bytes, dict, or None).


---

## Merkle — Merkle tree proofs

`import` : `from aib.merkle import ...`


### `AnchorChain`

Chain of Merkle Root anchors over time.

- `create_anchor(tree, metadata)` → `<class 'aib.merkle.MerkleAnchor'>`
- `export()` → `list[dict]`
- `verify_chain()` → `tuple[bool, int, str]`

**Properties**: `count`, `latest`


### `MerkleAnchor`

A timestamped Merkle Root that anchors the audit state.

**Constructor**: `MerkleAnchor(root_hash, tree_size, timestamp, anchor_id, previous_anchor_hash, metadata)`

- `to_dict()` → `<class 'dict'>`


### `MerkleProof`

Proof that a specific leaf exists in the tree.

**Constructor**: `MerkleProof(leaf_hash, leaf_index, steps, root_hash, tree_size)`

- `to_dict()` → `<class 'dict'>`
- `verify()` → `<class 'bool'>`


### `MerkleTree`

Merkle Tree for Action Receipt integrity proofs.

**Constructor**: `MerkleTree(leaves)`

- `add(leaf_hash)`
- `add_many(leaf_hashes)`
- `get_layer(level)` → `list[str]`
- `get_proof(index)` → `<class 'aib.merkle.MerkleProof'>`
- `verify_proof(proof)` → `<class 'bool'>`
- `verify_tree()` → `tuple[bool, str]`

**Properties**: `depth`, `root`, `size`


### Functions

#### `hash_pair(left, right)` → `<class 'str'>`

Hash two child nodes together to form a parent node.

#### `sha256(data)` → `<class 'str'>`

SHA-256 hash of a string, returns hex digest.


---

## Crypto — RSA key management, JWS signing

`import` : `from aib.crypto import ...`


### `KeyManager`

Manages RSA key rotation for passport signing.

**Constructor**: `KeyManager(keys_dir)`

- `get_key(kid)` → `typing.Optional[aib.crypto.SigningKey]`
- `jwks()` → `<class 'dict'>`
- `rotate()` → `<class 'aib.crypto.SigningKey'>`

**Properties**: `active_key`


### `PassportSigner`

Signs and verifies Agent Passports using RS256.

**Constructor**: `PassportSigner(key_manager)`

- `sign(payload)` → `<class 'str'>`
- `verify(token)` → `tuple[bool, typing.Optional[dict], str]`


### `SigningKey`

An RSA key pair with metadata.

**Constructor**: `SigningKey(kid, key_size, private_key)`

- `private_pem()` → `<class 'bytes'>`
- `public_pem()` → `<class 'bytes'>`
- `save(directory)`
- `to_jwk()` → `<class 'dict'>`

**Properties**: `private_key`, `public_key`


---

## Security — SSRF protection, input sanitization

`import` : `from aib.security import ...`


### `InputValidationError`

Raised when input fails sanitization.

**Constructor**: `InputValidationError(args, kwargs)`


### `RateLimiter`

Simple in-memory token bucket rate limiter.
Production: use Redis-based limiter.

**Constructor**: `RateLimiter(max_requests, window_seconds)`

- `check(key)` → `tuple[bool, int]`


### `URLValidationError`

Raised when a URL fails security validation.

**Constructor**: `URLValidationError(args, kwargs)`


### Functions

#### `is_private_ip(ip_str)` → `<class 'bool'>`

Check if an IP address is in a private/reserved range.

#### `resolve_and_check(hostname)` → `tuple[bool, str]`

Resolve a hostname and check if it points to a private IP.

#### `sanitize_agent_card(card)` → `<class 'dict'>`

Full sanitization of an A2A Agent Card or MCP Server Card.

#### `sanitize_array(items, field_name, max_items)` → `<class 'list'>`

Validate array length.

#### `sanitize_string(value, field_name, max_length)` → `<class 'str'>`

Sanitize a string field from an identity document.

#### `sanitize_url(url, field_name)` → `<class 'str'>`

Sanitize and validate a URL field.

#### `validate_document_size(document, max_bytes)` → `<class 'dict'>`

Check that a JSON document doesn't exceed size limits.

#### `validate_proxy_url(url, allowed_domains)` → `<class 'str'>`

Validate a URL for safe proxying. Blocks SSRF vectors.


---

## Rate Limiter — Per-tier request throttling

`import` : `from aib.rate_limiter import ...`


### `MemoryRateLimiter`

In-memory sliding window rate limiter.

**Constructor**: `MemoryRateLimiter(limits, window_seconds)`

- `check(key, tier)` → `<class 'aib.rate_limiter.RateLimitResult'>`
- `cleanup()`
- `get_all_keys()` → `list[str]`
- `get_usage(key, tier)` → `<class 'aib.rate_limiter.RateLimitResult'>`
- `reset(key)`
- `reset_all()`

**Properties**: `stats`


### `RateLimitResult`

Result of a rate limit check.

**Constructor**: `RateLimitResult(allowed, limit, remaining, window_seconds, reset_at, retry_after, tier, key)`

- `to_dict()` → `<class 'dict'>`
- `to_headers()` → `<class 'dict'>`


### `RateLimitTier`

**Constructor**: `RateLimitTier(args, kwds)`


### `RedisRateLimiterInterface`

Interface for Redis-based rate limiting.

- `check(key, tier)` → `<class 'aib.rate_limiter.RateLimitResult'>`
- `get_usage(key, tier)` → `<class 'aib.rate_limiter.RateLimitResult'>`
- `reset(key)`


---

## Schema Validator — JSON Schema enforcement

`import` : `from aib.schema_validator import ...`


### `SchemaValidationError`

Raised when a document fails schema validation.

**Constructor**: `SchemaValidationError(format_name, errors)`


### `SchemaValidator`

Validates protocol identity documents against JSON Schema.

**Constructor**: `SchemaValidator(strict)`

- `get_schema(name)` → `typing.Optional[dict]`
- `is_valid(format_name, document)` → `<class 'bool'>`
- `list_formats()` → `list[str]`
- `register_schema(name, schema)`
- `validate(format_name, document)` → `list[str]`
- `validate_or_raise(format_name, document)`
- `validate_translation(source, source_format, result, result_format)` → `<class 'dict'>`


---

## OIDC — OpenID Connect provider integration

`import` : `from aib.oidc import ...`


### `ClaimMapper`

Maps OIDC claims to AIB passport fields.

**Constructor**: `ClaimMapper(provider)`

- `extract_agent_id(claims)` → `<class 'str'>`
- `extract_capabilities(claims)` → `list[str]`
- `extract_display_name(claims)` → `<class 'str'>`
- `extract_protocols(claims)` → `list[str]`
- `map_to_passport_fields(claims)` → `<class 'dict'>`


### `ExchangeResult`

Result of an OIDC → AIB passport exchange.

**Constructor**: `ExchangeResult(success, error, org, agent_id, display_name, capabilities, protocols, protocol_bindings, tier, ttl_seconds, oidc_claims, oidc_issuer, oidc_subject, metadata)`


### `OIDCBridge`

The main integration point: exchange an OIDC token for an AIB passport.

**Constructor**: `OIDCBridge(provider)`

- `exchange(oidc_token, verify_signature, org_slug, tier, extra_metadata)` → `ExchangeResult`


### `OIDCProvider`

Configuration for an OIDC Identity Provider.

**Constructor**: `OIDCProvider(name, issuer_url, client_id, client_secret, authorization_endpoint, token_endpoint, jwks_uri, userinfo_endpoint, claim_mapping, default_protocols, default_tier, max_ttl_hours, allowed_audiences, metadata)`


### `OIDCTokenValidator`

Validates OIDC tokens from enterprise IdPs.

**Constructor**: `OIDCTokenValidator(provider)`

- `validate(token, verify_signature)` → `<class 'aib.oidc.ValidatedToken'>`


### `ValidatedToken`

Result of OIDC token validation.

**Constructor**: `ValidatedToken(valid, claims, error, issuer, subject, audience, expires_at)`


---

## Discovery — .well-known documents + Federation

`import` : `from aib.discovery import ...`


### `AIBDiscoveryDocument`

The main discovery document for an AIB-enabled organization.

**Constructor**: `AIBDiscoveryDocument(aib_version, issuer, domain, organization, supported_protocols, protocol_versions, gateway_url, passports_endpoint, translate_endpoint, proxy_endpoint, audit_endpoint, revocation_endpoint, jwks_uri, agents_uri, federation_uri, capabilities, features, signing_algorithms, key_rotation_days, multi_sig_policy, passport_tiers, oidc_providers, contact, documentation, published_at)`

- `to_dict()` → `<class 'dict'>`


### `AgentRegistry`

The public agent registry for an organization.

**Constructor**: `AgentRegistry(issuer, agents, updated_at)`

- `add(agent)`
- `get(passport_id)` → `typing.Optional[aib.discovery.PublicAgentEntry]`
- `remove(passport_id)` → `<class 'bool'>`
- `search(capability, protocol, status)` → `list[aib.discovery.PublicAgentEntry]`
- `to_dict()` → `<class 'dict'>`


### `DiscoveryService`

Manages all .well-known documents for an AIB gateway.

**Constructor**: `DiscoveryService(domain, org_slug, org_name, gateway_url, contact, documentation, supported_protocols)`

- `add_federation_trust(trust)`
- `get_agents()` → `<class 'dict'>`
- `get_all_documents(key_manager)` → `<class 'dict'>`
- `get_discovery()` → `<class 'dict'>`
- `get_federation()` → `<class 'dict'>`
- `get_jwks(key_manager)` → `<class 'dict'>`
- `get_jwks_uri_for_issuer(issuer)` → `typing.Optional[str]`
- `is_issuer_trusted(issuer)` → `tuple[bool, typing.Optional[aib.discovery.FederationTrust]]`
- `register_agent(agent)`
- `remove_federation_trust(domain)` → `<class 'bool'>`
- `search_agents(kwargs)` → `list[dict]`
- `unregister_agent(passport_id)` → `<class 'bool'>`


### `FederationDocument`

Federation configuration for cross-organization trust.

**Constructor**: `FederationDocument(issuer, domain, trusted_issuers, federation_policy, updated_at)`

- `add_trust(trust)`
- `get_jwks_uri(issuer)` → `typing.Optional[str]`
- `is_trusted(issuer)` → `tuple[bool, typing.Optional[aib.discovery.FederationTrust]]`
- `remove_trust(domain)` → `<class 'bool'>`
- `to_dict()` → `<class 'dict'>`


### `FederationTrust`

A trust relationship with another AIB-enabled organization.

**Constructor**: `FederationTrust(domain, issuer, jwks_uri, trusted_since, trust_level, protocols, notes)`

- `to_dict()` → `<class 'dict'>`


### `PublicAgentEntry`

A public entry in an organization's agent registry.

**Constructor**: `PublicAgentEntry(passport_id, display_name, description, capabilities, protocols, status, tier, public, contact, terms_of_service, rate_limit)`

- `to_dict()` → `<class 'dict'>`


---

## GDPR — Crypto-shredding, PII guard, consent management

`import` : `from aib.gdpr import ...`


### `ConsentManager`

Tracks legal basis for data processing.

- `export_consents(org_id)` → `list[dict]`
- `get_org_consents(org_id)` → `list[aib.gdpr.ConsentRecord]`
- `has_valid_consent(org_id, scope)` → `tuple[bool, str]`
- `record_consent(org_id, legal_basis, purpose, granted_by, scope, expires_at, metadata)` → `<class 'aib.gdpr.ConsentRecord'>`
- `revoke_consent(consent_id)` → `<class 'bool'>`


### `ConsentRecord`

Record of the legal basis for processing agent data.

**Constructor**: `ConsentRecord(consent_id, org_id, legal_basis, purpose, granted_at, granted_by, scope, expires_at, revoked, revoked_at, metadata)`

- `to_dict()` → `<class 'dict'>`


### `CryptoShredder`

Enables GDPR right-to-erasure without breaking audit hash chains.

**Constructor**: `CryptoShredder(keys_store)`

- `decrypt_field(org_id, ciphertext)` → `<class 'str'>`
- `decrypt_receipt(org_id, receipt_dict)` → `<class 'dict'>`
- `encrypt_field(org_id, plaintext)` → `<class 'str'>`
- `encrypt_receipt(org_id, receipt_dict)` → `<class 'dict'>`
- `get_or_create_key(org_id)` → `<class 'bytes'>`
- `is_shredded(org_id)` → `<class 'bool'>`
- `list_orgs()` → `<class 'dict'>`
- `shred(org_id)` → `<class 'bool'>`


### `DataExporter`

Export all data for an org in a portable, standard format.

- `compute_checksum(export)` → `<class 'str'>`
- `export_json(export)` → `<class 'str'>`
- `export_org(org_id, passports, receipts, translations, include_tokens)` → `<class 'dict'>`


### `LegalBasis`

GDPR Article 6 legal bases for processing.

**Constructor**: `LegalBasis(args, kwds)`


### `PIIGuard`

Prevents PII from entering passport metadata.

**Constructor**: `PIIGuard(strict)`

- `check(metadata)` → `tuple[bool, list[str]]`
- `sanitize(metadata)` → `<class 'dict'>`


### `PIIViolationError`

Raised when metadata contains PII.

**Constructor**: `PIIViolationError(args, kwargs)`


### `ShredError`

Raised when operating on a shredded org.

**Constructor**: `ShredError(args, kwargs)`


---

## Migration — Protocol addition/removal/migration

`import` : `from aib.migration import ...`


### `MigrationAction`

Types of protocol migration operations.

**Constructor**: `MigrationAction(args, kwds)`


### `MigrationError`

Raised when a migration operation is invalid.

**Constructor**: `MigrationError(args, kwargs)`


### `MigrationEvent`

Record of a protocol migration operation.

**Constructor**: `MigrationEvent(event_id, passport_id, action, protocol, timestamp, details, old_binding, new_binding, retired_at, retirement_reason, added_binding)`

- `to_dict()` → `<class 'dict'>`


### `PassportNotFoundError`

Raised when the passport doesn't exist.

**Constructor**: `PassportNotFoundError(args, kwargs)`


### `ProtocolAlreadyExistsError`

Raised when adding a protocol that already exists on the passport.

**Constructor**: `ProtocolAlreadyExistsError(args, kwargs)`


### `ProtocolMigrationManager`

Manages protocol migrations on live passports.

- `add_protocol(passport_id, protocol, binding, reason)` → `<class 'aib.migration.MigrationEvent'>`
- `export_migration_report(passport_id)` → `<class 'dict'>`
- `get_active_protocols(passport_id)` → `list[str]`
- `get_full_protocol_timeline(passport_id)` → `list[dict]`
- `get_history(passport_id)` → `list[aib.migration.MigrationEvent]`
- `get_retired(passport_id)` → `list[aib.migration.RetiredProtocol]`
- `migrate_protocol(passport_id, protocol, new_binding, reason)` → `<class 'aib.migration.MigrationEvent'>`
- `register(passport_id, passport)`
- `retire_protocol(passport_id, protocol, reason)` → `<class 'aib.migration.MigrationEvent'>`


### `ProtocolNotFoundError`

Raised when operating on a protocol that doesn't exist on the passport.

**Constructor**: `ProtocolNotFoundError(args, kwargs)`


### `RetiredProtocol`

Record of a retired protocol binding.

**Constructor**: `RetiredProtocol(protocol, binding, retired_at, reason, active_from, active_until, receipt_count)`


---

## Plugins — Protocol binding extensions

`import` : `from aib.plugins import ...`


### `A2aBinding`

Built-in A2A (Agent-to-Agent) binding.

- `detect_protocol(url)` → `<class 'bool'>`
- `from_passport_binding(binding)` → `<class 'dict'>`
- `health_check(endpoint_url)` → `tuple[bool, str]`
- `to_passport_binding(native_card)` → `<class 'dict'>`
- `translate_from(native_card)` → `<class 'dict'>`
- `translate_to(source, source_format)` → `<class 'dict'>`
- `validate_card(card)` → `tuple[bool, str]`


### `AgUiBinding`

Built-in AG-UI (Agent-User Interface) binding.

- `detect_protocol(url)` → `<class 'bool'>`
- `from_passport_binding(binding)` → `<class 'dict'>`
- `health_check(endpoint_url)` → `tuple[bool, str]`
- `to_passport_binding(native_card)` → `<class 'dict'>`
- `translate_from(native_card)` → `<class 'dict'>`
- `translate_to(source, source_format)` → `<class 'dict'>`
- `validate_card(card)` → `tuple[bool, str]`


### `AnpBinding`

Built-in ANP (Agent Network Protocol) binding.

- `detect_protocol(url)` → `<class 'bool'>`
- `from_passport_binding(binding)` → `<class 'dict'>`
- `health_check(endpoint_url)` → `tuple[bool, str]`
- `to_passport_binding(native_card)` → `<class 'dict'>`
- `translate_from(native_card)` → `<class 'dict'>`
- `translate_to(source, source_format)` → `<class 'dict'>`
- `validate_card(card)` → `tuple[bool, str]`


### `McpBinding`

Built-in MCP (Model Context Protocol) binding.

- `detect_protocol(url)` → `<class 'bool'>`
- `from_passport_binding(binding)` → `<class 'dict'>`
- `health_check(endpoint_url)` → `tuple[bool, str]`
- `to_passport_binding(native_card)` → `<class 'dict'>`
- `translate_from(native_card)` → `<class 'dict'>`
- `translate_to(source, source_format)` → `<class 'dict'>`
- `validate_card(card)` → `tuple[bool, str]`


### `PluginRegistry`

Registry for protocol bindings with auto-discovery.

**Constructor**: `PluginRegistry(auto_discover)`

- `auto_discover()`
- `detect(url)` → `typing.Optional[str]`
- `get(protocol_name)` → `typing.Optional[aib.plugins.ProtocolBinding]`
- `list_protocols()` → `list[dict]`
- `register(binding)`
- `supported_protocols()` → `list[str]`
- `unregister(protocol_name)` → `<class 'bool'>`

**Properties**: `count`


### `ProtocolBinding`

Abstract base class for protocol bindings.

- `detect_protocol(url)` → `<class 'bool'>`
- `from_passport_binding(binding)` → `<class 'dict'>`
- `health_check(endpoint_url)` → `tuple[bool, str]`
- `to_passport_binding(native_card)` → `<class 'dict'>`
- `translate_from(native_card)` → `<class 'dict'>`
- `translate_to(source, source_format)` → `<class 'dict'>`
- `validate_card(card)` → `tuple[bool, str]`


---

## Error Codes — AIB-xxx error code registry

`import` : `from aib.hardening_sprint1 import ...`


### `AIBError`

Standardized error response.

**Constructor**: `AIBError(code, message, detail, http_status)`

- `to_log()` → `<class 'dict'>`
- `to_response()` → `<class 'dict'>`


### `AudienceError`

Raised when passport audience doesn't match expected domain.

**Constructor**: `AudienceError(args, kwargs)`


### `ChildrenLimiter`

Tracks and enforces maximum children per passport.

**Constructor**: `ChildrenLimiter(limits)`

- `check_can_delegate(parent_id, parent_tier)` → `tuple[bool, str]`
- `get_count(parent_id)` → `<class 'int'>`
- `get_limit(tier)` → `<class 'int'>`
- `get_usage(parent_id, tier)` → `<class 'dict'>`
- `record_child(parent_id)`
- `remove_child(parent_id)`


### `DNSRebindingError`

Raised when DNS rebinding is detected.

**Constructor**: `DNSRebindingError(args, kwargs)`


### `ErrorCodes`

Centralized error code registry.


### `MaxChildrenExceededError`

Raised when a passport exceeds its maximum children count.

**Constructor**: `MaxChildrenExceededError(args, kwargs)`


### Functions

#### `double_dns_check(hostname)` → `tuple[bool, str]`

Double DNS resolution to prevent TOCTOU/DNS rebinding.

#### `get_jwt_decode_options(leeway_seconds, require_claims)` → `<class 'dict'>`

Build JWT decode options with clock skew tolerance.

#### `inject_audience(payload, audiences)` → `<class 'dict'>`

Inject audience claim into a passport payload before signing.

#### `make_error(template, detail)` → `<class 'aib.hardening_sprint1.AIBError'>`

Create an error instance from a template with specific detail.

#### `verify_audience(payload, expected_audience)` → `tuple[bool, str]`

Verify the audience claim in a passport payload.


---

## Enterprise — Circuit breaker, CRL, multi-algorithm

`import` : `from aib.sprint5_enterprise import ...`


### `AlgorithmProfile`

Properties of a signing algorithm.

**Constructor**: `AlgorithmProfile(name, algorithm, key_size_bits, signature_size_bytes, speed, compatibility, recommended_for)`

- `to_dict()` → `<class 'dict'>`


### `AlgorithmRegistry`

Registry of supported signing algorithms.

**Constructor**: `AlgorithmRegistry(default, accepted)`

- `get_profile(algo)` → `<class 'aib.sprint5_enterprise.AlgorithmProfile'>`
- `is_accepted(algo)` → `<class 'bool'>`
- `list_accepted()` → `list[dict]`
- `set_accepted(algos)`
- `set_default(algo)`
- `validate_algorithm(algo_str)` → `tuple[bool, str]`

**Properties**: `default`


### `CRLEntry`

A single revocation entry in the CRL.

**Constructor**: `CRLEntry(passport_id, revoked_at, reason)`

- `to_dict()` → `<class 'dict'>`


### `CircuitBreaker`

Circuit breaker pattern per target URL/host.

**Constructor**: `CircuitBreaker(failure_threshold, recovery_timeout, success_threshold)`

- `allow_request(target)` → `<class 'bool'>`
- `get_state(target)` → `<enum 'CircuitState'>`
- `get_stats(target)` → `typing.Optional[dict]`
- `list_open_circuits()` → `list[str]`
- `record_failure(target)`
- `record_success(target)`
- `reset(target)`

**Properties**: `total_circuits`


### `CircuitBreakerError`

Raised when circuit is open and request is blocked.

**Constructor**: `CircuitBreakerError(args, kwargs)`


### `CircuitState`

**Constructor**: `CircuitState(args, kwds)`


### `CircuitStats`

Statistics for a single circuit.

**Constructor**: `CircuitStats(target, state, failures, successes, last_failure_at, last_success_at, opened_at, half_open_attempts)`

- `to_dict()` → `<class 'dict'>`


### `SignedCRL`

Signed Certificate Revocation List.

**Constructor**: `SignedCRL(issuer)`

- `check_batch(passport_ids)` → `dict[str, bool]`
- `get_entry(passport_id)` → `typing.Optional[dict]`
- `is_revoked(passport_id)` → `<class 'bool'>`
- `list_revoked()` → `list[str]`
- `revoke(passport_id, reason)`
- `to_document()` → `<class 'dict'>`
- `unrevoke(passport_id)` → `<class 'bool'>`

**Properties**: `count`, `version`


### `SigningAlgorithm`

**Constructor**: `SigningAlgorithm(args, kwds)`


---

## Security Final — Signed discovery, PKCE, OTel, Shamir

`import` : `from aib.sprint6_final import ...`


### `KeyCeremony`

Manages Shamir key splitting/reconstruction ceremonies.

- `reconstruct(shares, key_length, participants)` → `<class 'bytes'>`
- `split(secret, shares_needed, total_shares, participants)` → `list[tuple[int, int]]`

**Properties**: `ceremony_count`, `records`


### `KeyCeremonyRecord`

Record of a key ceremony event.

**Constructor**: `KeyCeremonyRecord(ceremony_id, action, shares_needed, total_shares, timestamp, participants, success, detail)`

- `to_dict()` → `<class 'dict'>`


### `PKCEManager`

Manages PKCE sessions for OIDC token exchanges.

**Constructor**: `PKCEManager(ttl_seconds)`

- `cleanup_expired()` → `<class 'int'>`
- `create_session(method)` → `<class 'aib.sprint6_final.PKCESession'>`
- `get_session(session_id)` → `typing.Optional[dict]`
- `verify_and_consume(session_id, code_verifier)` → `<class 'bool'>`

**Properties**: `active_count`


### `PKCESession`

Tracks a PKCE session through the OAuth2 flow.

**Constructor**: `PKCESession(session_id, code_verifier, code_challenge, method, created_at, state)`

- `to_dict()` → `<class 'dict'>`


### `SignedDocumentError`

Raised when a signed document fails verification.

**Constructor**: `SignedDocumentError(args, kwargs)`


### `TraceContext`

W3C Trace Context (simplified) for OpenTelemetry compatibility.

**Constructor**: `TraceContext(trace_id, span_id, parent_span_id, flags, passport_id, protocol)`

- `to_dict()` → `<class 'dict'>`
- `to_headers()` → `<class 'dict'>`
- `to_traceparent()` → `<class 'str'>`
- `to_tracestate()` → `<class 'str'>`


### Functions

#### `generate_code_challenge(verifier, method)` → `<class 'str'>`

Generate a PKCE code_challenge from a code_verifier.

#### `generate_code_verifier(length)` → `<class 'str'>`

Generate a PKCE code_verifier (RFC 7636).

#### `new_trace_context(passport_id, protocol, parent)` → `<class 'aib.sprint6_final.TraceContext'>`

Create a new trace context, optionally as child of a parent.

#### `parse_traceparent(header)` → `typing.Optional[aib.sprint6_final.TraceContext]`

Parse a W3C traceparent header.

#### `reconstruct_secret(shares, secret_length)` → `<class 'bytes'>`

Reconstruct a secret from K shares using Lagrange interpolation.

#### `sign_discovery_document(document, secret_key)` → `<class 'dict'>`

Sign a discovery document (/.well-known/aib.json) with HMAC-SHA256.

#### `split_secret(secret, shares_needed, total_shares)` → `list[tuple[int, int]]`

Split a secret into N shares where K are needed to reconstruct.

#### `verify_pkce(code_verifier, code_challenge, method)` → `<class 'bool'>`

Verify a PKCE code_verifier against the stored code_challenge.

#### `verify_signed_document(signed_doc, secret_key)` → `tuple[bool, str]`

Verify a signed discovery document.
