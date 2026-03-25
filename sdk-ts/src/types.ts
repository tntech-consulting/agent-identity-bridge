/**
 * AIB TypeScript SDK — Type definitions.
 *
 * All types for Agent Passports, protocol bindings, translations,
 * and gateway responses.
 */

// ─── Protocol Bindings ───────────────────────────────────────────

export interface McpBinding {
  auth_method: string;
  server_card_url: string;
  credential_ref?: string;
  scopes?: string[];
}

export interface A2aBinding {
  auth_method: string;
  agent_card_url: string;
  credential_ref?: string;
  skills?: string[];
}

export interface AnpBinding {
  auth_method: string;
  did: string;
  credential_ref?: string;
}

export interface AgUiBinding {
  auth_method: string;
  endpoint_url: string;
  credential_ref?: string;
  ui_capabilities?: string[];
  supported_events?: string[];
  a2ui_support?: boolean;
  shared_state?: boolean;
}

export interface ProtocolBindings {
  mcp?: McpBinding;
  a2a?: A2aBinding;
  anp?: AnpBinding;
  ag_ui?: AgUiBinding;
}

// ─── Agent Passport ──────────────────────────────────────────────

export type PassportTier = "permanent" | "session" | "ephemeral";

export interface AgentPassport {
  aib_version: string;
  passport_id: string;
  display_name: string;
  issuer: string;
  capabilities: string[];
  protocol_bindings: Record<string, any>;
  tier: PassportTier;
  issued_at: string;
  expires_at: string;
  delegation?: {
    parent_id: string;
    max_depth: number;
    delegation_depth: number;
  };
  metadata?: Record<string, string>;
}

export interface CreatePassportRequest {
  org_slug: string;
  agent_slug: string;
  display_name: string;
  capabilities: string[];
  bindings: ProtocolBindings;
  tier?: PassportTier;
  ttl_hours?: number;
  metadata?: Record<string, string>;
}

export interface PassportResponse {
  passport: AgentPassport;
  token: string;
}

export interface VerifyResult {
  valid: boolean;
  payload?: AgentPassport;
  reason: string;
}

// ─── Translation ─────────────────────────────────────────────────

export type TranslationFormat =
  | "a2a_agent_card"
  | "mcp_server_card"
  | "did_document"
  | "ag_ui_descriptor";

export interface TranslateRequest {
  source: Record<string, any>;
  from_format: TranslationFormat;
  to_format: TranslationFormat;
  domain?: string;
  agent_slug?: string;
}

export interface TranslateResponse {
  from_format: string;
  to_format: string;
  result: Record<string, any>;
  translated_at: string;
}

// ─── Gateway ─────────────────────────────────────────────────────

export interface GatewayRequest {
  passport_id: string;
  target_url: string;
  method?: string;
  body?: Record<string, any>;
  headers?: Record<string, string>;
}

export interface GatewayResponse {
  status_code: number;
  body: any;
  headers: Record<string, string>;
  audit_trace_id: string;
  protocol_used: string;
}

export interface SendResult {
  success: boolean;
  protocol: string;
  trace_id: string;
  status_code: number;
  data: any;
  latency_ms: number;
}

// ─── Health ──────────────────────────────────────────────────────

export interface HealthResponse {
  status: string;
  version: string;
  passports_count: number;
  supported_protocols: string[];
}

// ─── Audit ───────────────────────────────────────────────────────

export interface AuditEntry {
  trace_id: string;
  passport_id: string;
  action: string;
  protocol: string;
  target_url: string;
  timestamp: string;
  status: string;
  latency_ms: number;
}

export interface AuditQueryResponse {
  passport_id: string;
  total_entries: number;
  entries: AuditEntry[];
}
