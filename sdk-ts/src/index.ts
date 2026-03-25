/**
 * Agent Identity Bridge — TypeScript SDK
 *
 * Portable identity for AI agents across MCP, A2A, ANP, AG-UI.
 *
 * Usage:
 *   import { AIBClient, Translator } from 'agent-identity-bridge';
 */

export { AIBClient, AIBError } from "./client";
export type { AIBClientOptions } from "./client";

export { Translator } from "./translator";

export type {
  AgentPassport,
  CreatePassportRequest,
  PassportResponse,
  VerifyResult,
  TranslationFormat,
  TranslateRequest,
  TranslateResponse,
  GatewayRequest,
  GatewayResponse,
  SendResult,
  HealthResponse,
  AuditEntry,
  AuditQueryResponse,
  McpBinding,
  A2aBinding,
  AnpBinding,
  AgUiBinding,
  ProtocolBindings,
  PassportTier,
} from "./types";
