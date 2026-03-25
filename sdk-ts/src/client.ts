/**
 * AIB TypeScript SDK — Client.
 *
 * Usage:
 *   import { AIBClient } from 'agent-identity-bridge';
 *
 *   const client = new AIBClient({ gatewayUrl: 'http://localhost:8420' });
 *
 *   const { passport, token } = await client.createPassport({
 *     org_slug: 'mycompany',
 *     agent_slug: 'booking',
 *     display_name: 'Booking Agent',
 *     capabilities: ['booking'],
 *     bindings: { mcp: { auth_method: 'oauth2', server_card_url: '...' } },
 *   });
 *
 *   const result = await client.send('urn:aib:agent:mycompany:booking',
 *     'https://partner.com/a2a/send', { task: 'Book 3pm' });
 */

import type {
  CreatePassportRequest,
  PassportResponse,
  VerifyResult,
  TranslationFormat,
  TranslateResponse,
  SendResult,
  HealthResponse,
  AuditQueryResponse,
  AgentPassport,
} from "./types";

export interface AIBClientOptions {
  gatewayUrl: string;
  apiKey?: string;
  timeout?: number;
}

export class AIBClient {
  private baseUrl: string;
  private apiKey: string;
  private timeout: number;

  constructor(options: AIBClientOptions) {
    this.baseUrl = options.gatewayUrl.replace(/\/$/, "");
    this.apiKey = options.apiKey || "";
    this.timeout = options.timeout || 30000;
  }

  // ─── Internal fetch ────────────────────────────────────────────

  private async request<T>(
    method: string,
    path: string,
    body?: any,
  ): Promise<T> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (this.apiKey) {
      headers["Authorization"] = `Bearer ${this.apiKey}`;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const res = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      const data = await res.json();

      if (!res.ok) {
        throw new AIBError(
          data?.error?.code || `HTTP_${res.status}`,
          data?.error?.message || res.statusText,
          res.status,
        );
      }

      return data as T;
    } finally {
      clearTimeout(timer);
    }
  }

  // ─── Health ────────────────────────────────────────────────────

  async health(): Promise<HealthResponse> {
    return this.request<HealthResponse>("GET", "/");
  }

  // ─── Passports ─────────────────────────────────────────────────

  async createPassport(req: CreatePassportRequest): Promise<PassportResponse> {
    return this.request<PassportResponse>("POST", "/passports", req);
  }

  async listPassports(): Promise<AgentPassport[]> {
    const res = await this.request<{ passports: AgentPassport[] }>(
      "GET",
      "/passports",
    );
    return res.passports;
  }

  async getPassport(passportId: string): Promise<PassportResponse> {
    const encoded = encodeURIComponent(passportId);
    return this.request<PassportResponse>("GET", `/passports/${encoded}`);
  }

  async revokePassport(passportId: string): Promise<{ status: string }> {
    const encoded = encodeURIComponent(passportId);
    return this.request<{ status: string }>("DELETE", `/passports/${encoded}`);
  }

  // ─── Translation ───────────────────────────────────────────────

  async translate(
    source: Record<string, any>,
    fromFormat: TranslationFormat,
    toFormat: TranslationFormat,
    options?: { domain?: string; agent_slug?: string },
  ): Promise<TranslateResponse> {
    return this.request<TranslateResponse>("POST", "/translate", {
      source,
      from_format: fromFormat,
      to_format: toFormat,
      domain: options?.domain,
      agent_slug: options?.agent_slug,
    });
  }

  // ─── Gateway Proxy ─────────────────────────────────────────────

  async send(
    passportId: string,
    targetUrl: string,
    body?: Record<string, any>,
    options?: { method?: string; headers?: Record<string, string> },
  ): Promise<SendResult> {
    const start = Date.now();

    const res = await this.request<{
      status_code: number;
      body: any;
      audit_trace_id: string;
      protocol_used: string;
    }>("POST", "/gateway/proxy", {
      passport_id: passportId,
      target_url: targetUrl,
      method: options?.method || "POST",
      body: body || {},
      headers: options?.headers || {},
    });

    return {
      success: res.status_code >= 200 && res.status_code < 300,
      protocol: res.protocol_used,
      trace_id: res.audit_trace_id,
      status_code: res.status_code,
      data: res.body,
      latency_ms: Date.now() - start,
    };
  }

  // ─── Audit ─────────────────────────────────────────────────────

  async getAuditTrail(
    passportId: string,
    options?: { protocol?: string; action?: string; limit?: number },
  ): Promise<AuditQueryResponse> {
    const encoded = encodeURIComponent(passportId);
    const params = new URLSearchParams();
    if (options?.protocol) params.set("protocol", options.protocol);
    if (options?.action) params.set("action", options.action);
    if (options?.limit) params.set("limit", String(options.limit));
    const qs = params.toString();
    return this.request<AuditQueryResponse>(
      "GET",
      `/audit/${encoded}${qs ? `?${qs}` : ""}`,
    );
  }

  // ─── Discovery ─────────────────────────────────────────────────

  async getDiscovery(): Promise<Record<string, any>> {
    return this.request<Record<string, any>>("GET", "/.well-known/aib.json");
  }

  async getJWKS(): Promise<Record<string, any>> {
    return this.request<Record<string, any>>(
      "GET",
      "/.well-known/aib-keys.json",
    );
  }
}

// ─── Error class ─────────────────────────────────────────────────

export class AIBError extends Error {
  code: string;
  statusCode: number;

  constructor(code: string, message: string, statusCode: number) {
    super(message);
    this.name = "AIBError";
    this.code = code;
    this.statusCode = statusCode;
  }
}
