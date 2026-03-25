/**
 * AIB TypeScript SDK — Local Credential Translator.
 *
 * Translates between A2A Agent Cards, MCP Server Cards,
 * and AG-UI Descriptors without needing a running gateway.
 *
 * Usage:
 *   import { Translator } from 'agent-identity-bridge';
 *
 *   const t = new Translator();
 *   const mcpCard = t.translate(agentCard, 'a2a_agent_card', 'mcp_server_card');
 */

import type { TranslationFormat } from "./types";

type TranslationFn = (source: Record<string, any>) => Record<string, any>;

export class Translator {
  private translations: Map<string, TranslationFn>;

  constructor() {
    this.translations = new Map();
    this.translations.set("a2a_agent_card->mcp_server_card", this.a2aToMcp);
    this.translations.set("mcp_server_card->a2a_agent_card", this.mcpToA2a);
    this.translations.set("a2a_agent_card->ag_ui_descriptor", this.a2aToAgUi);
    this.translations.set("ag_ui_descriptor->a2a_agent_card", this.agUiToA2a);
    this.translations.set("ag_ui_descriptor->mcp_server_card", this.agUiToMcp);
    this.translations.set("mcp_server_card->ag_ui_descriptor", this.mcpToAgUi);
  }

  translate(
    source: Record<string, any>,
    fromFormat: TranslationFormat,
    toFormat: TranslationFormat,
  ): Record<string, any> {
    const key = `${fromFormat}->${toFormat}`;
    const fn = this.translations.get(key);
    if (!fn) {
      throw new Error(
        `Unsupported translation: ${key}. Supported: ${[...this.translations.keys()].join(", ")}`,
      );
    }
    return fn(source);
  }

  get supportedTranslations(): string[] {
    return [...this.translations.keys()];
  }

  // ─── A2A ↔ MCP ──────────────────────────────────────────────

  private a2aToMcp(source: Record<string, any>): Record<string, any> {
    const tools = (source.skills || []).map((s: any) => ({
      name: s.id || s.name || "unknown",
      description: s.name || s.id || "",
    }));
    return {
      name: source.name || "",
      url: source.url || "",
      description: source.description || "",
      tools,
    };
  }

  private mcpToA2a(source: Record<string, any>): Record<string, any> {
    const skills = (source.tools || []).map((t: any) => ({
      id: t.name || "unknown",
      name: t.description || t.name || "",
    }));
    return {
      name: source.name || "",
      url: source.url || "",
      description: source.description || "",
      skills,
    };
  }

  // ─── A2A ↔ AG-UI ────────────────────────────────────────────

  private a2aToAgUi(source: Record<string, any>): Record<string, any> {
    const capabilities = (source.skills || []).map(
      (s: any) => s.id || s.name || "unknown",
    );
    const provider = source.provider || {};
    return {
      ag_ui_version: "1.0",
      name: source.name || "",
      description: source.description || "",
      endpoint_url: source.url || "",
      capabilities,
      supported_events: provider.ag_ui_events || [
        "RUN_STARTED", "RUN_FINISHED",
        "TEXT_MESSAGE_START", "TEXT_MESSAGE_CONTENT", "TEXT_MESSAGE_END",
      ],
      a2ui_support: provider.a2ui_support || false,
      shared_state: provider.shared_state || false,
      metadata: {},
    };
  }

  private agUiToA2a(source: Record<string, any>): Record<string, any> {
    const skills = (source.capabilities || []).map((c: string) => ({
      id: c,
      name: c.replace(/_/g, " ").replace(/\b\w/g, (l: string) => l.toUpperCase()),
    }));
    const card: Record<string, any> = {
      name: source.name || "",
      url: source.endpoint_url || "",
      description: source.description || "",
      skills,
    };
    const provider: Record<string, any> = {};
    if (source.a2ui_support) provider.a2ui_support = true;
    if (source.shared_state) provider.shared_state = true;
    if (source.supported_events?.length) {
      provider.ag_ui_events = source.supported_events;
    }
    if (Object.keys(provider).length > 0) card.provider = provider;
    return card;
  }

  // ─── AG-UI ↔ MCP ────────────────────────────────────────────

  private agUiToMcp(source: Record<string, any>): Record<string, any> {
    const tools = (source.capabilities || []).map((c: string) => ({
      name: c,
      description: c.replace(/_/g, " ").replace(/\b\w/g, (l: string) => l.toUpperCase()),
    }));
    return {
      name: source.name || "",
      url: source.endpoint_url || "",
      description: source.description || "",
      tools,
    };
  }

  private mcpToAgUi(source: Record<string, any>): Record<string, any> {
    const capabilities = (source.tools || []).map(
      (t: any) => t.name || "unknown",
    );
    return {
      ag_ui_version: "1.0",
      name: source.name || "",
      description: source.description || "",
      endpoint_url: source.url || "",
      capabilities,
      supported_events: [
        "RUN_STARTED", "RUN_FINISHED",
        "TEXT_MESSAGE_START", "TEXT_MESSAGE_CONTENT", "TEXT_MESSAGE_END",
      ],
      a2ui_support: false,
      shared_state: false,
      metadata: {},
    };
  }
}
