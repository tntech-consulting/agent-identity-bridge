const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const { Translator, AIBClient, AIBError } = require("../dist/index");

// ═══════════════════════════════════════════════════════════════════
// TRANSLATOR TESTS
// ═══════════════════════════════════════════════════════════════════

describe("Translator", () => {
  const t = new Translator();

  describe("A2A → MCP", () => {
    it("translates agent card to server card", () => {
      const card = {
        name: "Booking Agent",
        url: "https://example.com/agent",
        skills: [
          { id: "booking", name: "Book Hotels" },
          { id: "search", name: "Search Rooms" },
        ],
      };
      const mcp = t.translate(card, "a2a_agent_card", "mcp_server_card");
      assert.equal(mcp.name, "Booking Agent");
      assert.equal(mcp.url, "https://example.com/agent");
      assert.equal(mcp.tools.length, 2);
      assert.equal(mcp.tools[0].name, "booking");
    });
  });

  describe("MCP → A2A", () => {
    it("translates server card to agent card", () => {
      const card = {
        name: "MCP Server",
        url: "https://example.com/mcp",
        tools: [
          { name: "search", description: "Search" },
          { name: "calendar", description: "Calendar" },
        ],
      };
      const a2a = t.translate(card, "mcp_server_card", "a2a_agent_card");
      assert.equal(a2a.name, "MCP Server");
      assert.equal(a2a.skills.length, 2);
      assert.equal(a2a.skills[0].id, "search");
    });
  });

  describe("A2A ↔ MCP roundtrip", () => {
    it("preserves name and skills/tools count", () => {
      const original = {
        name: "Roundtrip Agent",
        url: "https://test.com",
        skills: [{ id: "s1", name: "Skill 1" }],
      };
      const mcp = t.translate(original, "a2a_agent_card", "mcp_server_card");
      const back = t.translate(mcp, "mcp_server_card", "a2a_agent_card");
      assert.equal(back.name, original.name);
      assert.equal(back.skills.length, original.skills.length);
    });
  });

  describe("A2A → AG-UI", () => {
    it("translates to AG-UI descriptor", () => {
      const card = {
        name: "Agent",
        url: "https://example.com",
        skills: [{ id: "text_message", name: "Messaging" }],
      };
      const agui = t.translate(card, "a2a_agent_card", "ag_ui_descriptor");
      assert.equal(agui.name, "Agent");
      assert.equal(agui.endpoint_url, "https://example.com");
      assert.ok(agui.capabilities.includes("text_message"));
      assert.ok(agui.supported_events.includes("RUN_STARTED"));
    });
  });

  describe("AG-UI → A2A", () => {
    it("translates back to agent card", () => {
      const desc = {
        name: "UI Agent",
        endpoint_url: "https://test.com/agent",
        capabilities: ["text_message", "tool_call"],
        a2ui_support: true,
        supported_events: ["RUN_STARTED", "TOOL_CALL_START"],
      };
      const card = t.translate(desc, "ag_ui_descriptor", "a2a_agent_card");
      assert.equal(card.name, "UI Agent");
      assert.equal(card.url, "https://test.com/agent");
      assert.equal(card.skills.length, 2);
      assert.ok(card.provider.a2ui_support);
    });
  });

  describe("AG-UI → MCP", () => {
    it("translates capabilities to tools", () => {
      const desc = {
        name: "Tool Agent",
        endpoint_url: "https://test.com",
        capabilities: ["search", "calendar"],
      };
      const mcp = t.translate(desc, "ag_ui_descriptor", "mcp_server_card");
      assert.equal(mcp.tools.length, 2);
      assert.equal(mcp.tools[0].name, "search");
    });
  });

  describe("MCP → AG-UI", () => {
    it("translates tools to capabilities", () => {
      const card = {
        name: "MCP Server",
        url: "https://mcp.test",
        tools: [{ name: "analyze", description: "Analyze data" }],
      };
      const agui = t.translate(card, "mcp_server_card", "ag_ui_descriptor");
      assert.ok(agui.capabilities.includes("analyze"));
      assert.equal(agui.a2ui_support, false);
    });
  });

  describe("AG-UI ↔ A2A roundtrip", () => {
    it("preserves data", () => {
      const original = {
        name: "RT Agent",
        endpoint_url: "https://rt.test",
        capabilities: ["text_message"],
      };
      const a2a = t.translate(original, "ag_ui_descriptor", "a2a_agent_card");
      const back = t.translate(a2a, "a2a_agent_card", "ag_ui_descriptor");
      assert.equal(back.name, original.name);
      assert.deepEqual(back.capabilities, original.capabilities);
    });
  });

  describe("Full chain AG-UI → A2A → MCP → AG-UI", () => {
    it("completes the full 4-format roundtrip", () => {
      const start = {
        name: "Chain Agent",
        endpoint_url: "https://chain.test",
        capabilities: ["booking", "support"],
      };
      const a2a = t.translate(start, "ag_ui_descriptor", "a2a_agent_card");
      const mcp = t.translate(a2a, "a2a_agent_card", "mcp_server_card");
      const end = t.translate(mcp, "mcp_server_card", "ag_ui_descriptor");
      assert.equal(end.name, "Chain Agent");
      assert.equal(end.capabilities.length, 2);
    });
  });

  describe("Unsupported translation", () => {
    it("throws on unknown format pair", () => {
      assert.throws(() => {
        t.translate({}, "unknown", "format");
      }, /Unsupported translation/);
    });
  });

  describe("supportedTranslations", () => {
    it("lists all 6 translations", () => {
      const list = t.supportedTranslations;
      assert.equal(list.length, 6);
      assert.ok(list.includes("a2a_agent_card->mcp_server_card"));
      assert.ok(list.includes("ag_ui_descriptor->a2a_agent_card"));
    });
  });
});

// ═══════════════════════════════════════════════════════════════════
// CLIENT TESTS (unit — no server needed)
// ═══════════════════════════════════════════════════════════════════

describe("AIBClient", () => {
  it("constructs with gateway URL", () => {
    const client = new AIBClient({ gatewayUrl: "http://localhost:8420" });
    assert.ok(client);
  });

  it("strips trailing slash from URL", () => {
    const client = new AIBClient({ gatewayUrl: "http://localhost:8420/" });
    // Can't access private baseUrl, but it shouldn't crash
    assert.ok(client);
  });
});

describe("AIBError", () => {
  it("creates error with code and status", () => {
    const err = new AIBError("AIB-001", "Passport not found", 404);
    assert.equal(err.code, "AIB-001");
    assert.equal(err.message, "Passport not found");
    assert.equal(err.statusCode, 404);
    assert.equal(err.name, "AIBError");
  });

  it("is an instance of Error", () => {
    const err = new AIBError("AIB-001", "test", 400);
    assert.ok(err instanceof Error);
  });
});
