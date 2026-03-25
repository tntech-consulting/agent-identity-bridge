# Agent Identity Bridge — TypeScript SDK

Portable identity for AI agents across MCP, A2A, ANP, AG-UI.

## Install

```bash
npm install agent-identity-bridge
```

## Quick start

### Local translation (no server needed)

```typescript
import { Translator } from 'agent-identity-bridge';

const t = new Translator();

// A2A Agent Card → MCP Server Card
const mcpCard = t.translate(agentCard, 'a2a_agent_card', 'mcp_server_card');

// AG-UI → A2A → MCP (chain)
const a2a = t.translate(agUiDesc, 'ag_ui_descriptor', 'a2a_agent_card');
const mcp = t.translate(a2a, 'a2a_agent_card', 'mcp_server_card');
```

### Gateway client

```typescript
import { AIBClient } from 'agent-identity-bridge';

const client = new AIBClient({ gatewayUrl: 'http://localhost:8420' });

// Create passport
const { passport, token } = await client.createPassport({
  org_slug: 'mycompany',
  agent_slug: 'booking',
  display_name: 'Booking Agent',
  capabilities: ['booking', 'scheduling'],
  bindings: {
    mcp: { auth_method: 'oauth2', server_card_url: 'https://...' },
    a2a: { auth_method: 'bearer', agent_card_url: 'https://...' },
  },
});

// Proxy request
const result = await client.send(
  passport.passport_id,
  'https://partner.com/a2a/send',
  { task: 'Book 3pm tomorrow' },
);

console.log(result.protocol);  // "a2a"
console.log(result.trace_id);  // "aib_7f3a...b2c1"
```

## Supported translations

| From | To | Direction |
|------|----|-----------|
| A2A Agent Card | MCP Server Card | ↔ |
| A2A Agent Card | AG-UI Descriptor | ↔ |
| AG-UI Descriptor | MCP Server Card | ↔ |

## License

Apache 2.0
