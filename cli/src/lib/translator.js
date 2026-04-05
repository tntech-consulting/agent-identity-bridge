const PROTOCOL_FORMATS = {
  mcp: {
    name: 'Model Context Protocol',
    card_field: 'mcp_server_card',
    tool_wrapper: 'tools',
  },
  a2a: {
    name: 'Agent-to-Agent Protocol',
    card_field: 'a2a_agent_card',
    tool_wrapper: 'skills',
  },
  'ag-ui': {
    name: 'AG-UI Protocol',
    card_field: 'ag_ui_manifest',
    tool_wrapper: 'actions',
  },
};

export function translate(passport, fromProtocol, toProtocol) {
  if (!PROTOCOL_FORMATS[fromProtocol]) throw new Error(`Unknown source protocol: ${fromProtocol}`);
  if (!PROTOCOL_FORMATS[toProtocol]) throw new Error(`Unknown target protocol: ${toProtocol}`);
  if (fromProtocol === toProtocol) return { protocol: toProtocol, note: 'Same protocol, no translation needed' };

  const base = {
    id: passport.passport_id,
    did: passport.did,
    agent: passport.agent.name,
    capabilities: passport.capabilities,
    signature: passport.signature,
    public_key: passport.public_key,
  };

  if (toProtocol === 'mcp') {
    return {
      schema: 'mcp/1.0',
      server_info: { name: base.agent, version: '1.0.0', protocol: 'mcp' },
      tools: base.capabilities.map(cap => ({
        name: cap.replace(':', '_'),
        description: `AIB capability: ${cap}`,
        inputSchema: { type: 'object', properties: {} },
      })),
      aib_passport: { id: base.id, did: base.did, signature: base.signature },
    };
  }

  if (toProtocol === 'a2a') {
    return {
      schema: 'a2a/1.0',
      agent_card: {
        name: base.agent,
        did: base.did,
        skills: base.capabilities.map(cap => ({ id: cap, name: cap, description: `AIB: ${cap}` })),
        authentication: { type: 'Ed25519', public_key: base.public_key },
      },
      aib_passport_id: base.id,
    };
  }

  if (toProtocol === 'ag-ui') {
    return {
      schema: 'ag-ui/1.0',
      manifest: {
        name: base.agent,
        actions: base.capabilities.map(cap => ({ id: cap, label: cap, type: 'agent_action' })),
        identity: { did: base.did, passport_id: base.id },
      },
    };
  }
}

export const PROTOCOLS = Object.keys(PROTOCOL_FORMATS);
export const PROTOCOL_NAMES = PROTOCOL_FORMATS;
