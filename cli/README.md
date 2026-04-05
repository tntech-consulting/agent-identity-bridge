# @aib-protocol/cli

**AIB Protocol CLI** — Agent Identity Bridge for AI agents.

The JWT/OIDC of the agentic era. Create cryptographic passports, enforce governance policies, translate credentials across protocols, and audit every agent action — from the command line.

## Install

```bash
npm install -g @aib-protocol/cli
```

## Quick Start

```bash
# Create a passport
aib passport create --name "my-agent" --protocols mcp,a2a

# Verify a passport
aib passport verify

# Check if an action is allowed (exit 0=ALLOW, exit 1=DENY)
aib guard check --action "exec.run" --params '{"command":"ls"}'

# Translate to A2A format
aib translate to --protocol a2a

# List governance templates
aib policy list
```

## Commands

| Command | Description |
|---|---|
| `aib passport create` | Create agent passport with Ed25519 keypair |
| `aib passport verify` | Verify passport signature and expiry |
| `aib passport export` | Export as W3C Verifiable Credential |
| `aib guard check` | Pre-action guardrail (exit 0/1) |
| `aib policy list` | List governance templates |
| `aib policy show` | Show template details |
| `aib policy evaluate` | Evaluate action against policies |
| `aib translate to` | Translate passport to MCP/A2A/AG-UI format |
| `aib translate protocols` | List supported protocols |

## Policy Templates

- `eu-ai-act` — EU AI Act compliance pack
- `minimal-guardrails` — Block dangerous commands
- `separation-of-duties` — Creator ≠ approver
- `budget-control` — Spending caps
- `delegation-chain` — Max depth limits

## License

Apache 2.0 — [aib-tech.fr](https://aib-tech.fr)
