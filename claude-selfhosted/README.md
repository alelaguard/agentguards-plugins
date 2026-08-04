# AgentGuards plugin for Claude Code — self-hosted

For a **self-hosted AgentGuards appliance**. If you're on the hosted product
at agentguards.co, install `agentguards-claude` instead — it bundles the MCP
server this variant deliberately does not.

## Why a separate plugin

Claude Code's plugin `.mcp.json` cannot substitute an environment variable
into its `url` field — it has to be a fixed string, baked in when the plugin
is published. `agentguards-claude`'s `.mcp.json` therefore points at
`https://prod.agentguards.co`, and there is no way to override that per
installation. Shipping one plugin for both audiences meant a self-hosted
operator's MCP tool calls (`check_input`, `authorize_action`, …) would go to
AgentGuards' hosted service instead of their own appliance, with no error and
no way to tell — the opposite of what a self-hosted deployment is for.

This variant ships **hooks only**, with no MCP server at all. Hooks read
`AGENTGUARDS_URL` from the environment as a subprocess, correctly per
installation, so they aren't affected by that limitation. They are also the
actual enforcement mechanism — `check_input`/`authorize_action` in the other
variant are a cooperative convenience the model can choose to call; the hooks
run regardless. Nothing here is a reduced version of the guardrail, only a
narrower plugin.

## Install

```
/plugin marketplace add alelaguard/agentguards-plugins
/plugin install agentguards-claude-selfhosted@agentguards
```

Then point it at your appliance. Unlike the hosted plugin, **there is no
default** — this is deliberate, so it can never silently talk to the wrong
instance:

```
export AGENTGUARDS_URL=https://<your-appliance>
export AGENTGUARDS_API_KEY=ag_your_token_here
```

Add both lines to your shell profile (`~/.bashrc`, `~/.zshrc`, …) and restart
Claude Code. Or run `/agentguards:setup` and it will walk you through it,
including the appliance's first-boot self-signed certificate if that applies.

**Alternative: `npm install @agentguardsco/claude-selfhosted-plugin`.** Fetches
these files for programmatic use — it does not register with Claude Code on
its own; use `/plugin install` above for that.

## Commands

- `/agentguards:setup` — configure the appliance URL and API key, and verify.
- `/agentguards:status` — report reachability and whether the key is accepted.

## Configuration

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `AGENTGUARDS_URL` | **yes** | — none | Your appliance's own address. No fallback, by design. |
| `AGENTGUARDS_API_KEY` | yes | — | Your `ag_` token, generated on your appliance's own `/admin/ui/keys`. |
| `AGENTGUARDS_CA_BUNDLE` | no | — | Pin the appliance's certificate while it's still self-signed. Verification stays on. |
| `AGENTGUARDS_TLS_NO_VERIFY` | no | `false` | Skip certificate verification. Private-network evaluation only. |
| `AGENTGUARDS_FAIL_OPEN` | no | `false` | Hooks fail **closed** by default. Set `true` to allow on error. |

## How it works

The hooks call your appliance's REST API on every prompt, before every Bash
command, and after every web fetch — blocking or redacting when it flags a
risk. There is no cooperative MCP layer in this variant; see the bundled
`guardrails` skill for why that's not a gap.

Learn more at https://agentguards.co.
