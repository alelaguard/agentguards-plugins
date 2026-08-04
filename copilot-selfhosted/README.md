# AgentGuards plugin for GitHub Copilot CLI — self-hosted

For a **self-hosted AgentGuards appliance**. If you're on the hosted product
at agentguards.co, install `agentguards-copilot` instead — it bundles the MCP
server this variant deliberately does not.

## Why a separate plugin

Copilot's `.mcp.json` cannot substitute an environment variable into its `url`
field — it has to be a fixed string, baked in when the plugin is published.
`agentguards-copilot`'s `.mcp.json` therefore points at
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

The hook is a self-contained Python script — no build step, no native binary.
It requires Python 3.9+ (already present on most systems).

## Install

```
copilot plugin install alelaguard/agentguards-plugins:copilot-selfhosted
```

(Copilot CLI currently warns that direct repo/path installs are deprecated in
favor of marketplace-based installs — this still works today; a marketplace
listing may be added here later if that becomes required.)

Then point it at your appliance. Unlike the hosted plugin, **there is no
default** — this is deliberate, so it can never silently talk to the wrong
instance:

```
export AGENTGUARDS_URL=https://<your-appliance>
export AGENTGUARDS_API_KEY=ag_your_token_here
```

Add both lines to your shell profile (`~/.bashrc`, `~/.zshrc`, …) and restart
Copilot CLI. Or ask Copilot to run the `setup` skill and it will walk you
through it, including the appliance's first-boot self-signed certificate if
that applies.

## Configuration

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `AGENTGUARDS_URL` | **yes** | — none | Your appliance's own address. No fallback, by design. |
| `AGENTGUARDS_API_KEY` | yes | — | Your `ag_` token, generated on your appliance's own `/admin/ui/keys`. |
| `AGENTGUARDS_CA_BUNDLE` | no | — | Pin the appliance's certificate while it's still self-signed. Verification stays on. |
| `AGENTGUARDS_TLS_NO_VERIFY` | no | `false` | Skip certificate verification. Private-network evaluation only. |
| `AGENTGUARDS_FAIL_OPEN` | no | `false` | Hooks fail **closed** by default. Set `true` to allow on error. |

## How it works

The hooks call your appliance's REST API on every prompt, before every shell
command, and after every web fetch — blocking the prompt, denying/asking on
the command, or withholding fetched content when it flags a risk. There is no
cooperative MCP layer in this variant; see the bundled `guardrails` skill for
why that's not a gap.

**Inline completions (ghost text) cannot be screened either way** — they
always call GitHub's own servers directly by design. Chat, Agent, Ask and Edit
are covered.

Learn more at https://agentguards.co.
