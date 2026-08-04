# AgentGuards extension for Gemini CLI — self-hosted

For a **self-hosted AgentGuards appliance**. If you're on the hosted product
at agentguards.co, install `agentguards-gemini` instead — it bundles the MCP
server this variant deliberately does not.

## Why a separate extension

Gemini CLI's extension manifest cannot substitute an environment variable
into its MCP server URL — it has to be a fixed string, baked in when the
extension is published. `agentguards-gemini`'s manifest therefore points at
`https://prod.agentguards.co`, and there is no way to override that per
installation. Shipping one extension for both audiences meant a self-hosted
operator's MCP tool calls (`check_input`, `authorize_action`, …) would go to
AgentGuards' hosted service instead of their own appliance, with no error and
no way to tell — the opposite of what a self-hosted deployment is for.

This variant ships **hooks only**, with no MCP server at all. Hooks read
`AGENTGUARDS_URL` from the environment as a subprocess, correctly per
installation, so they aren't affected by that limitation. They are also the
actual enforcement mechanism — `check_input`/`authorize_action` in the other
variant are a cooperative convenience the model can choose to call; the hooks
run regardless. Nothing here is a reduced version of the guardrail, only a
narrower extension.

## Install

Gemini CLI's `extensions install` only supports single-extension repos, and
this one lives alongside the other plugins in the same marketplace repo — so
install by cloning and linking the subdirectory:

```
git clone https://github.com/alelaguard/agentguards-plugins.git
gemini extensions link agentguards-plugins/gemini-selfhosted
```

Then point it at your appliance. Unlike the hosted extension, **there is no
default** — this is deliberate, so it can never silently talk to the wrong
instance:

```
export AGENTGUARDS_URL=https://<your-appliance>
export AGENTGUARDS_API_KEY=ag_your_token_here
```

Add both lines to your shell profile (`~/.bashrc`, `~/.zshrc`, …) and restart
Gemini CLI. Or ask Gemini to run the `setup` skill and it will walk you
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

The hooks call your appliance's REST API before every prompt, before every
tool call, and after every web fetch — blocking or soft-blocking (Gemini CLI
has no native "ask to approve" hook primitive, so risky tool calls are denied
with an explanatory message asking you to re-submit and confirm) when it
flags a risk. There is no cooperative MCP layer in this variant; see the
bundled `guardrails` skill for why that's not a gap.

Learn more at https://agentguards.co.
