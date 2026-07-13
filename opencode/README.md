# AgentGuards plugin for OpenCode

LLM security guardrails for [OpenCode](https://opencode.ai): jailbreak and
prompt-injection detection, web-content scanning, and destructive-command
authorization — enforced in-process, before the model ever sees a flagged
prompt or fetched page.

Enforcement is configurable: **fail-closed by default** for strict security, or
switch to fail-open (availability-first) with a single environment variable
(`AGENTGUARDS_FAIL_OPEN=true`).

This plugin bundles:

- **enforcing hooks** — `chat.message` prompt scanning, `bash` command
  authorization (a borderline command is blocked with a reason — re-run once
  you've confirmed you want to proceed), and post-execution web-content
  scanning/redaction for `webfetch` and `curl`/`wget`-style `bash` calls,
- the AgentGuards security instructions (the `guardrails` skill), for
  cooperative use of the AgentGuards MCP tools.

The **AgentGuards MCP server** (`check_input`, `authorize_action`,
`validate_output`, `evaluate_policy`, `health_check`) is set up separately —
see MCP setup below — since OpenCode's plugin API and its MCP registration are
independent mechanisms (unlike Claude Code, which bundles both from one
plugin install).

## Install the plugin

**npm (recommended):**

```
opencode plugin @agentguardsco/opencode-plugin
```

Add `-g`/`--global` to install for all projects instead of just the current
one.

**Local file (no npm):** copy `plugin/agentguards-opencode-plugin.ts` to
`.opencode/plugin/` in your project (or your global OpenCode config directory)
— OpenCode auto-loads any plugin file it finds there.

## Set your API key

```
export AGENTGUARDS_API_KEY=ag_your_token_here
```

Get a key at https://agentguards.co/dashboard/keys. Add that line to your
shell profile (`~/.bashrc`, `~/.zshrc`, …) and restart OpenCode.

## Set up the MCP server (optional, for cooperative checks)

```
opencode mcp add agentguards \
  --url https://prod.agentguards.co/mcp \
  --header 'X-API-Key=${AGENTGUARDS_API_KEY}'
```

Quote the header value with single quotes so your shell doesn't expand
`${AGENTGUARDS_API_KEY}` before OpenCode sees it — OpenCode resolves the
placeholder itself from your environment at connect time, so the raw key is
never written to your `opencode.json`/`opencode.jsonc`. Verify with
`opencode mcp list`.

## Configuration

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `AGENTGUARDS_API_KEY` | yes | — | Your `ag_` token. Drives both the hooks and the MCP header. |
| `AGENTGUARDS_URL` | no | `https://prod.agentguards.co` | Override only for a self-hosted instance. |
| `AGENTGUARDS_FAIL_OPEN` | no | `false` | Hooks fail **closed** by default (block when the service is unreachable). Set `true` to allow on error. |

## How it works

The plugin calls the AgentGuards REST API on every chat message, before every
`bash` command, and after every web fetch — blocking or redacting when
AgentGuards flags a risk. A borderline `bash` command (e.g. one AgentGuards
scores as `require-approval`) is blocked with a message telling you to re-run
it once you've confirmed you want to proceed, rather than being silently
allowed. The MCP tools let the model cooperatively check inputs and authorize
actions as described in the bundled `guardrails` skill.

Learn more at https://agentguards.co.
