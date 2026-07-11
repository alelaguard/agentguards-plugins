# AgentGuards plugin for Claude Code

LLM security guardrails for Claude Code in one install: jailbreak and
prompt-injection detection, web-content scanning, data-exfiltration blocking,
and destructive-command authorization.

Enforcement is configurable: **fail-closed by default** for strict security, or
switch to fail-open (availability-first) with a single environment variable
(`AGENTGUARDS_FAIL_OPEN=true`).

This plugin bundles:

- the **AgentGuards MCP server** (`check_input`, `authorize_action`,
  `validate_output`, `evaluate_policy`, `health_check`),
- **enforcing hooks** — `UserPromptSubmit` input scanning, `PreToolUse` Bash
  authorization, and `PostToolUse` web-content scanning/redaction,
- the AgentGuards security instructions (the `guardrails` skill).

## Install

```
/plugin marketplace add alelaguard/agentguards-plugins
/plugin install agentguards-claude@agentguards
```

Then provide your API key (get one at
https://agentguards.co/dashboard/keys) so both the MCP server and the hooks can
authenticate:

```
export AGENTGUARDS_API_KEY=ag_your_token_here
```

Add that line to your shell profile (`~/.bashrc`, `~/.zshrc`, …) and restart
Claude Code. Or just run `/agentguards:setup` and it will walk you through it.

**Alternative: `npm install @agentguards/claude-plugin`.** Fetches these same
files for programmatic use (pinned versions, CI, custom tooling) — it does
not register with Claude Code on its own; use `/plugin install` above for that.

## Commands

- `/agentguards:setup` — set your API key and verify everything is wired up.
- `/agentguards:status` — report whether the guardrails are active and healthy.

## Configuration

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `AGENTGUARDS_API_KEY` | yes | — | Your `ag_` token. Drives both the MCP header and the hooks. |
| `AGENTGUARDS_URL` | no | `https://prod.agentguards.co` | Override only for a self-hosted instance. |
| `AGENTGUARDS_FAIL_OPEN` | no | `false` | Hooks fail **closed** by default (block when the service is unreachable). Set `true` to allow on error. |

## How it works

The hooks call the AgentGuards REST API on every prompt, before every Bash
command, and after every web fetch — blocking or redacting when AgentGuards
flags a risk. The MCP tools let Claude cooperatively check inputs and authorize
actions as described in the bundled `guardrails` skill.

Learn more at https://agentguards.co.
