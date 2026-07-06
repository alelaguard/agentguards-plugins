# AgentGuards plugin for GitHub Copilot CLI

LLM security guardrails for GitHub Copilot CLI in one install: jailbreak and
prompt-injection detection, web-content scanning, data-exfiltration blocking,
and destructive-command authorization.

Enforcement is configurable: **fail-closed by default** for strict security, or
switch to fail-open (availability-first) with a single environment variable
(`AGENTGUARDS_FAIL_OPEN=true`).

This plugin bundles:

- **enforcing hooks** — `userPromptSubmitted` input scanning, `preToolUse`
  shell-command authorization (allow / deny / ask), and `postToolUse`
  web-content scanning of `curl`/`wget` output,
- the **AgentGuards MCP server** (`check_input`, `authorize_action`,
  `validate_output`, `evaluate_policy`, `health_check`),
- the AgentGuards security instructions (the `guardrails` skill).

The hook is a self-contained Python script — no build step, no native binary.
It requires Python 3.9+ (already present on most systems).

## Install

```
copilot plugin install alelaguard/agentguards-plugins:copilot
```

(Copilot CLI currently warns that direct repo/path installs are deprecated in
favor of marketplace-based installs — this still works today; a marketplace
listing may be added here later if that becomes required.)

Then set your API key (get one at https://agentguards.co/dashboard/keys) so
both the MCP server and the hooks can authenticate:

```
export AGENTGUARDS_API_KEY=ag_your_token_here
```

Add that line to your shell profile (`~/.bashrc`, `~/.zshrc`, …) and restart
Copilot CLI. Or just ask Copilot to run the `setup` skill and it will walk you
through it.

## Configuration

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `AGENTGUARDS_API_KEY` | yes | — | Your `ag_` token. Drives both the MCP header and the hooks. |
| `AGENTGUARDS_URL` | no | `https://prod.agentguards.co` | Override only for a self-hosted instance. |
| `AGENTGUARDS_FAIL_OPEN` | no | `false` | Hooks fail **closed** by default (block when the service is unreachable). Set `true` to allow on error. |

## How it works

The hooks call the AgentGuards REST API on every prompt, before every shell
command, and after every web fetch — blocking the prompt, denying/asking on
the command, or flagging fetched content when AgentGuards detects a risk. The
MCP tools let Copilot cooperatively check inputs and authorize actions as
described in the bundled `guardrails` skill.

Learn more at https://agentguards.co.
