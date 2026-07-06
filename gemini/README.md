# AgentGuards extension for Gemini CLI

LLM security guardrails for Gemini CLI in one install: jailbreak and
prompt-injection detection, web-content scanning, data-exfiltration blocking,
and destructive-command authorization.

Enforcement is configurable: **fail-closed by default** for strict security, or
switch to fail-open (availability-first) with a single environment variable
(`AGENTGUARDS_FAIL_OPEN=true`).

This extension bundles:

- the **AgentGuards MCP server** (`check_input`, `authorize_action`,
  `validate_output`, `evaluate_policy`, `health_check`),
- **enforcing hooks** — `BeforeAgent` input scanning, `BeforeTool` tool-call
  authorization, and `AfterTool` web-content scanning/redaction (built-in
  `web_fetch`/`google_web_search`, and `run_shell_command` output when it
  invokes `curl`/`wget`),
- the AgentGuards security instructions (the `guardrails` skill).

## Install

Gemini CLI's `extensions install` only supports single-extension repos, and
this one lives alongside the Claude Code and Codex plugins in the same
marketplace repo — so install by cloning and linking the subdirectory:

```
git clone https://github.com/alelaguard/agentguards-plugins.git
gemini extensions link agentguards-plugins/gemini
```

Then provide your API key (get one at https://agentguards.co/dashboard/keys) so
both the MCP server and the hooks can authenticate:

```
export AGENTGUARDS_API_KEY=ag_your_token_here
```

Add that line to your shell profile (`~/.bashrc`, `~/.zshrc`, …) and restart
Gemini CLI. Or just ask Gemini to run the `setup` skill and it will walk you
through it.

## Configuration

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `AGENTGUARDS_API_KEY` | yes | — | Your `ag_` token. Drives both the MCP header and the hooks. |
| `AGENTGUARDS_URL` | no | `https://prod.agentguards.co` | Override only for a self-hosted instance. |
| `AGENTGUARDS_FAIL_OPEN` | no | `false` | Hooks fail **closed** by default (block when the service is unreachable). Set `true` to allow on error. |

## How it works

The hooks call the AgentGuards REST API before every prompt, before every tool
call, and after every web fetch — blocking or soft-blocking (Gemini CLI has no
native "ask to approve" hook primitive, so risky tool calls are denied with an
explanatory message asking you to re-submit and confirm) when AgentGuards flags
a risk. The MCP tools let Gemini cooperatively check inputs and authorize
actions as described in the bundled `guardrails` skill.

Learn more at https://agentguards.co.
