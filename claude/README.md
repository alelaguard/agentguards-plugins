# AgentGuards plugin for Claude Code

LLM security guardrails for Claude Code in one install: jailbreak and
prompt-injection detection, web-content scanning, data-exfiltration blocking,
and destructive-command authorization.

Enforcement is configurable: **fail-closed by default** for strict security, or
switch to fail-open (availability-first) with a single environment variable
(`AGENTGUARDS_FAIL_OPEN=true`).

This plugin bundles:

- **enforcing hooks** — `UserPromptSubmit` input scanning, `PreToolUse` Bash
  authorization, and `PostToolUse` web-content scanning/redaction and security
  scanning of file writes,
- the `setup`, `status` and `guardrails` skills.

There is no MCP server: the hooks enforce everything on their own, so there is
nothing for Claude to call. (Before 0.2.34 the plugin also bundled one.)

**Easiest install:** the AgentGuards installer signs you in through the browser,
installs this plugin and saves your key, with nothing to paste. See
https://agentguards.co for the one-line command. The manual steps are below.

## Install

```
/plugin marketplace add alelaguard/agentguards-plugins
/plugin install agentguards-claude@agentguards
```

Then provide your API key (get one at
https://agentguards.co/dashboard/keys) so the hooks can authenticate:

```
export AGENTGUARDS_API_KEY=ag_your_token_here
```

Add that line to your shell profile (`~/.bashrc`, `~/.zshrc`, …) and restart
Claude Code. Or just run `/agentguards:setup` and it will walk you through it.

**No shell profile?** (Claude Desktop's Code tab, or any GUI-launched session
that doesn't read `~/.bashrc`.) Set it in `~/.claude/settings.json` instead —
this feeds the hooks exactly like a shell export:

```json
{
  "env": {
    "AGENTGUARDS_API_KEY": "ag_your_token_here"
  }
}
```

The plugin's **Configure** screen also accepts a key, as a fallback when the
environment variable is not set.

**The plain Chat tab is not supported** — hooks do not run there. Use the
**Code** tab.

**Cloud sessions (Cowork) are supported, with a one-time setup.** A cloud
sandbox never reads your `~/.claude`, so the key cannot come from your machine,
and its network is allowlisted by default. On the environment at claude.ai/code
you need to set **Network access** to Custom and add `prod.agentguards.co`, add
`AGENTGUARDS_API_KEY` under **Environment variables**, and enable the plugin
from your repo's `.claude/settings.json`. Note that the environment-variables
field is plaintext and readable by anyone using that environment, so prefer a
separate key. Full walkthrough:
[Claude Code in Cowork](https://agentguards.co/docs/claude-code-cowork).

**Alternative: `npm install @agentguardsco/claude-plugin`.** Fetches these same
files for programmatic use (pinned versions, CI, custom tooling) — it does
not register with Claude Code on its own; use `/plugin install` above for that.

## Commands

- `/agentguards:setup` — set your API key and verify everything is wired up.
- `/agentguards:status` — report whether the guardrails are active and healthy.

## Configuration

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `AGENTGUARDS_API_KEY` | yes | — | Your `ag_` token. Falls back to the plugin option, then `~/.agentguards/credentials.json` (saved by the installer). |
| `AGENTGUARDS_URL` | no | `https://prod.agentguards.co` | Override only for a self-hosted instance. |
| `AGENTGUARDS_FAIL_OPEN` | no | `false` | Hooks fail **closed** by default (block when the service is unreachable). Set `true` to allow on error. |

## How it works

The hooks call the AgentGuards REST API on every prompt, before every Bash
command, after every web fetch and after every file write — blocking or
redacting when AgentGuards flags a risk. Claude Code runs them itself, so the
model cannot skip or talk its way around them.

Learn more at https://agentguards.co.
