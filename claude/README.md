# AgentGuards plugin for Claude Code

LLM security guardrails for Claude Code in one install: jailbreak and
prompt-injection detection, web-content scanning, data-exfiltration blocking,
and destructive-command authorization.

Enforcement is configurable: **fail-closed by default** for strict security, or
switch to fail-open (availability-first) with a single environment variable
(`AGENTGUARDS_FAIL_OPEN=true`).

This plugin bundles:

- **enforcing hooks** — `UserPromptSubmit` input scanning, `PreToolUse` Bash
  authorization and a pre-fetch URL check (WebFetch, `curl`/`wget`, MCP fetch
  tools), and `PostToolUse` web-content scanning/redaction and security scanning
  of file writes,
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

## Commands

- `/agentguards:setup` — set your API key and verify everything is wired up.
- `/agentguards:status` — report whether the guardrails are active and healthy.

## Configuration

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `AGENTGUARDS_API_KEY` | yes | — | Your `ag_` token. Falls back to the plugin option, then `~/.agentguards/credentials.json` (saved by the installer). |
| `AGENTGUARDS_FAIL_OPEN` | no | `false` | Hooks fail **closed** by default (block when the service is unreachable). Set `true` to allow on error. |

## How it works

The hooks call the AgentGuards REST API on every prompt, before every Bash
command, after every web fetch and after every file write — blocking or
redacting when AgentGuards flags a risk. Claude Code runs them itself, so the
model cannot skip or talk its way around them.

Web fetches (since 0.2.35), when web scan is enabled for your account:

- **before the fetch**, the URL is checked. A URL that carries a credential or
  encoded secrets, points at a cloud metadata endpoint, or uses a non-web
  scheme is stopped before the request is sent. If this check cannot reach
  AgentGuards, the fetch goes ahead — the page is still scanned afterwards.
- **after the fetch**, instructions hidden from a human reader (HTML comments,
  invisible text, …) are removed and the rest of the page is passed on; a page
  whose visible text addresses the agent with an attack is withheld.

Fetch tools from MCP servers (names containing `fetch`, `browse`, `scrape`,
`web_`, `url` or `http`) are checked the same way.

## What this plugin sends, and where

Checking content means sending it to AgentGuards. The hooks send these to
`https://prod.agentguards.co`, over HTTPS, with your API key in the
`X-API-Key` header:

| When | What is sent |
|---|---|
| You submit a prompt | The prompt text |
| Before a Bash command runs | The command line |
| Before a web fetch (WebFetch, `curl`/`wget`, MCP fetch tools) | The URL(s) |
| After a web fetch | The fetched page or tool output |
| After Claude writes or edits a file | The file's path and new content |

Nothing is sent anywhere else, and the hooks send nothing when no API key is
set. The hooks read your key from `AGENTGUARDS_API_KEY`, the plugin's
**Configure** screen, or `~/.agentguards/credentials.json`, and send it only to
AgentGuards. How the service handles and retains this data is described in the
[privacy policy](https://agentguards.co/privacy).

Learn more at https://agentguards.co.
