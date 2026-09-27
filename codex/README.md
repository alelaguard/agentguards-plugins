# AgentGuards plugin for OpenAI Codex

LLM security guardrails for Codex in one install: jailbreak and
prompt-injection detection, web-content scanning, data-exfiltration blocking,
and destructive-command authorization.

Enforcement is configurable: **fail-closed by default** for strict security, or
switch to fail-open (availability-first) with a single environment variable
(`AGENTGUARDS_FAIL_OPEN=true`).

This plugin bundles:

- **enforcing hooks** — `UserPromptSubmit` input scanning, `PreToolUse`
  shell-command authorization (allow / deny / ask, with a per-session approval
  cache), and `PostToolUse` web-content scanning of `curl`/`wget` output and of
  web-fetching MCP tools, and security scanning of `apply_patch` edits,
- the `setup`, `status` and `guardrails` skills.

There is no MCP server: the hooks enforce everything on their own, so there is
nothing for Codex to call. (Before 0.2.18 the plugin also bundled one.) Codex's
built-in web search runs on OpenAI's servers, so no hook sees its results;
content fetched through shell commands and MCP fetch tools is screened.

**Web scan** (when web scan is enabled for your account): before a `curl`/`wget`
command or a web-fetching MCP tool runs, every URL it will request is checked, and the
fetch is denied if a URL carries a secret, targets a cloud metadata endpoint, uses a
non-web scheme, or breaks your domain policy (if the check itself fails, the fetch goes
ahead). After the fetch, instructions hidden from a human reader (HTML comments,
invisible text, …) are removed and the rest of the page is passed on with a note; a
page with a visible instruction aimed at the agent is withheld.

The hook is a self-contained script — no build step, no native binary. On Linux
and macOS it is Python (3.9+, already present on most systems); on Windows Codex
runs the PowerShell port, `scripts/agentguards_codex_hook.ps1`, with the Windows
PowerShell every Windows machine ships. Both behave identically (CI runs the same
scenarios through each).

## Install

```
codex plugin marketplace add alelaguard/agentguards-plugins
codex plugin add agentguards-codex@agentguards-codex
```

Then provide your API key (get one at
https://agentguards.co/dashboard/keys) so the hooks can authenticate:

```
export AGENTGUARDS_API_KEY=ag_your_token_here
```

Add that line to your shell profile (`~/.bashrc`, `~/.zshrc`, …) and restart
Codex so it inherits the key on every session.

> **Easiest install:** the AgentGuards installer signs you in through the
> browser, installs this plugin and saves your key, with nothing to paste. See
> https://agentguards.co for the one-line command.

## Configuration

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `AGENTGUARDS_API_KEY` | yes | — | Your `ag_` token. Falls back to `~/.codex/agentguards_token`, then `~/.agentguards/credentials.json` (saved by the installer). |
| `AGENTGUARDS_FAIL_OPEN` | no | `false` | Hooks fail **closed** by default (block when the service is unreachable). Set `true` to allow on error. |

## How it works

The hooks call the AgentGuards REST API on every prompt, before every shell
command, and after every web fetch — blocking the prompt, denying/asking on the
command, or withholding fetched content when AgentGuards flags a risk. Risky
commands are surfaced for **your approval** rather than silently blocked. Codex
runs the hooks itself, so the model cannot skip them.

Learn more at https://agentguards.co.
