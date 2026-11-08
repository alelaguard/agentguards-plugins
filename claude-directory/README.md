# AgentGuards for Claude — plugin directory edition

Security scans for AI agents, as tools Claude can call:

- **Scan untrusted text** — a web page, email, document, issue, or another
  tool's output — for prompt injection, jailbreak attempts, leaked secrets and
  personal data, before acting on it.
- **Check a shell command** before running or recommending it: destructive
  deletes, credential reads, data exfiltration, force pushes and infrastructure
  changes come back with a risk level and a reason.
- **Scan code** for security issues and hardcoded secrets before committing or
  running it.

The tools are read-only: they check what they are given and never run, change
or delete anything.

> [!IMPORTANT]
> **These are tools Claude calls, not automatic enforcement.** A check runs only
> when Claude calls a tool. For screening on every prompt, shell command and
> fetched page that Claude cannot skip, use
> [`agentguards-claude`](../claude) from this repo instead. One of the two is
> enough: with both installed, the same things get checked twice.

## Install

From Claude's plugin directory, or:

```
/plugin marketplace add alelaguard/agentguards-plugins
/plugin install agentguards@agentguards
```

### Then sign in (required, once)

The tools do nothing until you connect your AgentGuards account:

1. Run `/mcp` in Claude Code.
2. Select **agentguards**. It shows "needs authentication".
3. Choose **Authenticate** and approve in the browser. No account yet? Create a
   [free one](https://agentguards.co/sign-up) first.

There is no API key to paste. Signing in creates an AgentGuards API key for your
account (it appears under Keys in your dashboard) and gives it to Claude Code,
which stores it and sends it only to AgentGuards.

To sign out or switch accounts, open `/mcp` again and choose **Clear
authentication**. That removes the key from Claude Code only: it stays valid
until you revoke it under Keys in your [dashboard](https://agentguards.co/dashboard/keys).
If you think the key was exposed, revoke it there.

Scan results also appear in your AgentGuards dashboard.

## What it bundles

- the AgentGuards MCP server at `https://prod.agentguards.co/directory/mcp`
  (`scan_untrusted_text`, `check_command_safety`, `scan_code`),
- the `agentguards` skill, which tells Claude when to call them and how to act
  on the result.

No hooks and no scripts: nothing runs on your machine.

## What this plugin sends, and where

Only what a tool is called with: the text, command or code (with its file path,
if given) goes to `https://prod.agentguards.co` over HTTPS, with the access
token from your connected account. Nothing is sent when no tool is called, and
nothing goes anywhere else. How the service handles and retains this data is
described in the [privacy policy](https://agentguards.co/privacy).

Learn more at https://agentguards.co.
