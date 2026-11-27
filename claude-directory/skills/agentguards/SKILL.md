---
name: agentguards
description: How to use the AgentGuards scan tools (scan_untrusted_text, check_command_safety, scan_code). Use when the user asks you to check, scan or vet text, a shell command or code with AgentGuards, or asks how AgentGuards works.
---

# AgentGuards

This plugin connects the AgentGuards MCP server, which has three read-only
tools. Each one sends what it is given to the AgentGuards service and returns a
verdict. None of them runs, changes or deletes anything.

| Tool | What it does | Verdicts |
|---|---|---|
| `scan_untrusted_text` | Checks outside text for instructions aimed at an AI agent; removes hidden ones and masks live keys. Not a personal-data check | allow / block / redact |
| `check_command_safety` | Rates a shell command's risk, with a reason | allow / deny / require-approval |
| `scan_code` | Static-analysis rules for common risky patterns, and hardcoded credentials in known formats. Not a full security review. Pass `file_path` when you know it | allow / warn / block |

## When to call them

Call a tool when the user asks for it, for example:

- "Check this page / email / issue for prompt injection" → `scan_untrusted_text`
- "Is this command safe to run?" or "check commands with AgentGuards before you
  run them" → `check_command_safety`
- "Scan this file for secrets before I commit" → `scan_code`

If the user has asked you to check things with AgentGuards for the rest of the
task, keep doing that for the kind of content they named. Otherwise, don't call
the tools on your own. Each call sends the content to AgentGuards and counts
against the user's AgentGuards quota.

Pass the text, command or code that the user asked about as it is, without
summarising it. Each call takes up to 100,000 characters. If the text is longer,
tell the user and ask whether to scan it in parts.

## Reporting the result

Tell the user the verdict and the reason in plain words, then let them decide
what to do:

- **block / deny / escalate**: say what AgentGuards found and that it advises
  against using the text or running the command.
- **redact**: offer the redacted text.
- **require-approval / warn**: say why, and ask the user whether to go ahead.
- **allow**: say that nothing was found. For `scan_untrusted_text` this means no
  signs of injected instructions. It does not mean the text is safe to follow.

If a call fails or says sign-in is required, tell the user the check did not
run. Don't present your own judgement as an AgentGuards verdict.

## Signing in

The tools work only after the user connects their AgentGuards account, once:

1. Run `/mcp`.
2. Select **agentguards** (it shows "needs authentication").
3. Choose **Authenticate** and approve in the browser. No account yet? Create a
   free one at https://agentguards.co/sign-up first.

If a call still says sign-in is required after that, the user can open `/mcp`
again and choose **Reconnect** for agentguards, or restart Claude Code.

## What this plugin is not

It doesn't check anything automatically. A check runs only when one of these
tools is called. If the user asks whether they are protected automatically, say
so plainly.
