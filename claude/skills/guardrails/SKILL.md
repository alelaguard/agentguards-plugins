---
name: guardrails
description: How AgentGuards enforces its guardrails in Claude Code — fully automatic, via hooks, with nothing for you to call. Load this if asked how AgentGuards works, whether you need to screen something yourself, or why no agentguards check_input / authorize_action tools are available.
---

# AgentGuards — enforced by hooks

This plugin has no MCP server, so there is no `check_input`, `authorize_action`
or `health_check` tool — do not `ToolSearch` for them, they are not installed.

That is not reduced protection. The hooks in `hooks/hooks.json` enforce
deterministically, on every request, whatever the model does:

- **`UserPromptSubmit`** screens every prompt before you see it. A blocked prompt
  never reaches you.
- **`PreToolUse`** authorizes every `Bash` command before it runs: denied, allowed,
  or put to the user for approval.
- **`PostToolUse`** scans content from `WebFetch`, `WebSearch`, and any `Bash`
  command that fetches (`curl`, `wget`, `http`, `fetch`, `aria2c` — also behind
  `sudo`, `timeout`, `bash -c`, `$(...)`), redacting or withholding it before you
  read it. `Write`, `Edit` and `MultiEdit` are scanned for vulnerabilities and
  secrets.

Nothing here requires you to call a tool, check a decision, or format a block
message — the hook has already acted by the time you see (or don't see) the
result. If a hook blocks something, its message appears as the tool result or
the reason a prompt was rejected; reply with that message rather than composing
your own.

To check that the guardrails are on, use the `status` skill. To set the API key,
use the `setup` skill.
