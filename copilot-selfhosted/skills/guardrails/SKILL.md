---
name: guardrails
description: AgentGuards security guardrails for a self-hosted appliance — explains that enforcement is fully automatic via hooks and there is nothing further to call. Load this if asked how guardrails are enforced in this variant, or why no agentguards MCP tools are available.
---

# AgentGuards — self-hosted, hooks-only

This variant bundles no MCP server, so there is no `check_input`/`authorize_action`
to reach for — do not look for them, they are not installed here.

That is not reduced protection. The three hooks in `hooks.json` enforce
deterministically, on every request, regardless of anything the model does:

- **`userPromptSubmitted`** screens every prompt before you see it.
- **`preToolUse`** authorizes every shell command before it runs (allow/ask/deny).
- **`postToolUse`** scans fetched web content and withholds it if flagged.

Nothing here requires you to call a tool, check a decision, or format a block
message — the hook has already acted by the time you see (or don't see) the
result. If a hook blocks something, reply with its message rather than
composing your own.

**Why no MCP server:** Copilot's `.mcp.json` cannot substitute an environment
variable into its `url` field, so a URL baked in at publish time cannot be
made to point at each installer's own appliance — it would either be fixed to
one instance or, worse, silently fall back to AgentGuards' hosted service.
Rather than ship that, this variant relies entirely on the hooks, which read
`AGENTGUARDS_URL` correctly per installation because they are a subprocess,
not a static config file. If you're on the hosted product instead of a
self-hosted appliance, install `agentguards-copilot`, which does bundle the
MCP server.

**Inline completions (ghost text) cannot be screened either way.** They always
call GitHub's own servers directly by design — no hook or MCP server, ours or
anyone's, can intercept them. Chat, Agent, Ask and Edit are covered.
