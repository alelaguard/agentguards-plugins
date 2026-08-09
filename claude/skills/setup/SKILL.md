---
description: Set up and verify AgentGuards in Claude Code. Use when the user runs /agentguards:setup, asks to configure AgentGuards, set their API key, or check that the guardrails are wired up correctly.
---

# AgentGuards setup

Finish AgentGuards setup for the user. The plugin already bundles the MCP server
and the enforcing hooks — the only thing missing is their API key.

**Do the work for them.** Most people who reach this skill are not comfortable
editing JSON or using a terminal, and in the Claude Desktop app there is no
settings screen for the key at all. You have file tools; use them. Do not paste a
block of shell commands and ask the user to run it — that is the exact wall this
skill exists to remove.

## Steps

1. **Check whether it's already working.** Read the `AGENTGUARDS_API_KEY`
   environment variable and the `env` block of `~/.claude/settings.json`
   (`%USERPROFILE%\.claude\settings.json` on Windows). If a key starting with
   `ag_` is already in place, skip to step 4.

2. **Ask for the key.** Tell them to copy it from
   https://agentguards.co/dashboard/keys and paste it in the chat. It starts with
   `ag_`. Ask for nothing else.

   If what they paste doesn't start with `ag_`, say so plainly and ask again —
   don't write it. People commonly paste an Anthropic `sk-ant-...` key here by
   mistake; if you see one, tell them that's their Anthropic key, not their
   AgentGuards token, and point them at the dashboard link again.

3. **Write it yourself**, into the `env` block of `~/.claude/settings.json`:

   ```json
   { "env": { "AGENTGUARDS_API_KEY": "ag_..." } }
   ```

   Rules that matter:
   - **Merge, never overwrite.** Read the file first and keep every existing
     setting. Someone's `model`, `hooks`, or `permissions` must survive.
   - If the file doesn't exist, create it (and `~/.claude/` if needed).
   - If it exists but isn't valid JSON, **stop and tell them** — do not rewrite a
     file you couldn't parse, or you'll destroy settings you can't read.
   - `AGENTGUARDS_URL` only needs setting for a self-hosted appliance; the plugin
     defaults to the hosted service.

   Never print the key back to the user, and never write it anywhere else.

4. **Tell them to restart.** Settings are read at startup:
   - **Claude Desktop app:** fully quit it — on Windows the X only minimises to
     the tray, on macOS the red dot only hides the window — then reopen.
   - **Terminal:** start a new Claude Code session.

5. **Verify, then say plainly whether they're protected.** After the restart, run
   the `health_check` MCP tool (`ToolSearch(query="agentguards health_check")`;
   as a plugin its full name is
   `mcp__plugin_agentguards-claude_agentguards__health_check`).

   Then summarise what is now on: prompt screening on every message, Bash command
   authorization, web-content scanning, and the `check_input` /
   `authorize_action` tools.

   If it still fails, the key is almost certainly not being read — re-check the
   file you wrote in step 3 rather than guessing.

## Worth knowing

- **Without a key the guardrails are off, not blocking.** The hooks let the turn
  through and say so rather than blocking every message. So "nothing appears
  broken" is not evidence that setup worked — verify in step 5.
- **The desktop app never reads your shell profile.** A shell `export` reaches a
  terminal session only; the settings file is what both surfaces read, which is
  why step 3 writes there rather than suggesting an `export`.
- **The plain Chat tab isn't covered.** Hooks run in Agent Mode and Local Code
  sessions, which are Claude Code underneath. Say so if they ask why a normal
  chat isn't screened.
- Enforcement fails **closed** once a key is set: if AgentGuards is unreachable,
  actions are blocked. `AGENTGUARDS_FAIL_OPEN=true` prefers availability.
  Mention it only if they ask or report unexpected blocks.
