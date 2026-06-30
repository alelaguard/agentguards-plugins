---
description: Set up and verify AgentGuards in Claude Code. Use when the user runs /agentguards:setup, asks to configure AgentGuards, set their API key, or check that the guardrails are wired up correctly.
---

# AgentGuards setup

Guide the user through finishing AgentGuards setup after installing the plugin.
The plugin already bundles the MCP server and the enforcing hooks — the only
thing the user must supply is their API key.

## Steps

1. **Check for the API key.** Look for the `AGENTGUARDS_API_KEY` environment
   variable. If it is missing or does not start with `ag_`, tell the user to:
   - Get a key from the dashboard at https://agentguards.co/dashboard/keys
   - Export it so both the MCP server and the hooks can read it. For the current
     shell and future sessions, add to their shell profile
     (`~/.bashrc`, `~/.zshrc`, etc.):

     ```
     export AGENTGUARDS_API_KEY=ag_your_token_here
     ```

   - Restart Claude Code (or start a new session) so the MCP server picks up the
     key from the environment.

2. **Confirm the URL (optional).** AgentGuards defaults to
   `https://prod.agentguards.co`. Only set `AGENTGUARDS_URL` if the user runs a
   self-hosted instance.

3. **Fail-open vs fail-closed.** The hooks fail **closed** by default — if the
   AgentGuards service is unreachable, actions are blocked. A user who prefers
   availability over strict enforcement can set `AGENTGUARDS_FAIL_OPEN=true`.
   Mention this only if they ask or report unexpected blocks.

4. **Verify.** Run the AgentGuards `health_check` MCP tool
   (`ToolSearch(query="select:mcp__agentguards__health_check")` then call it).
   Report whether the service is reachable and which key prefix is active. If it
   fails, the most common cause is `AGENTGUARDS_API_KEY` not being exported in
   the environment Claude Code was launched from.

5. **Summarize what is now active:** UserPromptSubmit input scanning, PreToolUse
   Bash authorization, PostToolUse web-content scanning, and the `check_input` /
   `authorize_action` MCP tools.
