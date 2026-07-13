---
description: Set up and verify AgentGuards in OpenCode. Use when the user asks to configure AgentGuards, set their API key, or check that the guardrails are wired up correctly.
---

# AgentGuards setup

Guide the user through finishing AgentGuards setup after installing the
plugin. The plugin already bundles the enforcing hooks — the user must supply
their API key and, optionally, register the MCP server.

## Steps

1. **Check for the API key.** Look for the `AGENTGUARDS_API_KEY` environment
   variable. If it is missing or does not start with `ag_`, tell the user to:
   - Get a key from the dashboard at https://agentguards.co/dashboard/keys
   - Export it so both the plugin and the MCP server can read it. For the
     current shell and future sessions, add to their shell profile
     (`~/.bashrc`, `~/.zshrc`, etc.):

     ```
     export AGENTGUARDS_API_KEY=ag_your_token_here
     ```

   - Restart OpenCode (or start a new session) so the plugin picks up the key
     from the environment.

2. **Confirm the URL (optional).** AgentGuards defaults to
   `https://prod.agentguards.co`. Only set `AGENTGUARDS_URL` if the user runs a
   self-hosted instance.

3. **Fail-open vs fail-closed.** The plugin fails **closed** by default — if
   the AgentGuards service is unreachable, actions are blocked. A user who
   prefers availability over strict enforcement can set
   `AGENTGUARDS_FAIL_OPEN=true`. Mention this only if they ask or report
   unexpected blocks.

4. **Register the MCP server (optional but recommended).** If not already
   done:

   ```
   opencode mcp add agentguards \
     --url https://prod.agentguards.co/mcp \
     --header 'X-API-Key=${AGENTGUARDS_API_KEY}'
   ```

   Verify with `opencode mcp list` — `agentguards` should show as connected.

5. **Verify.** Call the AgentGuards `health_check` MCP tool. Report whether the
   service is reachable and which key prefix is active. If it fails, the most
   common cause is `AGENTGUARDS_API_KEY` not being exported in the environment
   OpenCode was launched from.

6. **Summarize what is now active:** `chat.message` prompt scanning, `bash`
   command authorization (a borderline command is blocked with a reason, not
   silently allowed), post-fetch web-content scanning for `webfetch` and `bash`-invoked
   curl/wget, and the `check_input` / `authorize_action` MCP tools.
