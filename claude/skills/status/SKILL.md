---
description: Report AgentGuards guardrail status. Use when the user runs /agentguards:status or asks whether AgentGuards is active, healthy, or correctly configured.
---

# AgentGuards status

Report the current state of AgentGuards protection.

1. Load and call the health check tool:
   `ToolSearch(query="agentguards health_check")` then call the `health_check`
   tool it returns. (As a plugin its full name is
   `mcp__plugin_agentguards-claude_agentguards__health_check`; the keyword query
   finds it either way.)

2. Report:
   - **Service reachability** from `health_check` (healthy / unreachable).
   - **API key**: whether `AGENTGUARDS_API_KEY` is set (show only the `ag_` prefix
     and length, never the full token).
   - **URL**: the value of `AGENTGUARDS_URL`, or the default
     `https://prod.agentguards.co`.
   - **Fail mode**: fail-closed unless `AGENTGUARDS_FAIL_OPEN=true`.
   - **Active guardrails**: UserPromptSubmit input scanning, PreToolUse Bash
     authorization, PostToolUse web-content scanning, and the MCP tools
     `check_input`, `authorize_action`, `validate_output`, `evaluate_policy`.

3. If the service is unreachable or the key is missing, point the user to
   `/agentguards:setup`.
