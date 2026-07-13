---
description: Report AgentGuards guardrail status. Use when the user asks whether AgentGuards is active, healthy, or correctly configured.
---

# AgentGuards status

Report the current state of AgentGuards protection.

1. Call the AgentGuards `health_check` MCP tool.

2. Report:
   - **Service reachability** from `health_check` (healthy / unreachable).
   - **API key**: whether `AGENTGUARDS_API_KEY` is set (show only the `ag_`
     prefix and length, never the full token).
   - **URL**: the value of `AGENTGUARDS_URL`, or the default
     `https://prod.agentguards.co`.
   - **Fail mode**: fail-closed unless `AGENTGUARDS_FAIL_OPEN=true`.
   - **Active guardrails**: `chat.message` prompt scanning, `bash` command
     authorization, post-fetch web-content scanning, and the MCP tools
     `check_input`, `authorize_action`, `validate_output`, `evaluate_policy`.

3. If the service is unreachable or the key is missing, point the user to the
   `setup` skill.
