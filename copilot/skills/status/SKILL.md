---
name: status
description: Report AgentGuards guardrail status. Use when the user asks whether AgentGuards is active, healthy, or correctly configured in GitHub Copilot CLI.
---

# AgentGuards status

Report the current state of AgentGuards protection.

1. Call the `health_check` tool from the `agentguards` MCP server.

2. Report:
   - **Service reachability** from `health_check` (healthy / unreachable).
   - **API key**: whether `AGENTGUARDS_API_KEY` is set (show only the `ag_`
     prefix and length, never the full token).
   - **URL**: the value of `AGENTGUARDS_URL`, or the default
     `https://prod.agentguards.co`.
   - **Fail mode**: fail-closed unless `AGENTGUARDS_FAIL_OPEN=true`.
   - **Active guardrails**: `userPromptSubmitted` input scanning, `preToolUse`
     shell-command authorization, `postToolUse` web-content scanning, and the
     MCP tools `check_input`, `authorize_action`, `validate_output`,
     `evaluate_policy`.

3. If the service is unreachable or the key is missing, walk the user through
   the setup steps (set `AGENTGUARDS_API_KEY` and restart Copilot CLI).
