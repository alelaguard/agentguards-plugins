---
name: status
description: Report AgentGuards guardrail status for a self-hosted appliance. Use when the user asks whether AgentGuards is active, healthy, or correctly configured in Codex.
---

# AgentGuards status — self-hosted

There is no `health_check` MCP tool in this variant (see the `guardrails`
skill for why). Check status directly instead:

1. **Confirm both required variables are set**: `AGENTGUARDS_URL`, and either
   `AGENTGUARDS_API_KEY` or `~/.codex/agentguards_token`. If `AGENTGUARDS_URL`
   is missing, stop here and point the user at the `setup` skill — the hooks
   fail closed without it.

2. **Check the appliance is reachable**, using the actual configured value:
   ```
   curl -s -o /dev/null -w '%{http_code}\n' "$AGENTGUARDS_URL/health"
   ```
   `200` means the appliance is up. A connection failure or a certificate
   error means the hooks will fail closed too — see the `setup` skill's TLS
   step.

3. **Confirm the key is accepted**, not just present:
   ```
   curl -s -o /dev/null -w '%{http_code}\n' "$AGENTGUARDS_URL/v1/guardrails/evaluate-input" \
     -H "X-API-Key: $(cat ~/.codex/agentguards_token 2>/dev/null || echo "$AGENTGUARDS_API_KEY")" \
     -H 'Content-Type: application/json' -d '{"text":"status check"}'
   ```
   `200` means it's accepted. `401` means the key is wrong or was revoked on
   the appliance's own Keys page.

4. **Report plainly**: which required variables are set, the `/health` status
   code, and the evaluate-input status code. Do not speculate beyond what
   these three checks actually showed.
