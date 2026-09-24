---
name: status
description: Report AgentGuards guardrail status. Use when the user runs /agentguards:status or asks whether AgentGuards is active, healthy, or correctly configured.
---

# AgentGuards status

Check the real state yourself — run these, don't hand them to the user. Never
print the API key: the commands below only ever pass it along, and you report
at most its `ag_` prefix.

1. **If the AgentGuards CLI is installed, use it.** It checks the key, the
   service and each agent's install in one go:
   ```bash
   ag=$(command -v agentguards || ls ~/.agentguards/bin/agentguards ~/.agentguards/bin/agentguards.exe 2>/dev/null | head -1)
   [ -n "$ag" ] && "$ag" doctor
   ```
   If that ran, report its output and stop here.

2. **Otherwise, find the key.** The hooks use the first of: the
   `AGENTGUARDS_API_KEY` environment variable, the plugin's API-key option, then
   `~/.agentguards/credentials.json` (saved by `agentguards login`). Say which
   one is set — not the value.

3. **Check the service is reachable:**
   ```bash
   curl -s -o /dev/null -w '%{http_code}\n' "${AGENTGUARDS_URL:-https://prod.agentguards.co}/health"
   ```
   `200` means it is up. A connection failure means the hooks fail closed and
   block until it is back (unless `AGENTGUARDS_FAIL_OPEN=true`).

4. **Confirm the key is accepted**, not just present:
   ```bash
   curl -s -o /dev/null -w '%{http_code}\n' "${AGENTGUARDS_URL:-https://prod.agentguards.co}/v1/guardrails/evaluate-input" \
     -H "X-API-Key: ${AGENTGUARDS_API_KEY:-$(python3 -c "import json,os;print(json.load(open(os.path.expanduser('~/.agentguards/credentials.json')))['api_key'])" 2>/dev/null)}" \
     -H 'Content-Type: application/json' -d '{"text":"status check"}'
   ```
   `200` means it is accepted. `401` means the key is wrong or was revoked at
   https://agentguards.co/dashboard/keys.

5. **Report plainly**: where the key comes from, the two status codes, the fail
   mode (fail-closed unless `AGENTGUARDS_FAIL_OPEN=true`), and what the hooks
   cover — every prompt, every Bash command, fetched web content, and file
   writes. Don't speculate beyond what the checks showed. If the key is missing
   or rejected, point the user to `/agentguards:setup`.
