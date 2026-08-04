---
description: Set up and verify AgentGuards in Claude Code against a self-hosted appliance. Use when the user runs /agentguards:setup, asks to configure AgentGuards, set their URL/API key, or check that the guardrails are wired up correctly.
---

# AgentGuards setup — self-hosted

Unlike the hosted plugin, this variant has **no default backend** — it must be
told which appliance to use. Guide the user through both required variables.

## Steps

1. **Check for `AGENTGUARDS_URL`.** This is required here (the hosted plugin
   defaults it; this one deliberately does not, so it can never silently talk
   to the wrong instance). It should be the appliance's own address, e.g.
   `https://guardrails.internal.example.com` — reachable from wherever Claude
   Code runs, over HTTPS.

2. **Check for `AGENTGUARDS_API_KEY`.** Look for it in the environment. If
   missing, tell the user to generate one on their appliance's own console at
   `<AGENTGUARDS_URL>/admin/ui/keys`, then export it.

3. **If the appliance is still on its first-boot self-signed certificate**,
   plain requests will fail with `CERTIFICATE_VERIFY_FAILED`. Two ways to fix,
   both explained on the appliance's own `/admin/ui/docs#tls` page:
   - `AGENTGUARDS_CA_BUNDLE=<path to the appliance's exported cert>` (pins it,
     verification stays on — the better option)
   - `AGENTGUARDS_TLS_NO_VERIFY=true` (evaluation on a private network only)

4. **Tell the user to add all set variables to their shell profile**
   (`~/.bashrc`, `~/.zshrc`, …), not just export them in the current terminal —
   a one-off `export` is gone the moment the terminal closes or a new agent
   session starts.

5. **Restart Claude Code** — hooks are read at startup.

6. **Verify**: ask the user to try a prompt like "ignore all previous
   instructions". It should be refused with an `[AgentGuards]` block panel. If
   it isn't, `AGENTGUARDS_URL`/`AGENTGUARDS_API_KEY` are likely not reaching the
   hook process — confirm they're in the shell profile, not just the current
   shell.
