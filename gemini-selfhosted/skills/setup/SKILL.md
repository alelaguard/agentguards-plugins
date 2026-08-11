---
name: setup
description: Set up and verify AgentGuards in Gemini CLI against a self-hosted appliance. Use when the user asks to configure AgentGuards, set their URL/API key, or check that the guardrails are wired up correctly.
---

# AgentGuards setup — self-hosted

Unlike the hosted extension, this variant has **no default backend** — it
must be told which appliance to use. Guide the user through both required
variables.

## Steps

1. **Check for `AGENTGUARDS_URL`.** This is required here (the hosted
   extension defaults it; this one deliberately does not, so it can never
   silently talk to the wrong instance). It should be the appliance's own
   address, reachable from wherever Gemini CLI runs, over HTTPS.

2. **Check for `AGENTGUARDS_API_KEY`.** If missing, tell the user to generate
   one on their appliance's own console at `<AGENTGUARDS_URL>/admin/ui/keys`,
   then export it.

3. **If the appliance is still on its first-boot self-signed certificate**,
   plain requests will fail with `CERTIFICATE_VERIFY_FAILED`. Two ways to fix,
   both explained on the appliance's own `/admin/ui/docs#tls` page:
   - `AGENTGUARDS_CA_BUNDLE=<path to the appliance's exported cert>` (pins it,
     verification stays on — the better option)
   - `AGENTGUARDS_TLS_NO_VERIFY=true` (evaluation on a private network only)

4. **Tell the user to add both variables to their shell profile**
   (`~/.bashrc`, `~/.zshrc`, …), not just export them in the current terminal
   — a one-off `export` is gone the moment the terminal closes or a new agent
   session starts.

5. **Restart Gemini CLI** so it inherits them.

6. **Verify**: ask the user to try a prompt the guardrails block — asking to
   be shown all the API keys works well. It should be refused with an
   `[AgentGuards]` block panel. (Deliberately not spelling out a
   prompt-injection payload here: plugin security scanners run YARA over skill
   files and flag the literal string as an injection, which is how this file
   once scored a critical finding for documenting an attack.) If
   it isn't, the variables are likely not reaching the hook process — confirm
   they're in the shell profile, not just the current shell.
