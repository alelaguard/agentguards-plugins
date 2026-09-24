---
description: Set up and verify AgentGuards in Claude Code. Use when the user runs /agentguards:setup, asks to configure AgentGuards, set their API key, or check that the guardrails are wired up correctly.
---

# AgentGuards setup

Set up AgentGuards for the user. The plugin already bundles the enforcing hooks —
the only thing missing is their API key.

## Never do these

They are all wrong, and every one of them has been given to a real user:

- **Never print an `export` or `setx` or `[Environment]::SetEnvironmentVariable`
  command for them to run.** You have file tools. Use them.
- **Never tell them to edit a shell profile** (`~/.bashrc`, `~/.zshrc`, a
  PowerShell profile). The Claude Desktop app **never reads a shell profile**, so
  this does nothing for desktop users and wastes their time.
- **Never mention a "Configure" screen.** There isn't one. The desktop app has no
  settings screen for this key.
- **Never end your turn by asking whether they'd like you to set it up.** Setting
  it up is what this skill is for. Ask only for the key itself.

If you catch yourself writing any of the above, stop and write the file instead.

## Steps

0. **Check which surface you are on, before anything else.** Run this yourself —
   it is a check you perform, not a command to hand the user:

   ```bash
   [ "$CLAUDE_CODE_REMOTE" = "true" ] && echo cloud || echo local
   ```

   If it prints `cloud` you are in a Claude Code cloud session (Cowork, on
   claude.ai/code). **Stop and follow "Cloud sessions" below instead of steps
   1-5.** Writing `~/.claude/settings.json` there is pointless: the sandbox is
   an ephemeral container with its own `/root` home, thrown away when the
   session ends, and its user-scope settings are never read anyway.

   Use **`CLAUDE_CODE_REMOTE`** and nothing else. In particular do **not** test
   `CLAUDE_CODE_BRIDGE_SESSION_ID` — that is Remote Control, a *local* session
   exposed to the web, and it is set in ordinary local terminal sessions. Using
   it here would send Remote Control users down the cloud path and refuse to
   write the file that would have worked for them.

1. **Find the current key.** Check the `AGENTGUARDS_API_KEY` environment variable
   and the `env` block of the settings file for this OS:
   - Windows: `%USERPROFILE%\.claude\settings.json`
   - macOS/Linux: `~/.claude/settings.json`

   **Treat a placeholder as missing.** Values like `ag_YOUR_TOKEN`,
   `ag_YOUR_KEY_HERE`, `ag_your_token_here`, or anything containing `YOUR`, are
   copy-paste artefacts from the setup page. Say so plainly ("that's the example
   value from the setup page, not a real key") rather than reporting it as
   configured.

   A real key is `ag_` followed by 32 hex characters. If one is already there,
   skip to step 4.

2. **Get the key.** Three ways, in order:

   a. **They already put it in the message** — e.g. `/agentguards:setup ag_1234…`.
      Use it, don't ask again.

   b. **Offer the clipboard.** Most people arrive having just copied the key from
      the dashboard. Offer: *"If you've already copied your key, I can read it
      straight from your clipboard — say the word."* Only read it if they agree:
      - Windows: `Get-Clipboard`
      - macOS: `pbpaste`
      - Linux: `wl-paste`, or `xclip -selection clipboard -o`

      Validate before using it, and if the clipboard holds something else, say
      only that it didn't look like a key — **never** echo clipboard contents
      back, as it may hold something private.

   c. **Otherwise ask them to paste it**, from https://agentguards.co/dashboard/keys

   Either way, validate it is `ag_` + 32 hex before writing. If it isn't, say why
   and ask again. People often paste an Anthropic `sk-ant-…` key here — if you see
   one, tell them that's their Anthropic key, not their AgentGuards token.

3. **Write it into the settings file yourself**, at the path for their OS from
   step 1:

   ```json
   { "env": { "AGENTGUARDS_API_KEY": "ag_..." } }
   ```

   Rules that matter:
   - **Read the file first and merge — never overwrite.** Their `model`,
     `enabledPlugins`, `hooks` and `permissions` must all survive. Add the key
     inside `env`, creating `env` only if it is absent.
   - If the file doesn't exist, create it, and its directory.
   - If it exists but isn't valid JSON, **stop and tell them**. Never rewrite a
     file you couldn't parse — you would destroy settings you can't see.
   - This file is the right place because both the terminal and the desktop app
     read it. That is why a shell profile is not an option here.
   - Write the key and nothing else. Don't raise `AGENTGUARDS_URL` or self-hosting
     — this plugin is for the hosted service and points at it by default. A
     self-hosted appliance uses the separate `agentguards-claude-selfhosted`
     plugin, so mentioning it here is noise mid-setup.

   Never print the key back, and never write it anywhere else.

4. **Tell them to restart** — settings are read only at startup:
   - **Claude Desktop app:** fully quit it. On Windows the X only minimises to the
     tray; on macOS the red dot only hides the window. Then reopen.
   - **Terminal:** start a new Claude Code session.

5. **Verify after the restart.** Run the checks in the `status` skill yourself:
   they prove the key is **accepted** (HTTP 200), not just present — a
   placeholder key is present too.

   Then have the user send a message the guardrails block — asking to be shown
   all the API keys works well — and confirm it comes back blocked. That proves
   the hook itself is running. (Deliberately not spelling out a prompt-injection
   payload here: plugin security scanners run YARA over skill files and flag the
   literal string as an injection, which is how a sibling plugin once scored a
   critical finding for documenting an attack.)

   Then say plainly what is now on: prompt screening on every message, Bash
   command authorization, web-content scanning, and security scanning of file
   writes.

## Cloud sessions (Cowork)

You cannot set the key from inside the sandbox — there is no file you can write
that survives it. The key has to be set **on the cloud environment**, from the
web UI, by the user. Walk them through it and then stop; do not fall back to
writing a file.

Three things have to be true. Give them all three — the first one is the one
everybody misses, and without it a correct key still fails.

1. **Let the sandbox reach AgentGuards.** Cloud environments default to
   "Trusted" network access, an allowlist of package registries, GitHub and
   cloud SDKs. `prod.agentguards.co` is not on it, so every check fails until
   they add it: at claude.ai/code pick the environment, then **Network
   access** -> **Custom** -> add `prod.agentguards.co` to the allowed domains.

2. **Set the key on the environment.** Same environment, **Environment
   variables**, add:

   ```
   AGENTGUARDS_API_KEY=ag_your_token_here
   ```

   This is the one place a value reaches the sandbox's real process
   environment, which is what the hooks read.

   Tell them plainly, without softening it: **that field is plaintext, and
   anyone who can use that environment can read the key.** On a personal
   environment that is fine. On a shared team environment, everyone on the team
   gets the key.

   So suggest a **separate key for Cowork** — mint one at
   https://agentguards.co/dashboard/keys, name it `cowork`, and it can be
   revoked later without breaking their laptop. Check their plan first: the
   free plan allows exactly **one** API key, so if they are on free, this
   advice does not apply and they reuse the key they have.

3. **Make the plugin load in the session.** Cloud sessions do not install the
   plugins on their machine; they install what the repo asks for. Add this to
   the repo's `.claude/settings.json` and commit it:

   ```json
   {
     "extraKnownMarketplaces": {
       "agentguards": {
         "source": { "source": "github", "repo": "alelaguard/agentguards-plugins" }
       }
     },
     "enabledPlugins": ["agentguards-claude@agentguards"]
   }
   ```

   The bundled hooks come with the plugin — they do not need to be declared
   separately.

Then have them start a **new** cloud session and verify exactly as in step 5:
the key check must return `200`, and a message that should be blocked must come
back blocked. Together those prove both the key and the domain allowlist
actually took.

If checks appear to do nothing, or the guardrails report the service is
unreachable, **suspect the domain allowlist first** — that is step 1, and a
missing allowlist entry looks exactly like a broken key.

## Worth knowing

- **Without a key the guardrails are off, not blocking.** The hooks let the turn
  through and say so. "Nothing looks broken" is not evidence that setup worked —
  verify as in step 5.
- **The plain Chat tab isn't covered.** Hooks run in Agent Mode and Local Code
  sessions, which are Claude Code underneath. If you are in a plain chat with no
  file access, say so directly: *"I can't set this up from here — open an Agent
  Mode or Local Code session and run me there."* Do not fall back to reciting
  manual instructions.
- **Cloud sessions (Cowork) are covered, but only once the user configures the
  environment** — see "Cloud sessions" above. Don't tell them it is unsupported;
  it works, it just cannot be set up from inside the sandbox.
- Once a key is set, enforcement fails **closed**: if AgentGuards is unreachable,
  actions are blocked. `AGENTGUARDS_FAIL_OPEN=true` prefers availability. Mention
  it only if they ask or report unexpected blocks.
