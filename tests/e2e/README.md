# Plugin e2e smoke test

Drives the **real, published** Claude Code SaaS plugin (`agentguards-claude`)
inside a container, over a real pseudo-terminal, and asserts on what a user's
terminal actually shows — not on a hook function's return value.

## How this differs from `../test_hook_security_behaviour.py`

That suite loads each shipped hook script and calls its handlers directly with
synthetic stdin. It proves the hook **logic** is correct, fast and without
Docker. It cannot see anything that only exists once real Claude Code renders
a session — which is exactly the class of bug that has shipped before: PR #258
fixed a block message that echoed the raw attacker prompt back to the model, a
UI-rendering regression a direct function call can't observe. This suite
installs the plugin the way a user would (`/plugin marketplace add`,
`/plugin install`) and drives an actual `claude` TUI session to catch that
class of bug.

## Run it

```bash
export AGENTGUARDS_API_KEY=ag_your_token_here      # https://agentguards.co/dashboard/keys
export ANTHROPIC_API_KEY=sk-ant-...
./run.sh
```

Or via the `test-plugin-e2e` skill in the `agentguards` monorepo, which wraps
this as the pre-release gate.

Needs Docker and network access to prod SaaS. There is no CI wiring for this
yet — it needs live credentials against prod, which is a secrets/cost
decision that hasn't been made; run it by hand before a release.

## What it checks

| Check | What it catches |
|---|---|
| Plugin installs and MCP connects | 0.2.18-class bug: plugin errors on every event, nothing past this point ever runs |
| Normal prompt gets a normal reply | guardrail false-positive on benign input |
| Blocking prompt shows the readable block message | PR #258-class bug: raw JSON or the attacker's own prompt leaking into what the model/user reads next |
| No known error signatures in the transcript | install failures (`ERR_STREAM_PREMATURE_CLOSE`), MCP disconnects, unhandled exceptions |

## Gotchas

- **DNS**: if the host Docker daemon pins a VPN resolver, `docker run` and
  `docker build` fail to resolve anything without `--dns 8.8.8.8`. The
  container fixture already passes this; only matters if you invoke `docker`
  by hand.
- **`node:22-slim` ships no `git`.** Without it, `/plugin marketplace add`
  fails with `ERR_STREAM_PREMATURE_CLOSE` and an SSH-shaped error — the git
  binary never existed, SSH is never reached. The `Dockerfile` installs git
  and rewrites the SSH remote to HTTPS so no key is needed (the plugin repo
  is public).
- **`docker exec -i` without `-t` never starts the TUI.** `drive_session.py`
  uses a real pty for exactly this reason — don't "simplify" it to a plain
  pipe.
- **Needs a real API key to test real block behavior.** Per
  `../conftest.py`: the SaaS `claude` plugin is the one hook that
  warns-and-allows when unconfigured (Claude Desktop has no shell profile to
  export a key into). Without `AGENTGUARDS_API_KEY` set, the blocking-prompt
  assertion would fail for the wrong reason.
- Never redirect a raw transcript to a tracked file — `output/` is
  gitignored because the container carries a live `AGENTGUARDS_API_KEY` in
  its environment.

## Adding a check

Per `../README.md`'s rule: **watch it fail first.** Reintroduce the bug you're
guarding against, confirm the new assertion goes red, then fix it and confirm
green.
