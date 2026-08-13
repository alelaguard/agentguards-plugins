#!/usr/bin/env bash
# One-line entry point for the plugin e2e smoke test. See README.md for what
# it checks and .claude/skills/test-plugin-e2e in the agentguards monorepo for
# when to run it.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

: "${AGENTGUARDS_API_KEY:?set AGENTGUARDS_API_KEY -- https://agentguards.co/dashboard/keys}"
: "${ANTHROPIC_API_KEY:?set ANTHROPIC_API_KEY}"

# Host-side deps (pytest drives docker/pty from the host, not from inside the
# container) — installed into a local venv rather than assumed present.
if [ ! -d .venv ]; then
  python3 -m venv .venv
  .venv/bin/pip install --quiet -r requirements.txt
fi

.venv/bin/pytest test_plugin_smoke.py -v "$@"
