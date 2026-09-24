#!/bin/sh
# Runs one Codex hook event (the only argument) through AgentGuards.
#
# Prefers the `agentguards` binary (installed by the AgentGuards installer): the
# same guardrails with no Python needed. Falls back to the Python hook next to
# this file, so a plugin installed without the installer keeps working exactly
# as before. `exec` hands over stdin (the event), stdout (the verdict) and the
# exit code unchanged.
event="${1:-}"
here="$(cd "$(dirname "$0")" && pwd)"

# `hook --supports codex` guards against an installed binary too old to run hooks
# (CLI 0.1.0 had none): that one is skipped and Python is used instead.
for bin in "$HOME/.agentguards/bin/agentguards" "$(command -v agentguards 2>/dev/null)"; do
  if [ -n "$bin" ] && [ -x "$bin" ] && "$bin" hook --supports codex >/dev/null 2>&1; then
    exec "$bin" hook codex "$event"
  fi
done
exec python3 "$here/agentguards_codex_hook.py" "$event"
