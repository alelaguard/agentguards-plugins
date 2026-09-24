#!/bin/sh
# Runs one Codex hook event (the only argument) through AgentGuards on Linux and
# macOS. Windows runs agentguards_codex_hook.ps1 instead (commandWindows in
# hooks/hooks.json), since Codex runs Windows hooks with cmd.exe.
# `exec` hands over stdin (the event), stdout (the verdict) and the exit code.
event="${1:-}"
here="$(cd "$(dirname "$0")" && pwd)"
# Unset OR empty -> prod, exactly what the pre-0.2.16 hook command did. (Python's
# os.getenv(name, default) returns "" for an empty variable, which breaks every call.)
: "${AGENTGUARDS_URL:=https://prod.agentguards.co}"
export AGENTGUARDS_URL
exec python3 "$here/agentguards_codex_hook.py" "$event"
