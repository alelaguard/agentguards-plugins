#!/usr/bin/env bash
# Dispatches one hook event to the right runtime for this machine.
#
# This exists to keep hooks.json's `command` short. Claude Code prints the whole
# command in brackets ahead of a hook's message, so a 561-character inline shell
# one-liner meant a blocked prompt rendered as a wall of shell before the user
# reached "Prompt blocked":
#
#   A hook blocked your prompt
#   [if [ "$OS" = "Windows_NT" ]; then PS=powershell; command -v powershell …
#    elif command -v python3 …]: 🛡️ [AgentGuards] Prompt blocked Decision: block …
#
# The logic is unchanged; it just lives in a file now, so the bracket reads
# [.../scripts/run-hook.sh UserPromptSubmit] and the message is legible.
#
# Argument: the event name, passed straight through to the hook.
set -u

event="${1:-}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# LLM usage reports (agentguards_usage.py) — opt-in, Linux/macOS only for now.
#   They must cost nothing while tracking is off. The marker file exists only while
#   the dashboard has it on. Without it, UsageTick (after EVERY tool call) ends here
#   before any interpreter starts, and a turn end starts Python only when the cached
#   "is it on?" answer is over an hour old. Windows (PowerShell hook) has no usage
#   reports yet, so these events end here there too.
case "$event" in
  Stop|SubagentStop|UsageTick)
    if [ "${OS:-}" = "Windows_NT" ]; then exit 0; fi
    if [ ! -f "${HOME}/.claude/agentguards_usage_on" ]; then
      [ "$event" = "UsageTick" ] && exit 0
      cfg="${HOME}/.claude/agentguards_usage_config.json"
      if [ -f "$cfg" ] && [ -n "$(find "$cfg" -mmin -60 2>/dev/null)" ]; then exit 0; fi
    fi
    command -v python3 >/dev/null 2>&1 || exit 0
    ;;
esac

if [ "${OS:-}" = "Windows_NT" ]; then
  ps=powershell
  command -v powershell >/dev/null 2>&1 || ps=pwsh
  "$ps" -NoProfile -ExecutionPolicy Bypass -File "$here/agentguards_hook.ps1" "$event"
  exit $?
fi

if command -v python3 >/dev/null 2>&1; then
  python3 "$here/agentguards_hook.py" "$event"
  exit $?
fi

# No Python and not Windows: the guardrails cannot run. Say so through the one
# channel each event actually surfaces on a zero exit — stderr from a hook that
# exits 0 reaches only the debug log, so a warning there would never be seen.
case "$event" in
  PreToolUse)
    # permissionDecisionReason is the only field shown to the user here.
    printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"AgentGuards: Python is not installed - command authorization is OFF. Install it from https://www.python.org/downloads/ and restart Claude. Tell the user this: they are not protected."}}'
    ;;
  UserPromptSubmit)
    # stdout is added to the model's context, so Claude can pass this on.
    echo "AgentGuards: Python is not installed - guardrails are OFF for this message. Install it from https://www.python.org/downloads/ then fully quit and reopen Claude. Tell the user this: they are not protected."
    ;;
  *)
    # PostToolUse and anything else: nothing useful to say, and no channel to say
    # it on. Stay silent rather than emit noise on every tool call.
    ;;
esac
exit 0
