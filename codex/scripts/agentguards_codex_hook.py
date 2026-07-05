#!/usr/bin/env python3
"""Codex CLI hook for AgentGuards guardrails.

Handles UserPromptSubmit, PreToolUse and PostToolUse hooks. Reads JSON from
stdin, calls the AgentGuards REST API, and either lets the action continue or
asks the user to approve it. Prompt-injection / policy hits on the prompt are
blocked outright; shell commands are surfaced for approval rather than silently
blocked, and an approved command isn't re-asked again the same session.

At PostToolUse, output from web-fetching shell commands (curl, wget, etc.) is
scanned with use_case="web_fetch" and withheld if AgentGuards flags it.

Setup:
    1. Save this file as ~/.codex/agentguards_codex_hook.py
    2. Save your ag_ token:  echo "ag_..." > ~/.codex/agentguards_token
    3. Register the hooks in ~/.codex/config.toml (see the dashboard snippet).

Environment overrides:
    AGENTGUARDS_URL      Base URL (default https://prod.agentguards.co)
    AGENTGUARDS_API_KEY  ag_ token (falls back to ~/.codex/agentguards_token)
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# Block panels include a shield glyph (🛡️); avoid a non-UTF-8 locale crashing output.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except Exception:
        pass

AGENTGUARDS_URL = os.getenv("AGENTGUARDS_URL", "https://prod.agentguards.co").rstrip("/")

# Per-session approval cache. A command reaching PostToolUse actually ran (= it
# was approved), so we remember its binaries keyed by session_id and skip
# re-asking for them later that session. The risk scorer always runs first, so a
# remembered binary can never carry a destructive command through.
_APPROVALS_PATH = str(Path.home() / ".codex" / "agentguards_session_approvals.json")
_SESSION_TTL = 7 * 24 * 3600


def _api_key() -> str:
    key = os.getenv("AGENTGUARDS_API_KEY", "").strip()
    if key:
        return key
    token_file = Path.home() / ".codex" / "agentguards_token"
    if token_file.exists():
        return token_file.read_text().strip()
    return ""


def _fail_open() -> bool:
    # Escape hatch for transient outages. Default is fail-CLOSED (block).
    return os.getenv("AGENTGUARDS_FAIL_OPEN", "").strip().lower() in ("1", "true", "yes", "on")


class QuotaExceededError(Exception):
    """API returned 429 QUOTA_EXCEEDED — a real quota block, not a service outage."""

    def __init__(self, message: str):
        super().__init__(message)
        self.user_message = message


def _post(path: str, payload: dict) -> dict:
    req = urllib.request.Request(
        f"{AGENTGUARDS_URL}{path}",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "X-API-Key": _api_key()},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            try:
                body = json.loads(exc.read())
            except Exception:
                body = {}
            if body.get("error") == "QUOTA_EXCEEDED":
                raise QuotaExceededError(body.get("message") or "Monthly request quota reached.")
        raise


def _command_binaries(command: str) -> list:
    """Leading binary of each pipeline segment (skips leading VAR=val)."""
    binaries = []
    for segment in re.split(r"\|\||&&|[|;&\n]", str(command or "")):
        tokens = segment.strip().split()
        idx = 0
        while idx < len(tokens) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[idx]):
            idx += 1
        if idx < len(tokens):
            binaries.append(tokens[idx].split("/")[-1])
    return binaries


def _load_approvals() -> dict:
    try:
        with open(_APPROVALS_PATH) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _approved_binaries(session_id: str) -> set:
    if not session_id:
        return set()
    entry = _load_approvals().get(session_id) or {}
    return set(entry.get("binaries", []))


def _remember_binaries(session_id: str, binaries: list) -> None:
    if not session_id or not binaries:
        return
    data = _load_approvals()
    entry = data.get(session_id) or {}
    merged = sorted(set(entry.get("binaries", [])) | set(binaries))
    data[session_id] = {"binaries": merged, "ts": time.time()}
    now = time.time()
    data = {
        sid: e for sid, e in data.items()
        if isinstance(e, dict) and now - e.get("ts", 0) < _SESSION_TTL
    }
    try:
        os.makedirs(os.path.dirname(_APPROVALS_PATH), exist_ok=True)
        with open(_APPROVALS_PATH, "w") as fh:
            json.dump(data, fh)
    except OSError:
        pass


_FETCH_BINARIES = {"curl", "wget", "http", "https", "fetch", "aria2c"}


def _is_fetch_command(command: str) -> bool:
    return any(b in _FETCH_BINARIES for b in _command_binaries(command))


def _extract_tool_response(event: dict) -> str:
    response = event.get("tool_response")
    if isinstance(response, str):
        return response
    if isinstance(response, dict):
        for key in ("output", "stdout", "content", "text", "result"):
            value = response.get(key)
            if isinstance(value, str) and value:
                return value
        return json.dumps(response)
    return ""


def _continue() -> None:
    # Exit 0 with no output -> Codex continues its normal flow.
    sys.exit(0)


def _block_prompt(reason: str) -> None:
    print(json.dumps({"decision": "block", "reason": reason}))
    sys.exit(0)


def _block_output(reason: str) -> None:
    # PostToolUse block: decision:"block" makes Codex replace the tool result
    # before the model sees it.
    print(
        json.dumps(
            {
                "decision": "block",
                "reason": reason,
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "additionalContext": f"AgentGuards withheld fetched web content: {reason}",
                },
            }
        )
    )
    sys.exit(0)


def _scan_web_output(content: str) -> None:
    """Scan curl/wget output through the web_fetch guardrail; block if flagged."""
    if not content.strip():
        return
    try:
        result = _post(
            "/v1/guardrails/evaluate-input",
            {"text": content, "use_case": "web_fetch", "channel": "codex_hook"},
        )
    except QuotaExceededError as exc:
        _block_output(f"AgentGuards monthly quota reached: {exc.user_message} Fetched web content withheld.")
    except Exception as exc:
        if _fail_open():
            print(f"AgentGuards: service unreachable ({exc}), allowing web content (AGENTGUARDS_FAIL_OPEN=true)", file=sys.stderr)
            return
        _block_output(f"AgentGuards unreachable ({exc}) — fetched web content withheld (fail-closed).")
    decision = result.get("decision", "allow")
    if decision not in ("allow",):
        # Server composes the full structured panel; print it + a snippet of the content.
        message = result.get("message") or "🛡️ [AgentGuards] Web content blocked\nDecision: block\nReason: policy - flagged by AgentGuards guardrails\nSeverity: high"
        flagged = result.get("flagged_input")
        text = f"{message}\n\n    {flagged}" if flagged else message
        _block_output(text)


def _ask(reason: str) -> None:
    # Surface the command for user approval instead of blocking it outright.
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "ask",
                    "permissionDecisionReason": reason,
                }
            }
        )
    )
    sys.exit(0)


def _deny(reason: str) -> None:
    # Hard-block a command (used for fail-closed config / outage cases).
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }
        )
    )
    sys.exit(0)


def _allow_tool(reason: str) -> None:
    # Codex has no "allow" permissionDecision (it rejects it) — let the command run
    # by exiting 0 with no output, so Codex proceeds with its normal flow.
    _continue()


def handle_user_prompt(event: dict) -> None:
    prompt = event.get("prompt", "")
    if not prompt.strip():
        _continue()
    try:
        result = _post("/v1/guardrails/evaluate-input", {"text": prompt, "use_case": "check"})
    except QuotaExceededError as exc:
        _block_prompt(f"[AgentGuards] Monthly quota reached: {exc.user_message}")
    except Exception as exc:
        if _fail_open():
            print(f"AgentGuards: service unreachable ({exc}), allowing prompt (AGENTGUARDS_FAIL_OPEN=true)", file=sys.stderr)
            _continue()
        _block_prompt(
            f"[AgentGuards] Prompt blocked: service unreachable ({exc}); the hook is "
            f"fail-closed. Set AGENTGUARDS_FAIL_OPEN=true to allow while it is down."
        )
    if result.get("decision", "allow") in ("block", "escalate", "redact"):
        # Server composes the full structured panel; print it + the flagged input.
        message = result.get("message") or "🛡️ [AgentGuards] Prompt blocked\nDecision: block\nReason: policy - flagged by AgentGuards guardrails\nSeverity: high"
        flagged = result.get("flagged_input")
        text = f"{message}\n\n    {flagged}" if flagged else message
        _block_prompt(text)
    _continue()


def handle_pre_tool_use(event: dict) -> None:
    tool_name = event.get("tool_name", "")
    tool_input = event.get("tool_input", {}) or {}
    command = tool_input.get("command")
    session_id = event.get("session_id", "")
    if not command:
        _continue()
    try:
        result = _post(
            "/v1/actions/authorize",
            {
                "action": "shell_command",
                "tool": tool_name or "shell",
                "parameters": {"command": command},
            },
        )
    except QuotaExceededError as exc:
        _deny(f"AgentGuards monthly quota reached: {exc.user_message}")
    except Exception as exc:
        if _fail_open():
            print(f"AgentGuards: service unreachable ({exc}), allowing tool call (AGENTGUARDS_FAIL_OPEN=true)", file=sys.stderr)
            _continue()
        _deny(
            f"AgentGuards is unreachable ({exc}) and the hook is fail-closed. "
            f"Set AGENTGUARDS_FAIL_OPEN=true to allow while it is down."
        )
    decision = result.get("decision", "allow")
    # allow -> run with no prompt (safe baseline). "deny" (destructive command)
    # is hard-blocked. Anything else is surfaced for approval ("ask") unless every
    # binary was already approved this session. The risk scorer ran first, so a
    # remembered binary still can't carry a destructive command through.
    # The server composes the full structured panel (shield + heading + Decision/
    # Reason/Severity); print it verbatim, then the command that was flagged.
    reason = result.get("reason") or "🛡️ [AgentGuards] Command blocked\nDecision: deny\nReason: policy - flagged by AgentGuards guardrails\nSeverity: high"
    shown = command if len(str(command)) <= 500 else str(command)[:500] + "..."
    if decision == "deny":
        _deny(f"{reason}\n\n    {shown}")
    if decision == "allow":
        _allow_tool("AgentGuards: safe baseline")
    binaries = _command_binaries(command)
    if binaries and all(b in _approved_binaries(session_id) for b in binaries):
        _allow_tool("AgentGuards: approved earlier this session")
    _ask(f"{reason}\n\n    {shown}")


def handle_post_tool_use(event: dict) -> None:
    command = (event.get("tool_input", {}) or {}).get("command")
    # Scan output from web-fetching shell commands before the model sees it.
    if command and _is_fetch_command(command):
        _scan_web_output(_extract_tool_response(event))
    # Remember approved binaries for this session to skip re-asking next time.
    if command:
        _remember_binaries(event.get("session_id", ""), _command_binaries(command))
    _continue()


def main() -> None:
    event_type = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        event = json.loads(sys.stdin.read())
    except json.JSONDecodeError:
        _continue()
    if event_type == "PostToolUse":
        handle_post_tool_use(event)
        return
    if not _api_key():
        # Fail-closed: refuse until the token is configured.
        message = (
            "AgentGuards is not configured: save your ag_ token to "
            "~/.codex/agentguards_token (or set AGENTGUARDS_API_KEY). The hook is fail-closed."
        )
        if event_type == "PreToolUse":
            _deny(message)
        else:
            _block_prompt(message)
    if event_type == "UserPromptSubmit":
        handle_user_prompt(event)
    elif event_type == "PreToolUse":
        handle_pre_tool_use(event)
    else:
        _continue()


if __name__ == "__main__":
    main()
