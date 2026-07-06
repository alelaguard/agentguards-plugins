#!/usr/bin/env python3
"""GitHub Copilot CLI hook for AgentGuards guardrails.

Handles userPromptSubmitted, preToolUse and postToolUse hooks. Reads JSON from
stdin, calls the AgentGuards REST API, and prints JSON to stdout using Copilot
CLI's native hook protocol (not the VS Code compat / hookSpecificOutput shape):
  - userPromptSubmitted block: {"decision": "block", "reason": "..."}
  - preToolUse:  {"permissionDecision": "allow"|"ask"|"deny",
                  "permissionDecisionReason": "..."}
  - postToolUse content withheld: {"decision": "block", "reason": "...",
                  "additionalContext": "..."}

At postToolUse, output from web-fetching shell commands (curl, wget, etc.) is
scanned with use_case="web_fetch" and flagged if AgentGuards detects an issue
(e.g. an indirect prompt injection planted in a page).

Setup:
    1. Save this file as ~/.copilot/agentguards_copilot_hook.py (or install the
       agentguards-copilot plugin, which bundles it).
    2. Register the hooks in a plugin hooks.json (see the dashboard snippet).

Environment overrides:
    AGENTGUARDS_URL      Base URL (default https://prod.agentguards.co)
    AGENTGUARDS_API_KEY  ag_ token
    AGENTGUARDS_FAIL_OPEN  Set to "true" to allow when service is unreachable
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.request

AGENTGUARDS_URL = os.getenv("AGENTGUARDS_URL", "https://prod.agentguards.co").rstrip("/")

_APPROVALS_PATH = os.path.expanduser("~/.copilot/agentguards_session_approvals.json")
_SESSION_TTL = 7 * 24 * 3600


def _api_key() -> str:
    return os.getenv("AGENTGUARDS_API_KEY", "").strip()


def _fail_open() -> bool:
    return os.getenv("AGENTGUARDS_FAIL_OPEN", "").strip().lower() in ("1", "true", "yes", "on")


def _post(path: str, payload: dict) -> dict:
    req = urllib.request.Request(
        f"{AGENTGUARDS_URL}{path}",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "X-API-Key": _api_key()},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def _continue() -> None:
    # Exit 0 with no output -> Copilot CLI continues its normal flow.
    sys.exit(0)


def _block_prompt(reason: str) -> None:
    print(json.dumps({"decision": "block", "reason": reason}))
    sys.exit(0)


def _block_output(reason: str) -> None:
    print(
        json.dumps(
            {
                "decision": "block",
                "reason": reason,
                "additionalContext": f"AgentGuards withheld fetched web content: {reason}",
            }
        )
    )
    sys.exit(0)


def _ask(reason: str) -> None:
    print(json.dumps({"permissionDecision": "ask", "permissionDecisionReason": reason}))
    sys.exit(0)


def _deny(reason: str) -> None:
    print(json.dumps({"permissionDecision": "deny", "permissionDecisionReason": reason}))
    sys.exit(0)


def _allow_tool(reason: str) -> None:
    print(json.dumps({"permissionDecision": "allow", "permissionDecisionReason": reason}))
    sys.exit(0)


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


def _tool_name(event: dict) -> str:
    return event.get("toolName") or event.get("tool_name") or ""


def _tool_args(event: dict) -> dict:
    return event.get("toolArgs") or event.get("tool_input") or {}


def _tool_command(tool_args: dict) -> str:
    return str(tool_args.get("command") or tool_args.get("cmd") or "")


_FETCH_BINARIES = {"curl", "wget", "http", "https", "fetch", "aria2c"}


def _is_fetch_command(command: str) -> bool:
    return any(b in _FETCH_BINARIES for b in _command_binaries(command))


def _tool_result_text(event: dict) -> str:
    result = event.get("toolResult") or event.get("tool_result") or {}
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        for key in ("textResultForLlm", "text_result_for_llm", "sessionLog", "session_log"):
            value = result.get(key)
            if isinstance(value, str) and value:
                return value
        return json.dumps(result)
    return ""


def handle_user_prompt_submitted(event: dict) -> None:
    prompt = event.get("prompt", "")
    if not prompt.strip():
        _continue()
    try:
        result = _post("/v1/guardrails/evaluate-input", {"text": prompt, "use_case": "check"})
    except Exception as exc:
        if _fail_open():
            print(f"AgentGuards: service unreachable ({exc}), allowing prompt (AGENTGUARDS_FAIL_OPEN=true)", file=sys.stderr)
            _continue()
        _block_prompt(
            f"[AgentGuards] Prompt blocked: service unreachable ({exc}); the hook is "
            f"fail-closed. Set AGENTGUARDS_FAIL_OPEN=true to allow while it is down."
        )
    if result.get("decision", "allow") in ("block", "escalate", "redact"):
        checks = result.get("checks", [])
        hit = next((c for c in checks if not c.get("passed", True)), {})
        _block_prompt(
            f"[AgentGuards] Prompt blocked: {hit.get('check_name', 'policy')} - "
            f"{hit.get('reason', result.get('decision'))} "
            f"(severity: {hit.get('severity', 'unknown')})"
        )
    _continue()


def handle_pre_tool_use(event: dict) -> None:
    tool_name = _tool_name(event)
    tool_args = _tool_args(event)
    command = _tool_command(tool_args)
    session_id = event.get("sessionId") or event.get("session_id") or ""
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
    except Exception as exc:
        if _fail_open():
            print(f"AgentGuards: service unreachable ({exc}), allowing tool call (AGENTGUARDS_FAIL_OPEN=true)", file=sys.stderr)
            _continue()
        _deny(
            f"AgentGuards is unreachable ({exc}) and the hook is fail-closed. "
            f"Set AGENTGUARDS_FAIL_OPEN=true to allow while it is down."
        )
    decision = result.get("decision", "allow")
    risk = result.get("risk_level", "unknown")
    reason = result.get("reason") or "flagged by AgentGuards policy"
    shown = command if len(str(command)) <= 500 else str(command)[:500] + "..."
    if decision == "deny":
        _deny(
            f"""AgentGuards blocked this command:

    {shown}

Reason: {reason} (risk: {risk})"""
        )
    if decision == "allow":
        _allow_tool("AgentGuards: safe baseline")
    binaries = _command_binaries(command)
    if binaries and all(b in _approved_binaries(session_id) for b in binaries):
        _allow_tool("AgentGuards: approved earlier this session")
    _ask(
        f"""AgentGuards needs approval to run:

    {shown}

Reason: {reason} (risk: {risk})"""
    )


def handle_post_tool_use(event: dict) -> None:
    tool_name = _tool_name(event)
    tool_args = _tool_args(event)
    command = _tool_command(tool_args)
    session_id = event.get("sessionId") or event.get("session_id") or ""

    if command and _is_fetch_command(command):
        text = _tool_result_text(event)
        if text.strip():
            try:
                result = _post(
                    "/v1/guardrails/evaluate-input",
                    {"text": text, "use_case": "web_fetch", "channel": "copilot_cli"},
                )
            except Exception as exc:
                if _fail_open():
                    print(f"AgentGuards: service unreachable ({exc}), allowing web content (AGENTGUARDS_FAIL_OPEN=true)", file=sys.stderr)
                else:
                    _block_output(f"AgentGuards unreachable ({exc}) — fetched web content withheld (fail-closed).")
            else:
                decision = result.get("decision", "allow")
                if decision not in ("allow",):
                    checks = result.get("checks", [])
                    hit = next((c for c in checks if not c.get("passed", True)), {})
                    _block_output(f"{hit.get('check_name', 'policy')} — {hit.get('reason', decision)}")

    _remember_binaries(session_id, _command_binaries(command) + ([tool_name] if tool_name else []))
    _continue()


def main() -> None:
    event_type = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        event = json.loads(sys.stdin.read())
    except json.JSONDecodeError:
        _continue()

    if event_type == "postToolUse":
        handle_post_tool_use(event)
        return

    if not _api_key():
        if event_type == "preToolUse":
            _deny(
                "AGENTGUARDS_API_KEY is not set. The hook is fail-closed, so it blocks "
                "until configured."
            )
        _block_prompt(
            "AGENTGUARDS_API_KEY is not set. The hook is fail-closed, so it blocks "
            "until configured."
        )

    if event_type == "userPromptSubmitted":
        handle_user_prompt_submitted(event)
    elif event_type == "preToolUse":
        handle_pre_tool_use(event)
    else:
        _continue()


if __name__ == "__main__":
    main()
