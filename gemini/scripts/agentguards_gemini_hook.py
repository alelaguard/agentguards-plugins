#!/usr/bin/env python3
"""Gemini CLI hook script for AgentGuards guardrails.

Handles BeforeAgent, BeforeTool and AfterTool hooks. Reads JSON from stdin,
calls the AgentGuards REST API, and outputs JSON to stdout (Gemini's blocking
protocol — {"decision": "deny"} to block, {} to allow).

At AfterTool, content fetched by the built-in web_fetch / google_web_search tools
is scanned with use_case="web_fetch" and denied (withheld from the agent) if
AgentGuards flags it — e.g. an indirect prompt injection planted in a webpage.
run_shell_command output is scanned the same way when the command invokes a fetch
binary (curl, wget, etc.) — this does NOT rely on the model cooperatively calling
the MCP check_input tool; it is enforced here regardless of what the model does.

Install:
    cp scripts/agentguards_gemini_hook.py ~/.gemini/agentguards_gemini_hook.py

Configure in ~/.gemini/settings.json:
    {
      "hooks": {
        "BeforeAgent": [{
          "hooks": [{"type": "command",
            "command": "python3 ~/.gemini/agentguards_gemini_hook.py BeforeAgent"}]
        }],
        "BeforeTool": [{
          "matcher": ".*",
          "hooks": [{"type": "command",
            "command": "python3 ~/.gemini/agentguards_gemini_hook.py BeforeTool"}]
        }],
        "AfterTool": [{
          "matcher": ".*",
          "hooks": [{"type": "command",
            "command": "python3 ~/.gemini/agentguards_gemini_hook.py AfterTool"}]
        }]
      }
    }

Environment variables:
    AGENTGUARDS_URL      Base URL of your AgentGuards instance (required)
    AGENTGUARDS_API_KEY  Your ag_ API token (required)
    AGENTGUARDS_FAIL_OPEN  Set to "true" to allow when service is unreachable
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.request
import urllib.error

# Block panels include a shield glyph (🛡️); avoid a non-UTF-8 locale crashing output.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except Exception:
        pass

AGENTGUARDS_URL = os.getenv("AGENTGUARDS_URL", "").rstrip("/")
AGENTGUARDS_API_KEY = os.getenv("AGENTGUARDS_API_KEY", "")

_APPROVALS_PATH = os.path.expanduser("~/.gemini/agentguards_session_approvals.json")
_SESSION_TTL = 7 * 24 * 3600


class QuotaExceededError(Exception):
    """API returned 429 QUOTA_EXCEEDED — a real quota block, not a service outage.

    Carries the human-readable message so the hook can show it verbatim instead of
    routing it through the "service unreachable" fail-open/closed branch.
    """

    def __init__(self, message: str):
        super().__init__(message)
        self.user_message = message


def _post(path: str, payload: dict) -> dict:
    url = f"{AGENTGUARDS_URL}{path}"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": AGENTGUARDS_API_KEY,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        # A 429 QUOTA_EXCEEDED is a deliberate block with a user-facing message —
        # surface it as such rather than as an opaque transport error.
        if exc.code == 429:
            try:
                body = json.loads(exc.read())
            except Exception:
                body = {}
            if body.get("error") == "QUOTA_EXCEEDED":
                raise QuotaExceededError(body.get("message") or "Monthly request quota reached.")
        raise


def _block(reason: str, user_message: str | None = None) -> None:
    # Gemini CLI blocks on {"decision": "deny"} in stdout (exit 0). The "reason"
    # is sent back to the agent as an error; "systemMessage" is shown to the user.
    out: dict = {"decision": "deny", "reason": reason}
    if user_message:
        out["systemMessage"] = user_message
    print(json.dumps(out))
    sys.exit(0)


def _allow() -> None:
    print("{}")
    sys.exit(0)


def _fail_open() -> bool:
    return os.getenv("AGENTGUARDS_FAIL_OPEN", "").strip().lower() in ("1", "true", "yes", "on")


def _command_binaries(command: str) -> list[str]:
    """Leading binary of each pipeline segment (skips leading VAR=val)."""
    binaries: list[str] = []
    for segment in re.split(r"\|\||&&|[|;&\n]", command or ""):
        tokens = segment.strip().split()
        idx = 0
        while idx < len(tokens) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[idx]):
            idx += 1
        if idx < len(tokens):
            binaries.append(tokens[idx].split("/")[-1])
    return binaries


def _tool_cache_keys(tool_name: str, tool_input: dict) -> list[str]:
    """Cache keys for an approved tool call. Shell-like tools also yield their binaries."""
    keys = [tool_name]
    command = tool_input.get("command") or tool_input.get("cmd") or ""
    if command:
        keys.extend(_command_binaries(str(command)))
    return keys


def _load_approvals() -> dict:
    try:
        with open(_APPROVALS_PATH) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _approved_keys(session_id: str) -> set:
    if not session_id:
        return set()
    entry = _load_approvals().get(session_id) or {}
    return set(entry.get("keys", []))


def _remember_keys(session_id: str, keys: list[str]) -> None:
    if not session_id or not keys:
        return
    data = _load_approvals()
    entry = data.get(session_id) or {}
    merged = sorted(set(entry.get("keys", [])) | set(keys))
    data[session_id] = {"keys": merged, "ts": time.time()}
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


def _session_id(event: dict) -> str:
    return event.get("session_id") or os.getenv("GEMINI_SESSION_ID", "")


# Gemini's built-in web tools whose fetched content must be scanned.
_WEB_TOOLS = ("web_fetch", "google_web_search")

# The built-in shell tool; its output is scanned too when it invokes a fetch binary.
_SHELL_TOOLS = ("run_shell_command",)
_FETCH_BINARIES = {"curl", "wget", "http", "https", "fetch", "aria2c"}


def _is_fetch_command(command: str) -> bool:
    return any(b in _FETCH_BINARIES for b in _command_binaries(command))


def _extract_web_text(tool_response) -> str:
    """Pull fetched content out of a web_fetch / google_web_search / shell response.

    web_fetch returns a markdown string (or a dict wrapping one); google_web_search
    returns a list of result dicts; run_shell_command returns a dict with PascalCase
    keys (Command/Directory/Stdout/Stderr/Exit Code/Background PIDs).
    """
    if isinstance(tool_response, str):
        return tool_response
    if isinstance(tool_response, dict):
        for key in ("output", "result", "content", "text", "response", "Stdout"):
            value = tool_response.get(key)
            if isinstance(value, str):
                return value
        return json.dumps(tool_response)
    if isinstance(tool_response, list):
        parts: list[str] = []
        for item in tool_response:
            if isinstance(item, dict):
                parts.append(
                    " ".join(
                        str(item.get(k, ""))
                        for k in ("title", "snippet", "content", "url")
                        if item.get(k)
                    )
                )
            else:
                parts.append(str(item))
        return "\n".join(p for p in parts if p)
    return ""


def _scan_web_content(tool_name: str, tool_response) -> None:
    # Runs at AfterTool for the built-in web tools. Gemini's AfterTool honors
    # {"decision": "deny"} — it blocks the turn and sends the reason to the agent
    # as a tool error — so a bad verdict here genuinely withholds the content.
    text = _extract_web_text(tool_response)
    if not text.strip():
        return

    if not AGENTGUARDS_URL or not AGENTGUARDS_API_KEY:
        if _fail_open():
            return
        _block(
            "AgentGuards not configured and the hook is fail-closed. "
            "Set AGENTGUARDS_URL/AGENTGUARDS_API_KEY (or AGENTGUARDS_FAIL_OPEN=true).",
            "[AgentGuards] Web content withheld — hook not configured (fail-closed).",
        )

    try:
        result = _post(
            "/v1/guardrails/evaluate-input",
            {"text": text, "use_case": "web_fetch", "channel": "gemini_cli"},
        )
    except QuotaExceededError as exc:
        _block(
            f"AgentGuards monthly quota reached: {exc.user_message}",
            f"[AgentGuards] Monthly quota reached — {exc.user_message}",
        )
    except Exception as exc:
        if _fail_open():
            print(
                f"AgentGuards: service unreachable ({exc}), allowing web content (AGENTGUARDS_FAIL_OPEN=true)",
                file=sys.stderr,
            )
            return
        _block(
            f"AgentGuards is unreachable ({exc}) and the hook is fail-closed.",
            "[AgentGuards] Web content withheld — service unreachable (fail-closed).",
        )

    # Any non-allow aggregate (redact/safe-complete-only included) means the
    # service flagged the content — withhold it rather than passing the original.
    decision = result.get("decision", "allow")
    if decision not in ("allow",):
        # Server composes the full structured panel; print it + a snippet of the content.
        message = result.get("message") or "🛡️ [AgentGuards] Web content blocked\nDecision: block\nReason: policy - flagged by AgentGuards guardrails\nSeverity: high"
        flagged = result.get("flagged_input")
        detail = f"{message}\n\n    {flagged}" if flagged else message
        _block(detail, "[AgentGuards] Web content withheld")


def handle_before_agent(event: dict) -> None:
    prompt = event.get("prompt", "")
    if not prompt.strip():
        _allow()

    try:
        result = _post("/v1/guardrails/evaluate-input", {"text": prompt, "use_case": "gemini_cli"})
    except QuotaExceededError as exc:
        _block(
            f"AgentGuards monthly quota reached: {exc.user_message}",
            f"[AgentGuards] Monthly quota reached — {exc.user_message}",
        )
    except Exception as exc:
        if _fail_open():
            print(f"AgentGuards: service unreachable ({exc}), allowing (AGENTGUARDS_FAIL_OPEN=true)", file=sys.stderr)
            _allow()
        _block(
            f"AgentGuards is unreachable ({exc}) and the hook is fail-closed. "
            "Set AGENTGUARDS_FAIL_OPEN=true to allow prompts while the service is down.",
            "[AgentGuards] Service unreachable — request blocked (fail-closed).",
        )

    decision = result.get("decision", "allow")
    if decision in ("block", "escalate"):
        # Server composes the full structured panel; print it + the flagged input.
        message = result.get("message") or "🛡️ [AgentGuards] Prompt blocked\nDecision: block\nReason: policy - flagged by AgentGuards guardrails\nSeverity: high"
        flagged = result.get("flagged_input")
        detail = f"{message}\n\n    {flagged}" if flagged else message
        _block(detail, "[AgentGuards] Prompt blocked")
    _allow()


def handle_before_tool(event: dict) -> None:
    tool_name = event.get("tool_name", "")
    tool_input = event.get("tool_input") or {}
    session_id = _session_id(event)

    # The risk scorer ALWAYS runs first — the session cache can only downgrade a
    # require-approval into "allow", never override a deny. (If we short-circuited
    # on the cache before scoring, a tool whose name/binary was approved once would
    # bypass scoring for any later parameters, e.g. an approved write_file could
    # then write to ~/.ssh/authorized_keys unscored.)
    try:
        result = _post(
            "/v1/actions/authorize",
            {"action": "tool_call", "tool": tool_name, "parameters": tool_input},
        )
    except QuotaExceededError as exc:
        _block(
            f"AgentGuards monthly quota reached: {exc.user_message}",
            f"[AgentGuards] Monthly quota reached — {exc.user_message}",
        )
    except Exception as exc:
        if _fail_open():
            print(f"AgentGuards: service unreachable ({exc}), allowing tool call (AGENTGUARDS_FAIL_OPEN=true)", file=sys.stderr)
            _allow()
        _block(
            f"AgentGuards is unreachable ({exc}) and the hook is fail-closed. "
            "Set AGENTGUARDS_FAIL_OPEN=true to allow tool calls while the service is down.",
            "[AgentGuards] Service unreachable — tool call blocked (fail-closed).",
        )

    decision = result.get("decision", "allow")
    # The server returns a finished, plain-English sentence; surface it verbatim.
    reason = result.get("reason") or "AgentGuards couldn't confirm this tool call is safe."

    if decision == "allow":
        _allow()

    if decision == "deny":
        _block(
            f"AgentGuards blocked tool call '{tool_name}': {reason}",
            f"[AgentGuards] Tool '{tool_name}' blocked — {reason}",
        )

    # require-approval / escalate / dry-run. If every key was already approved
    # earlier this session, don't re-prompt — the scorer ran above, so a deny
    # still denies. Otherwise Gemini CLI has no native "ask user" primitive, so
    # we soft-block with an explanatory message and let the user re-submit.
    cache_keys = _tool_cache_keys(tool_name, tool_input)
    if cache_keys and all(k in _approved_keys(session_id) for k in cache_keys):
        _allow()

    _block(
        f"AgentGuards needs approval for tool call '{tool_name}': {reason} "
        "If you intended this, ask Gemini to run it again and confirm explicitly.",
        f"[AgentGuards] Tool '{tool_name}' requires approval — {reason} "
        "Re-submit with explicit confirmation to proceed.",
    )


def handle_after_tool(event: dict) -> None:
    # A successful tool call (= it was approved and ran) is remembered so a later
    # require-approval for the same keys isn't re-prompted. Skip failed runs — an
    # errored tool wasn't really "approved" and shouldn't seed the cache.
    tool_response = event.get("tool_response") or {}
    if isinstance(tool_response, dict) and tool_response.get("error"):
        _allow()
    tool_name = event.get("tool_name", "")
    tool_input = event.get("tool_input") or {}
    # Scan content fetched by the built-in web tools before it is used, and by
    # shell commands that invoke a fetch binary (curl/wget) — same deterministic
    # scan, not left to the model cooperatively calling the MCP check_input tool.
    # _block() exits if the content is flagged; otherwise we fall through to caching.
    if tool_name in _WEB_TOOLS:
        _scan_web_content(tool_name, event.get("tool_response"))
    elif tool_name in _SHELL_TOOLS and _is_fetch_command(str(tool_input.get("command") or "")):
        _scan_web_content(tool_name, event.get("tool_response"))
    session_id = _session_id(event)
    _remember_keys(session_id, _tool_cache_keys(tool_name, tool_input))
    _allow()


def main() -> None:
    event_type = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        event = json.loads(sys.stdin.read())
    except json.JSONDecodeError:
        _allow()

    if event_type == "AfterTool":
        handle_after_tool(event)
        return

    if not AGENTGUARDS_URL or not AGENTGUARDS_API_KEY:
        _block(
            "AGENTGUARDS_URL and AGENTGUARDS_API_KEY must be set. "
            "The hook is fail-closed, so it blocks until configured.",
            "[AgentGuards] Not configured — set AGENTGUARDS_URL and AGENTGUARDS_API_KEY "
            "in your ~/.gemini/settings.json env block.",
        )

    if event_type == "BeforeAgent":
        handle_before_agent(event)
    elif event_type == "BeforeTool":
        handle_before_tool(event)
    else:
        _allow()


if __name__ == "__main__":
    main()
