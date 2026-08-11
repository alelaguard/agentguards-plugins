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

write_file/replace output is also scanned at AfterTool for SAST findings and
secrets (semgrep + gitleaks, run server-side on a separate host) via
/v1/code/scan. This is a paid, opt-in feature — off by default, so most
tenants get a quiet 403 that's treated as "allow" (see ForbiddenError).

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
import ssl
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


class ForbiddenError(Exception):
    """API returned 403 — a deliberate access-control response (e.g. a feature the
    tenant hasn't enabled/purchased), not a transient outage. Callers that hit this
    should not treat it like a service failure (i.e. should not fail-closed-block)."""

    def __init__(self, message: str):
        super().__init__(message)
        self.detail = message


def _truthy(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in ("1", "true", "yes", "on")


def _ssl_context():
    """How to trust the AgentGuards server, or None to use Python's defaults.

    A self-hosted appliance generates its own certificate on first boot — it has no DNS
    name yet, so no public CA could have issued it one. Python rejects that by default,
    which is correct behaviour and also the reason a brand-new appliance appears to
    "refuse connections" when you point a hook at its IP address.

    Returning None for the unconfigured case matters: urlopen treats a falsy context as
    "use the default opener", so hosted users get exactly the verification they had
    before this existed.

    * ``AGENTGUARDS_CA_BUNDLE=/path/to/appliance.pem`` — still verifies, just against
      the appliance's own certificate. That is pinning, and is stricter than a public CA.
    * ``AGENTGUARDS_TLS_NO_VERIFY=true`` — no verification. Fine on a private subnet
      while evaluating; anything on the path can then read and alter the traffic.
    """
    bundle = os.getenv("AGENTGUARDS_CA_BUNDLE", "").strip()
    if bundle:
        return ssl.create_default_context(cafile=os.path.expanduser(bundle))
    if _truthy("AGENTGUARDS_TLS_NO_VERIFY"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return None


def _is_tls_trust_error(exc: BaseException) -> bool:
    """True when a request failed because the certificate was not trusted."""
    if isinstance(exc, ssl.SSLCertVerificationError):
        return True
    reason = getattr(exc, "reason", None)
    if isinstance(reason, ssl.SSLError):
        return True
    return "CERTIFICATE_VERIFY_FAILED" in str(exc)


def _missing_ca_bundle() -> str:
    """The configured CA bundle path, if it was set but does not exist.

    Worth its own branch: the resulting OSError is `[Errno 2] No such file or
    directory` with no filename, which tells an operator who just pasted the console's
    setup snippet nothing at all about what to do.
    """
    bundle = os.getenv("AGENTGUARDS_CA_BUNDLE", "").strip()
    if bundle and not os.path.exists(os.path.expanduser(bundle)):
        return bundle
    return ""


def _unreachable_remedy(exc: BaseException) -> str:
    """The advice line for a failed call.

    A certificate failure gets certificate advice. Suggesting AGENTGUARDS_FAIL_OPEN
    here would be telling an operator to switch off screening because the transport was
    not trusted — the wrong lever, and one that leaves the guardrail off long after the
    real problem is fixed.
    """
    missing = _missing_ca_bundle()
    if missing:
        return (
            f"AGENTGUARDS_CA_BUNDLE points at {missing}, which does not exist. Save the "
            "appliance's certificate there first:\n"
            "      openssl s_client -connect <host>:443 -showcerts </dev/null 2>/dev/null "
            "| openssl x509 > " + missing + "\n"
            "Or unset AGENTGUARDS_CA_BUNDLE to go back to the public CA roots."
        )
    if _is_tls_trust_error(exc):
        return (
            "The server's certificate is not trusted. A self-hosted appliance signs "
            "its own certificate on first boot, so this is expected until you install "
            "a real one.\n"
            "  • Best: install your own certificate at Settings -> TLS certificate, and "
            "reach the appliance by the hostname it is issued for.\n"
            "  • Or pin the appliance's certificate:\n"
            "      openssl s_client -connect <host>:443 -showcerts </dev/null 2>/dev/null "
            "| openssl x509 > ~/.agentguards-appliance.pem\n"
            "      export AGENTGUARDS_CA_BUNDLE=~/.agentguards-appliance.pem\n"
            "  • Evaluating on a private network: export AGENTGUARDS_TLS_NO_VERIFY=true"
        )
    code = getattr(exc, "code", None)
    if code == 401:
        return (
            "The API key was rejected. Check AGENTGUARDS_API_KEY matches a key on this "
            "instance (Admin console -> API keys), and that AGENTGUARDS_URL points at "
            "the right one. Do not use AGENTGUARDS_FAIL_OPEN for this — the service is "
            "healthy and turning off screening would not fix the credential."
        )
    return "Set AGENTGUARDS_FAIL_OPEN=true to allow requests while the service is down."


def _post(path: str, payload: dict, *, timeout: int = 10) -> dict:
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
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as resp:
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
        if exc.code == 403:
            try:
                body = json.loads(exc.read())
            except Exception:
                body = {}
            raise ForbiddenError(body.get("detail") or "Forbidden")
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

    decision = result.get("decision", "allow")

    # `redact` is not `block`. A PERSON hit on a fetched page is usually a real name
    # that is genuinely there — an author byline, a maintainer handle — so withholding
    # the whole page over one surname destroys the fetch for nothing.
    #
    # AfterTool has no replace-without-denying field: per the hooks reference, the only
    # substitution channel is decision:"deny" + `reason`, whose text replaces the tool
    # result sent to the model. So the sanitised page rides in `reason` and does reach
    # the agent. It is labelled a deny; that is a Gemini protocol limit, not our intent.
    redacted_text = result.get("redacted_text")
    failing = [c for c in (result.get("checks") or []) if not c.get("passed", True)]
    # Defence in depth: only take this path when every failing check is one that
    # redaction actually resolves, so a server-side regression can't route an
    # injection verdict through the redaction branch.
    only_pii = bool(failing) and all(
        c.get("check_name") in {"presidio", "pii_detection", "secret_detection"} for c in failing
    )
    if (
        decision == "redact"
        and isinstance(redacted_text, str)
        and redacted_text.strip()
        and only_pii
    ):
        types: list[str] = []
        for check in result.get("checks") or []:
            if check.get("passed", True):
                continue
            for pii_type in (check.get("metadata") or {}).get("pii_types") or []:
                if str(pii_type) not in types:
                    types.append(str(pii_type))
        what = f" ({', '.join(types)})" if types else ""
        _block(
            f"{redacted_text}\n\n[AgentGuards redacted sensitive values{what} from this "
            "content. The rest of the result is intact and safe to use.]",
            f"[AgentGuards] Redacted sensitive values{what} — content otherwise intact",
        )

    if decision not in ("allow",):
        # Server composes the full structured panel; print THAT and nothing else.
        #
        # Deliberately NOT appending result["flagged_input"] here, unlike the prompt
        # path. On the prompt path the flagged text is the user's own input and
        # quoting it back is the whole point. Here it is fetched web content: the
        # server's excerpt is the first 240 characters of the page, so echoing it
        # into a field the model reads hands an attacker a guaranteed 240-char
        # channel into context — carrying AgentGuards' own framing — from a page we
        # just decided was too dangerous to show. That defeats the block.
        message = result.get("message") or "🛡️ [AgentGuards] Web content blocked\nDecision: block\nReason: policy - flagged by AgentGuards guardrails\nSeverity: high"
        _block(message, "[AgentGuards] Web content withheld")


# Gemini's built-in write tools whose output must be scanned for SAST/secrets.
_WRITE_TOOLS = ("write_file", "replace")
# Outer timeout (hook -> API). Kept above the API's inner API->VPS timeout (5s)
# so a slow-but-successful scan isn't abandoned mid-flight (which would fail-open
# and allow a write the scan flagged). Still well under the prompt path's budget.
_CODE_SCAN_TIMEOUT = 8


def _extract_write_content(tool_input: dict) -> tuple[str | None, str]:
    """Return (file_path, written_content) for a write_file/replace tool call."""
    file_path = tool_input.get("file_path") or tool_input.get("path")
    if "content" in tool_input:  # write_file
        return file_path, str(tool_input.get("content") or "")
    if "new_string" in tool_input:  # replace
        return file_path, str(tool_input.get("new_string") or "")
    return file_path, ""


def _scan_code(tool_input: dict) -> None:
    # Runs at AfterTool for the built-in write tools. Gemini's AfterTool honors
    # {"decision": "deny"}, so a bad verdict genuinely withholds — same as
    # _scan_web_content. This is a paid, opt-in feature (off by default), so a
    # 403 here means the tenant hasn't enabled it and must be treated as allow,
    # not as an outage.
    file_path, content = _extract_write_content(tool_input)
    if not content.strip():
        return

    print(f"AgentGuards: scanning {file_path or 'file'} for security issues...", file=sys.stderr)

    if not AGENTGUARDS_URL or not AGENTGUARDS_API_KEY:
        if _fail_open():
            return
        _block(
            "AgentGuards not configured and the hook is fail-closed.",
            "[AgentGuards] Code scan withheld — hook not configured (fail-closed).",
        )

    try:
        result = _post(
            "/v1/code/scan",
            {"content": content, "file_path": file_path},
            timeout=_CODE_SCAN_TIMEOUT,
        )
    except ForbiddenError:
        return
    except QuotaExceededError as exc:
        _block(
            f"AgentGuards monthly quota reached: {exc.user_message}",
            f"[AgentGuards] Monthly quota reached — {exc.user_message}",
        )
    except Exception as exc:
        if _fail_open():
            print(
                f"AgentGuards: code scan unreachable ({exc}), allowing write (AGENTGUARDS_FAIL_OPEN=true)",
                file=sys.stderr,
            )
            return
        _block(
            f"AgentGuards is unreachable ({exc}) and the hook is fail-closed.",
            "[AgentGuards] Code scan withheld — service unreachable (fail-closed).",
        )

    decision = result.get("decision", "allow")
    if decision == "block":
        message = result.get("message") or "[AgentGuards] Code scan blocked"
        _block(message, message)
    if decision == "warn" and result.get("message"):
        print(result["message"], file=sys.stderr)


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
            f"{_unreachable_remedy(exc)}",
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
            f"{_unreachable_remedy(exc)}",
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
    elif tool_name in _WRITE_TOOLS:
        _scan_code(tool_input)
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
