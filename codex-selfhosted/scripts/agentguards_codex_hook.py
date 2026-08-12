#!/usr/bin/env python3
"""Codex CLI hook for AgentGuards guardrails.

Handles UserPromptSubmit, PreToolUse, PermissionRequest and PostToolUse hooks.
Reads JSON from stdin, calls the AgentGuards REST API, and either lets the action
continue, hard-blocks it, or defers to the user. Prompt-injection / policy hits on
the prompt are blocked outright.

Shell commands: PreToolUse hard-denies what the authorizer rejects. Codex's
PreToolUse hook parses but does NOT support permissionDecision:"ask" and a hook
cannot force an approval prompt, so a borderline command is deferred (exit 0) to
Codex's own approval flow — the user is prompted whenever approval_policy is
`untrusted`/`on-request` (in `full-auto`/`never` it runs ungated). PermissionRequest
then rides that real prompt when it appears: it hard-denies re-flagged commands with
the AgentGuards panel as the message and auto-approves binaries already cleared this
session, so the user isn't re-asked. Note PermissionRequest only fires when Codex was
already going to ask, so it does not close the `full-auto`/`never` gap.

At PostToolUse, output from web-fetching shell commands (curl, wget, etc.) is
scanned with use_case="web_fetch" and withheld if AgentGuards flags it.
apply_patch (Codex's file-edit tool) content is scanned the same way via
/v1/code/scan for SAST findings and secrets — a paid, opt-in feature (off by
default), so most tenants get a quiet 403 treated as allow, not a block.
NOTE: apply_patch's tool_input field name for the patch body is inferred
(tried: patch/input/diff/content) — verify against a real Codex session
before relying on this in production.

Setup:
    1. Save this file as ~/.codex/agentguards_codex_hook.py
    2. Save your ag_ token:  echo "ag_..." > ~/.codex/agentguards_token
    3. Register the hooks in ~/.codex/config.toml (see the dashboard snippet).

Environment (self-hosted variant — both required, no default):
    AGENTGUARDS_URL      Your appliance's own address. No fallback, deliberately: a
                         default here would mean a misconfigured install silently
                         screens through AgentGuards' hosted service instead of your
                         appliance, with no error. See agentguards-codex (the SaaS
                         plugin) if you want prod.agentguards.co by default.
    AGENTGUARDS_API_KEY  ag_ token from your appliance's own console (falls back to
                         ~/.codex/agentguards_token)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
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

# Deliberately no default, unlike agentguards-codex's copy of this script — see the
# module docstring. This is the one intentional line of divergence between the two
# plugins' otherwise-identical hook; everything else here is unchanged.
AGENTGUARDS_URL = os.getenv("AGENTGUARDS_URL", "").rstrip("/")

# Per-session approval cache. A command reaching PostToolUse actually ran (= it
# was approved), so we remember its binaries keyed by session_id and skip
# re-asking for them later that session. The risk scorer always runs first, so a
# remembered binary can never carry a destructive command through.
_APPROVALS_PATH = str(Path.home() / ".codex" / "agentguards_session_approvals.json")
_SESSION_TTL = 7 * 24 * 3600
# Bumped when the meaning of a stored approval changes. v1 recorded every command
# that ran, including ones nobody was asked about, so v1 entries are ignored.
_APPROVALS_VERSION = 2


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
    req = urllib.request.Request(
        f"{AGENTGUARDS_URL}{path}",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "X-API-Key": _api_key()},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
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


# Commands that run ANOTHER command. Naming them is what stops `sudo curl` and
# `timeout 5 curl` reading as "sudo" and "timeout" — which is how fetches slipped past
# the web-content scan. Values are the options that consume the FOLLOWING token, so
# `sudo -u root curl` does not mistake "root" for the command.
_WRAPPERS = {
    "sudo": {"-u", "-g", "-p", "-C", "-U", "-r", "-t", "-h"},
    "doas": {"-u", "-C"},
    "env": {"-u", "-C", "-S"},
    "timeout": {"-s", "-k", "--signal", "--kill-after"},
    "nohup": set(),
    "nice": {"-n", "--adjustment"},
    "ionice": {"-c", "-n", "-p", "-t"},
    "stdbuf": {"-i", "-o", "-e"},
    "command": set(),
    "xargs": {"-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s", "--max-args"},
    "time": {"-o", "-f", "--output", "--format"},
    "setsid": set(),
    "unbuffer": set(),
    "watch": {"-n", "--interval"},
    "script": {"-c"},
}

# Shells, which run whatever string follows -c. `bash -c "curl ..."` is a fetch.
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "busybox"}

# $(...) and `...` run a command whose output is substituted in. Treated as their own
# segments so `OUT=$(curl ...)` is seen as a fetch rather than an assignment.
_SUBSTITUTION_RE = re.compile(r"\$\(([^()]*)\)|`([^`]*)`")


def _segments(command: str) -> list:
    """Split a command line into the individual commands it runs."""
    parts = []
    remainder = _SUBSTITUTION_RE.sub(
        lambda m: parts.append(m.group(1) or m.group(2) or "") or " ", command or ""
    )
    parts.extend(re.split(r"\|\||&&|[|;&\n]", remainder))
    return parts


def _resolve_binaries(segment: str, _depth: int = 0) -> list:
    """Every binary a single segment invokes: wrappers, then the command they wrap.

    Returns the whole chain rather than just the target, so the approval cache stays
    strict — approving `curl` alone must not silently approve `sudo curl`.
    """
    tokens = segment.strip().split()
    found = []
    idx = 0
    while idx < len(tokens):
        token = tokens[idx]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token):  # leading VAR=val
            idx += 1
            continue
        name = token.split("/")[-1]
        found.append(name)

        if name in _SHELLS and _depth < 3:
            # Recurse into the string after -c, which the shell will execute.
            for j in range(idx + 1, len(tokens) - 1):
                if tokens[j] == "-c" or (tokens[j].startswith("-") and "c" in tokens[j][1:]):
                    nested = " ".join(tokens[j + 1 :]).strip("\"'")
                    found.extend(_resolve_binaries(nested, _depth + 1))
                    break
            break

        if name not in _WRAPPERS or _depth >= 3:
            break

        # Step over the wrapper's own options to reach the command it runs.
        takes_value = _WRAPPERS[name]
        idx += 1
        while idx < len(tokens):
            arg = tokens[idx]
            if arg == "--":
                idx += 1
                break
            if arg.startswith("-"):
                idx += 1
                if arg in takes_value and idx < len(tokens):
                    idx += 1
                continue
            if re.fullmatch(r"\d+(\.\d+)?[smhd]?", arg):  # timeout 5, nice 10
                idx += 1
                continue
            break
    return found


def _command_binaries(command: str) -> list:
    """Every binary the command line invokes, across pipelines and substitutions."""
    binaries = []
    for segment in _segments(command):
        binaries.extend(_resolve_binaries(segment))
    return binaries


def _load_approvals() -> dict:
    try:
        with open(_APPROVALS_PATH) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    # Entries written before the approval fix recorded binaries the user was never
    # asked about (see _mark_pending). They cannot be told apart from genuine ones, so
    # they are dropped rather than trusted; the cost is at most one extra prompt.
    return {
        sid: e
        for sid, e in data.items()
        if isinstance(e, dict) and e.get("v") == _APPROVALS_VERSION
    }


def _approved_binaries(session_id: str) -> set:
    if not session_id:
        return set()
    entry = _load_approvals().get(session_id) or {}
    return set(entry.get("binaries", []))


def _command_key(command: str) -> str:
    """Stable id for one exact command, so a pending approval can only be redeemed
    by the command it was granted for. The command text itself is never stored."""
    return hashlib.sha256((command or "").encode("utf-8", "replace")).hexdigest()[:16]


def _write_approvals(data: dict) -> None:
    now = time.time()
    data = {
        sid: e
        for sid, e in data.items()
        if isinstance(e, dict) and now - e.get("ts", 0) < _SESSION_TTL
    }
    try:
        os.makedirs(os.path.dirname(_APPROVALS_PATH), exist_ok=True)
        # 0600: this file decides whether a command is re-prompted, so anything able
        # to write it could pre-approve binaries for the session.
        fd = os.open(_APPROVALS_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh)
    except OSError:
        pass


def _mark_pending(session_id: str, command: str) -> None:
    """Record that the USER IS BEING ASKED about this exact command.

    Only a command that reached this point — i.e. Claude Code is putting the approval
    prompt in front of a human — may ever become a remembered approval. That is the
    whole point of the fix: previously every command that merely *ran* was recorded,
    including the safe-baseline ones the server auto-allowed with no prompt at all, so
    `rm stale.log` (allowed silently) taught the cache that `rm` was approved and the
    next `rm -rf ~/work` was let through without ever asking.

    Keyed by the exact command, not just its binaries. Keying by binary alone would
    reintroduce the bug through the back door: deny `rm -rf /`, then run a harmless
    `rm foo.txt`, and the harmless one would redeem the denied command's pending
    entry. A pending approval can only be redeemed by the command it was granted for.
    """
    if not session_id or not command:
        return
    data = _load_approvals()
    entry = data.get(session_id) or {}
    pending = dict(entry.get("pending") or {})
    pending[_command_key(command)] = sorted(set(_command_binaries(command)))
    data[session_id] = {
        "v": _APPROVALS_VERSION,
        "binaries": sorted(set(entry.get("binaries", []))),
        "pending": pending,
        "ts": time.time(),
    }
    _write_approvals(data)


def _redeem_pending(session_id: str, command: str) -> None:
    """This command actually ran, so if the user was asked about it, it was approved.

    Reaching PostToolUse means the tool call went through. Combined with a pending
    entry — which only _mark_pending creates, and only when the user was genuinely
    prompted — that is a real human approval, and its binaries can be remembered for
    the rest of the session.

    A command with no pending entry ran without anyone being asked (safe baseline),
    so nothing is remembered. That is the fix.
    """
    if not session_id or not command:
        return
    data = _load_approvals()
    entry = data.get(session_id)
    if not entry:
        return
    pending = dict(entry.get("pending") or {})
    binaries = pending.pop(_command_key(command), None)
    if binaries is None:
        return
    data[session_id] = {
        "v": _APPROVALS_VERSION,
        "binaries": sorted(set(entry.get("binaries", [])) | set(binaries)),
        "pending": pending,
        "ts": time.time(),
    }
    _write_approvals(data)


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


def _redact_output(redacted: str, pii_types: list[str]) -> None:
    """Hand the sanitised page back through the one channel Codex actually honours.

    Do NOT reach for `updatedMCPToolOutput` here even though it names exactly this use
    case: Codex parses it, marks the hook run FAILED, and then continues normal
    processing of the tool result — i.e. the ORIGINAL unredacted content reaches the
    model. An unsupported field is worse than no field; it fails open.
    """
    what = f" ({', '.join(pii_types)})" if pii_types else ""
    print(
        json.dumps(
            {
                "decision": "block",
                "reason": (
                    f"{redacted}\n\n[AgentGuards redacted sensitive values{what} from this "
                    "content. The rest of the result is intact and safe to use.]"
                ),
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "additionalContext": (
                        f"AgentGuards redacted sensitive values{what} from the fetched "
                        "content. The remaining content is intact — use it normally."
                    ),
                },
            }
        )
    )
    sys.exit(0)


# Checks whose failure redaction genuinely resolves: the sensitive span is replaced
# and what is left is safe. Any OTHER failing check means something redaction can't fix.
_PII_CHECKS = {"presidio", "pii_detection", "secret_detection"}


def _only_pii_failed(result: dict) -> bool:
    """True when every failing check is one redaction actually resolves (defence in depth)."""
    failing = [c for c in (result.get("checks") or []) if not c.get("passed", True)]
    return bool(failing) and all(c.get("check_name") in _PII_CHECKS for c in failing)


def _redacted_entity_types(result: dict) -> list[str]:
    """PII type names from the checks that fired, for the redaction notice."""
    types: list[str] = []
    for check in result.get("checks") or []:
        if check.get("passed", True):
            continue
        for pii_type in (check.get("metadata") or {}).get("pii_types") or []:
            if str(pii_type) not in types:
                types.append(str(pii_type))
    return types


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

    # `redact` is not `block`. A PERSON hit on a fetched page is usually a real name
    # that is genuinely there — an author byline, a maintainer handle — so withholding
    # the whole page over one surname destroys the fetch for nothing.
    #
    # Codex has no clean output-rewrite field: `updatedMCPToolOutput` is documented as
    # "parsed but not supported yet". The one lever is decision:"block", which per the
    # docs "replaces the tool result with that feedback, and continues the model from
    # the hook-provided message" — so the sanitised page in `reason` does reach the
    # model and the fetch survives. It is labelled a block; that is a Codex protocol
    # limit, not our intent. Swap this for the real field when Codex ships it.
    redacted_text = result.get("redacted_text")
    if (
        decision == "redact"
        and isinstance(redacted_text, str)
        and redacted_text.strip()
        and _only_pii_failed(result)
    ):
        _redact_output(redacted_text, _redacted_entity_types(result))

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
        _block_output(message)


def _ask(reason: str) -> None:
    # Hand the decision to the user. Codex's PreToolUse hook parses but does NOT
    # support permissionDecision:"ask" (it errors: "unsupported permissionDecision"),
    # and a hook cannot force an approval prompt of its own. The only way to let the
    # user choose is to return no decision (exit 0, no stdout): Codex then falls back
    # to its own approval_policy and prompts the user whenever that policy is
    # `untrusted` or `on-request`. In `full-auto`/`never` it runs without asking.
    # We print the AgentGuards panel to stderr so the flag is visible in the hook log
    # even when Codex doesn't stop to prompt.
    print(reason, file=sys.stderr)
    _continue()


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


def _permission_allow() -> None:
    # PermissionRequest: auto-approve so Codex doesn't stop to ask the user.
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PermissionRequest",
                    "decision": {"behavior": "allow"},
                }
            }
        )
    )
    sys.exit(0)


def _permission_deny(message: str) -> None:
    # PermissionRequest: hard-deny the request; `message` is shown to the user.
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PermissionRequest",
                    "decision": {"behavior": "deny", "message": message},
                }
            }
        )
    )
    sys.exit(0)


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
            f"fail-closed. {_unreachable_remedy(exc)}"
        )
    if result.get("decision", "allow") in ("block", "escalate", "redact"):
        # Deliberately not appending result["flagged_input"]. The user just typed
        # this prompt — echoing it back adds a line they already know, to a message
        # the host has already prefixed with its own preamble and the whole hook
        # command. The field is still in the API response for anything programmatic.
        message = result.get("message") or "🛡️ [AgentGuards] Prompt blocked\nReason: policy - flagged by AgentGuards guardrails"
        _block_prompt(message)
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
            f"{_unreachable_remedy(exc)}"
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


def handle_permission_request(event: dict) -> None:
    # Fires only when Codex is already about to prompt the user for approval
    # (shell escalation, managed-network, etc.); it never runs for auto-allowed
    # commands and cannot create a prompt that wouldn't otherwise happen. Here we
    # let the AgentGuards verdict ride that real approval decision: hard-deny what
    # the authorizer rejects (with our panel as the message), silently approve a
    # binary the user already cleared this session, and otherwise defer so the user
    # makes the call at Codex's normal prompt.
    tool_name = event.get("tool_name", "")
    tool_input = event.get("tool_input", {}) or {}
    command = tool_input.get("command")
    session_id = event.get("session_id", "")
    # Only shell commands go through the action authorizer; defer apply_patch / MCP
    # tool approvals to Codex's normal prompt.
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
    except Exception:
        # Quota/outage/missing-key: the user is already being asked, so don't
        # hard-block their approval — let Codex's normal prompt continue.
        _continue()
    decision = result.get("decision", "allow")
    reason = result.get("reason") or "🛡️ [AgentGuards] Command blocked\nDecision: deny\nReason: policy - flagged by AgentGuards guardrails\nSeverity: high"
    shown = command if len(str(command)) <= 500 else str(command)[:500] + "..."
    if decision == "deny":
        _permission_deny(f"{reason}\n\n    {shown}")
    binaries = _command_binaries(command)
    if binaries and all(b in _approved_binaries(session_id) for b in binaries):
        _permission_allow()
    # authorize=allow or borderline: hand the decision to the user. Echo the panel
    # to stderr so the flag is visible alongside Codex's approval prompt.
    #
    # This is the ONLY place codex may mark an approval pending. PreToolUse's _ask()
    # cannot: it returns no decision and lets Codex's own approval_policy decide, so
    # under full-auto/never the command runs with nobody asked. Treating that as an
    # approval would rebuild the very bug this guards against. PermissionRequest, by
    # contrast, fires only when Codex is already about to prompt a human.
    _mark_pending(session_id, command)
    if decision != "allow":
        print(f"{reason}\n\n    {shown}", file=sys.stderr)
    _continue()


# Codex CLI's built-in file-edit tool; its patch content must be scanned.
_WRITE_TOOL_NAMES = {"apply_patch"}
# Outer timeout (hook -> API). Kept above the API's inner API->VPS timeout (5s)
# so a slow-but-successful scan isn't abandoned mid-flight (which would fail-open
# and allow a write the scan flagged). Still well under the prompt path's budget.
_CODE_SCAN_TIMEOUT = 8


def _extract_write_content(tool_input: dict) -> tuple[str | None, str]:
    file_path = tool_input.get("file_path") or tool_input.get("path")
    for key in ("patch", "input", "diff", "content"):
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            return file_path, value
    return file_path, ""


def _scan_code(tool_input: dict) -> None:
    # Paid, opt-in feature (off by default) — a 403 means the tenant hasn't
    # enabled it, which must be treated as allow, not as an outage.
    file_path, content = _extract_write_content(tool_input)
    if not content.strip():
        return

    print(f"AgentGuards: scanning {file_path or 'file'} for security issues...", file=sys.stderr)

    try:
        result = _post(
            "/v1/code/scan",
            {"content": content, "file_path": file_path},
            timeout=_CODE_SCAN_TIMEOUT,
        )
    except ForbiddenError:
        return
    except QuotaExceededError as exc:
        _block_output(f"AgentGuards monthly quota reached: {exc.user_message} Write withheld.")
    except Exception as exc:
        if _fail_open():
            print(
                f"AgentGuards: code scan unreachable ({exc}), allowing write (AGENTGUARDS_FAIL_OPEN=true)",
                file=sys.stderr,
            )
            return
        _block_output(f"AgentGuards unreachable ({exc}) — write withheld (fail-closed).")

    decision = result.get("decision", "allow")
    if decision == "block":
        _block_output(result.get("message") or "[AgentGuards] Code scan blocked")
    if decision == "warn" and result.get("message"):
        print(result["message"], file=sys.stderr)


def handle_post_tool_use(event: dict) -> None:
    tool_name = event.get("tool_name", "")
    tool_input = event.get("tool_input", {}) or {}
    command = tool_input.get("command")
    # Scan output from web-fetching shell commands before the model sees it.
    if command and _is_fetch_command(command):
        _scan_web_output(_extract_tool_response(event))
    # Scan file edits for SAST findings and secrets.
    if tool_name in _WRITE_TOOL_NAMES:
        _scan_code(tool_input)
    # If the user was asked about THIS command (PermissionRequest) and it then ran,
    # that is a real approval — remember its binaries. A command that ran without a
    # prompt is deliberately not remembered.
    if command:
        _redeem_pending(event.get("session_id", ""), command)
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
    if event_type == "PermissionRequest":
        # Runs while the user is already being asked; on a missing key the
        # authorize call fails and the handler defers, so don't fail-closed here.
        handle_permission_request(event)
        return
    if not AGENTGUARDS_URL or not _api_key():
        # Fail-closed: refuse until both are configured. Unlike the SaaS plugin, this
        # variant has no URL default, so a missing AGENTGUARDS_URL must be caught here
        # explicitly — otherwise it falls through to a relative-path request with no
        # host, which fails with a confusing transport error instead of this message.
        message = (
            "AgentGuards is not configured: set AGENTGUARDS_URL to your appliance's "
            "address, and save your ag_ token to ~/.codex/agentguards_token (or set "
            "AGENTGUARDS_API_KEY). The hook is fail-closed."
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
