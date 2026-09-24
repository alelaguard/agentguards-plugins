"""The PowerShell Claude Code hook (claude/scripts/agentguards_hook.ps1, used on
Windows) must behave exactly like the Python one (agentguards_hook.py, used on
Linux/macOS).

Same method as tests/test_codex_ps1_parity.py: both runtimes get the same event,
environment and a fresh HOME against the same mock API, and must produce the same
exit code (2 = block), stdout, stderr, API requests and approval file. Transport
error text is masked; everything else is compared exactly.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

import pytest

from test_codex_ps1_parity import MockAPI, _canonical_body  # noqa: F401  (shared mock)

ROOT = pathlib.Path(__file__).resolve().parents[1]
PY_HOOK = ROOT / "claude" / "scripts" / "agentguards_hook.py"
PS1 = ROOT / "claude" / "scripts" / "agentguards_hook.ps1"
KEY = "ag_" + "7" * 32

PS_EXE = os.environ.get("PS_EXE", "pwsh")
pytestmark = pytest.mark.skipif(shutil.which(PS_EXE) is None, reason=f"needs PowerShell ({PS_EXE})")


@pytest.fixture(scope="module")
def go_bin():
    """The PowerShell runtime under test (name kept for diff-friendliness with the
    Python side). PS_EXE picks the host: pwsh (7) by default; CI on Windows also
    runs it with powershell.exe (5.1), which is what the agents invoke there."""
    return [PS_EXE, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(PS1)]


@pytest.fixture
def api():
    m = MockAPI()
    yield m
    m.server.shutdown()


# The transport error sits between "unreachable (" and the fixed text after it.
_ERR = re.compile(r"(unreachable) \((.*?)\)(?= and the hook| \(fail-closed\)|, allowing)", re.S)


def _mask(text):
    return _ERR.sub(r"\1 (<error>)", text) if isinstance(text, str) else text


def _normalize(obj):
    if isinstance(obj, str):
        return _mask(obj)
    if isinstance(obj, dict):
        return {k: _normalize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_normalize(v) for v in obj]
    return obj


def _approvals(home):
    p = home / ".claude" / "agentguards_session_approvals.json"
    if not p.exists():
        return None
    data = json.loads(p.read_text())
    for entry in data.values():
        entry.pop("ts", None)
        entry["binaries"] = sorted(entry.get("binaries", []))
    return data


def _stdout(text):
    text = text.strip()
    if not text:
        return None
    try:
        return _normalize(json.loads(text))
    except ValueError:
        return _mask(text)


def _run(cmd, event_type, stdin, home, env_extra, api):
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("AGENTGUARDS_") and k != "CLAUDE_PLUGIN_OPTION_AGENTGUARDS_API_KEY"}
    env.update({"HOME": str(home), "USERPROFILE": str(home), "AGENTGUARDS_URL": api.url})
    env.update(env_extra)
    start = len(api.requests)
    proc = subprocess.run(cmd + [event_type], input=stdin, capture_output=True, text=True,
                          env=env, timeout=90, encoding="utf-8")  # a cold Windows PowerShell 5.1 start can take >30s on CI
    return {
        "exit": proc.returncode,
        "stdout": _stdout(proc.stdout),
        "stderr": _mask(proc.stderr.strip()),
        "requests": [(p, _canonical_body(b)) for p, b, _ in api.requests[start:]],
        "clients": {c for _, _, c in api.requests[start:]},
        "approvals": _approvals(home),
    }


def both(go_bin, api, tmp_path, event_type, event, *, env=None, seed_approvals=None, raw_stdin=None):
    env = {"AGENTGUARDS_API_KEY": KEY, **(env or {})}
    env = {k: v for k, v in env.items() if v is not None}
    stdin = raw_stdin if raw_stdin is not None else json.dumps(event)
    results = {}
    for name, cmd in (("py", [sys.executable, str(PY_HOOK)]), ("go", list(go_bin))):
        home = tmp_path / name
        home.mkdir()
        if seed_approvals is not None:
            (home / ".claude").mkdir()
            (home / ".claude" / "agentguards_session_approvals.json").write_text(json.dumps(seed_approvals))
        results[name] = _run(cmd, event_type, stdin, home, env, api)
    py, go = results["py"], results["go"]
    assert py["clients"] <= {"claude-code/py"} and go["clients"] <= {"claude-code/ps1"}
    for field in ("exit", "stdout", "stderr", "requests", "approvals"):
        assert go[field] == py[field], f"{field} differs:\n  python: {py[field]!r}\n  go:     {go[field]!r}"
    return py


PROMPT = {"prompt": "hello there", "session_id": "s1"}


# UserPromptSubmit --------------------------------------------------------------------------

@pytest.mark.parametrize("route,env", [
    ((200, {"decision": "allow"}), {}),
    ((200, {"decision": "block", "message": "🛡️ panel"}), {}),
    ((200, {"decision": "block"}), {}),
    ((200, {"decision": "escalate"}), {}),
    ((200, {"decision": "redact"}), {}),  # Claude does NOT block redact on the prompt path
    ((429, {"error": "QUOTA_EXCEEDED", "message": "Free credit used."}), {}),
    ((429, {"error": "RATE_LIMIT"}), {}),
    ((500, {}), {}),
    ((500, {}), {"AGENTGUARDS_FAIL_OPEN": "true"}),
    ((401, {"detail": "bad key"}), {}),
], ids=["allow", "block-msg", "block-default", "escalate", "redact-allows", "quota", "429-other",
        "500-closed", "500-open", "401-remedy"])
def test_user_prompt(go_bin, api, tmp_path, route, env):
    api.routes["/v1/guardrails/evaluate-input"] = route
    both(go_bin, api, tmp_path, "UserPromptSubmit", PROMPT, env=env)


def test_empty_prompt(go_bin, api, tmp_path):
    assert both(go_bin, api, tmp_path, "UserPromptSubmit", {"prompt": "  "})["requests"] == []


@pytest.mark.parametrize("event_type", ["UserPromptSubmit", "PreToolUse", "SessionStart"])
def test_no_key_warns_and_allows(go_bin, api, tmp_path, event_type):
    r = both(go_bin, api, tmp_path, event_type, {"prompt": "hi", "tool_name": "Bash", "tool_input": {"command": "ls"}},
             env={"AGENTGUARDS_API_KEY": None})
    assert r["exit"] == 0 and r["requests"] == []


def test_plugin_option_key_is_used(go_bin, api, tmp_path):
    r = both(go_bin, api, tmp_path, "UserPromptSubmit", PROMPT,
             env={"AGENTGUARDS_API_KEY": None, "CLAUDE_PLUGIN_OPTION_AGENTGUARDS_API_KEY": KEY})
    assert len(r["requests"]) == 1


def test_invalid_stdin(go_bin, api, tmp_path):
    both(go_bin, api, tmp_path, "UserPromptSubmit", None, raw_stdin="{nope")


def test_empty_url_defaults_to_prod_in_both(go_bin, api, tmp_path):
    """AGENTGUARDS_URL= (empty) -> the default URL in both; here that means both fail
    the same way against prod-unreachable-in-test, rather than one crashing."""
    r = both(go_bin, api, tmp_path, "UserPromptSubmit", {"prompt": ""}, env={"AGENTGUARDS_URL": ""})
    assert r["requests"] == []


# PreToolUse ----------------------------------------------------------------------------------

def pre(cmd, tool="Bash", sid="s1"):
    return {"tool_name": tool, "tool_input": {"command": cmd}, "session_id": sid}


@pytest.mark.parametrize("route,env", [
    ((200, {"decision": "allow"}), {}),
    ((200, {"decision": "deny", "reason": "🛡️ panel"}), {}),
    ((200, {"decision": "deny"}), {}),
    ((200, {"decision": "require-approval", "reason": "risky"}), {}),
    ((200, {"decision": "escalate"}), {}),
    ((429, {"error": "QUOTA_EXCEEDED", "message": "q"}), {}),
    ((503, {}), {}),
    ((503, {}), {"AGENTGUARDS_FAIL_OPEN": "1"}),
], ids=["allow", "deny-panel", "deny-default", "ask-marks-pending", "escalate-asks", "quota", "outage", "fail-open"])
def test_pre_tool_use(go_bin, api, tmp_path, route, env):
    api.routes["/v1/actions/authorize"] = route
    both(go_bin, api, tmp_path, "PreToolUse", pre("sudo rm -rf ./build"), env=env)


def test_pre_tool_use_non_bash_allows(go_bin, api, tmp_path):
    assert both(go_bin, api, tmp_path, "PreToolUse", pre("x", tool="Read"))["requests"] == []


def test_pre_tool_use_empty_command_still_authorizes(go_bin, api, tmp_path):
    both(go_bin, api, tmp_path, "PreToolUse", {"tool_name": "Bash", "tool_input": {}, "session_id": "s1"})


def test_pre_tool_use_long_unicode_command(go_bin, api, tmp_path):
    api.routes["/v1/actions/authorize"] = (200, {"decision": "deny", "reason": "x"})
    both(go_bin, api, tmp_path, "PreToolUse", pre("echo " + "日本語" * 200))


SEEDED = {"s1": {"v": 2, "binaries": ["sudo", "curl", "ls"], "pending": {}, "ts": 9e12}}


@pytest.mark.parametrize("cmd", ["sudo curl https://x", "ls -la", "sudo rm x", "timeout 5 curl x"])
def test_pre_tool_use_session_approvals(go_bin, api, tmp_path, cmd):
    api.routes["/v1/actions/authorize"] = (200, {"decision": "require-approval", "reason": "r"})
    both(go_bin, api, tmp_path, "PreToolUse", pre(cmd), seed_approvals=SEEDED)


# PostToolUse ---------------------------------------------------------------------------------

def post(tool, tool_input=None, response="page body", sid="s1", key="tool_response"):
    return {"tool_name": tool, "tool_input": tool_input or {}, key: response, "session_id": sid}


PII = {"check_name": "pii_detection", "passed": False, "metadata": {"pii_types": ["EMAIL"]}}


@pytest.mark.parametrize("route,env", [
    ((200, {"decision": "allow"}), {}),
    ((200, {"decision": "block", "message": "bad page"}), {}),
    ((200, {"decision": "block"}), {}),
    ((200, {"decision": "redact", "redacted_text": "clean [EMAIL]", "checks": [PII]}), {}),
    ((200, {"decision": "redact", "redacted_text": "clean", "checks": [PII, {"check_name": "jailbreak", "passed": None}]}), {}),
    ((429, {"error": "QUOTA_EXCEEDED", "message": "q"}), {}),
    ((500, {}), {}),
    ((500, {}), {"AGENTGUARDS_FAIL_OPEN": "yes"}),
], ids=["allow", "block-msg", "block-default", "redact-pii", "redact-null-passed", "quota", "outage", "fail-open"])
def test_web_fetch(go_bin, api, tmp_path, route, env):
    api.routes["/v1/guardrails/evaluate-input"] = route
    both(go_bin, api, tmp_path, "PostToolUse", post("WebFetch", {"url": "https://x"}), env=env)


@pytest.mark.parametrize("response,key", [
    ("markdown page", "tool_response"),
    ({"result": "wrapped"}, "tool_response"),
    ({"stdout": "", "content": "c"}, "tool_response"),
    ({"other": 1}, "tool_response"),
    ([{"title": "T", "snippet": "S", "url": "u"}, {"content": "C"}, "plain", 7, True], "tool_response"),
    ("from older builds", "tool_result"),
    ("", "tool_response"),
], ids=["string", "dict-result", "dict-empty-first", "dict-fallback", "search-list", "tool_result", "empty"])
def test_web_search_shapes(go_bin, api, tmp_path, response, key):
    both(go_bin, api, tmp_path, "PostToolUse", post("WebSearch", response=response, key=key))


def test_web_content_without_key_allows(go_bin, api, tmp_path):
    r = both(go_bin, api, tmp_path, "PostToolUse", post("WebFetch"), env={"AGENTGUARDS_API_KEY": None})
    assert r["requests"] == [] and r["exit"] == 0


@pytest.mark.parametrize("cmd", ["curl https://x", "sudo wget -qO- x", 'bash -c "curl x"', "ls", "git status"])
def test_bash_post_tool_use(go_bin, api, tmp_path, cmd):
    api.routes["/v1/guardrails/evaluate-input"] = (200, {"decision": "block", "message": "bad"})
    both(go_bin, api, tmp_path, "PostToolUse", post("Bash", {"command": cmd}, response={"stdout": "out"}))


@pytest.mark.parametrize("tool,tool_input", [
    ("Write", {"file_path": "a.py", "content": "API_KEY='x'"}),
    ("Edit", {"file_path": "a.py", "old_string": "a", "new_string": "b = 1"}),
    ("MultiEdit", {"file_path": "a.py", "edits": [{"new_string": "x = 1"}, {"old_string": "y"}, "junk"]}),
    ("Write", {"content": "no path"}),
    ("Write", {"file_path": "a.py", "content": ""}),
    ("Write", {"file_path": "a.py", "content": 42}),
], ids=["write", "edit", "multiedit", "no-path", "empty", "non-string"])
def test_code_scan_inputs(go_bin, api, tmp_path, tool, tool_input):
    api.routes["/v1/code/scan"] = (200, {"decision": "allow"})
    both(go_bin, api, tmp_path, "PostToolUse", post(tool, tool_input))


@pytest.mark.parametrize("route,env", [
    ((200, {"decision": "block", "message": "secret found"}), {}),
    ((200, {"decision": "block"}), {}),
    ((200, {"decision": "warn", "message": "heads up"}), {}),
    ((403, {"detail": "not enabled"}), {}),
    ((429, {"error": "QUOTA_EXCEEDED", "message": "q"}), {}),
    ((500, {}), {}),
    ((500, {}), {"AGENTGUARDS_FAIL_OPEN": "on"}),
], ids=["block", "block-default", "warn", "forbidden", "quota", "outage", "fail-open"])
def test_code_scan_verdicts(go_bin, api, tmp_path, route, env):
    api.routes["/v1/code/scan"] = route
    both(go_bin, api, tmp_path, "PostToolUse", post("Write", {"file_path": "a.py", "content": "x = 1"}), env=env)


def test_code_scan_without_key_allows(go_bin, api, tmp_path):
    both(go_bin, api, tmp_path, "PostToolUse", post("Write", {"file_path": "a.py", "content": "x"}),
         env={"AGENTGUARDS_API_KEY": None})


def test_approval_flow_end_to_end(go_bin, api, tmp_path):
    """ask (marks pending) -> the command runs (PostToolUse redeems) -> next time it's allowed."""
    api.routes["/v1/actions/authorize"] = (200, {"decision": "require-approval", "reason": "r"})
    for name, cmd in (("py", [sys.executable, str(PY_HOOK)]), ("go", list(go_bin))):
        home = tmp_path / name
        home.mkdir()
        env = {"AGENTGUARDS_API_KEY": KEY}
        _run(cmd, "PreToolUse", json.dumps(pre("make install")), home, env, api)
        _run(cmd, "PostToolUse", json.dumps(post("Bash", {"command": "make install"}, response={"stdout": "ok"})), home, env, api)
        third = _run(cmd, "PreToolUse", json.dumps(pre("make build")), home, env, api)
        assert third["stdout"]["hookSpecificOutput"]["permissionDecision"] == "allow", name
    assert _approvals(tmp_path / "go") == _approvals(tmp_path / "py")


# Review findings, pinned ----------------------------------------------------------------

@pytest.mark.parametrize("decision", [None, 1], ids=["null", "number"])
@pytest.mark.parametrize("path,event_type,event", [
    ("/v1/guardrails/evaluate-input", "UserPromptSubmit", PROMPT),
    ("/v1/actions/authorize", "PreToolUse", pre("make build")),
    ("/v1/guardrails/evaluate-input", "PostToolUse", post("WebFetch")),
    ("/v1/code/scan", "PostToolUse", post("Write", {"file_path": "a.py", "content": "x"})),
], ids=["prompt", "pre-tool", "web", "code-scan"])
def test_non_string_decision_is_never_an_implicit_allow(go_bin, api, tmp_path, decision, path, event_type, event):
    api.routes[path] = (200, {"decision": decision})
    both(go_bin, api, tmp_path, event_type, event)


def test_zero_content_is_empty_like_python(go_bin, api, tmp_path):
    r = both(go_bin, api, tmp_path, "PostToolUse", post("Write", {"file_path": "a.py", "content": 0}))
    assert r["requests"] == []


def test_zero_title_is_dropped_like_python(go_bin, api, tmp_path):
    both(go_bin, api, tmp_path, "PostToolUse",
         post("WebSearch", response=[{"title": 0, "snippet": "s", "url": "u"}, {"title": 0.0, "snippet": 1.5}]))
