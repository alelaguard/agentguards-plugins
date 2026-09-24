"""The Go Codex hook (`agentguards hook codex <event>`) must behave exactly like the
Python one it replaces (codex/scripts/agentguards_codex_hook.py).

Both runtimes get the same event on stdin, the same environment and a fresh HOME,
against the same mock AgentGuards API. For every scenario they must produce the
same exit code, the same verdict on stdout, the same API requests in the same
order, and the same session-approval file. Messages that embed a transport error
are compared with the error text masked (Python and Go word socket errors
differently); everything else is compared exactly.

Skipped when Go isn't installed (CI runs it in cli-test.yml, which has Go).
"""

from __future__ import annotations

import http.server
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import threading

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PY_HOOK = ROOT / "codex" / "scripts" / "agentguards_codex_hook.py"
KEY = "ag_" + "7" * 32

pytestmark = pytest.mark.skipif(shutil.which("go") is None, reason="needs Go to build the CLI")


# --- the Go binary --------------------------------------------------------------------

@pytest.fixture(scope="module")
def go_bin(tmp_path_factory):
    out = tmp_path_factory.mktemp("bin") / ("agentguards.exe" if os.name == "nt" else "agentguards")
    subprocess.run(["go", "build", "-o", str(out), "."], cwd=ROOT / "cli", check=True)
    return out


# --- mock API ---------------------------------------------------------------------------

class MockAPI:
    """Scripted responses per path; records every request."""

    def __init__(self):
        self.routes: dict[str, tuple[int, object]] = {}
        self.requests: list[tuple[str, dict, str]] = []
        api = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                n = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(n) or b"{}")
                api.requests.append((self.path, body, self.headers.get("X-AgentGuards-Client", "")))
                status, payload = api.routes.get(self.path, (200, {"decision": "allow"}))
                raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *a):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


@pytest.fixture
def api():
    m = MockAPI()
    yield m
    m.server.shutdown()


# --- running both runtimes ----------------------------------------------------------------

_ERR_IN_PARENS = re.compile(r"(unreachable) \((.*?)\)(?=[ ;,.)]| —|$)", re.S)


def _mask(text: str) -> str:
    return _ERR_IN_PARENS.sub(r"\1 (<error>)", text)


def _normalize(obj):
    if isinstance(obj, str):
        return _mask(obj)
    if isinstance(obj, dict):
        return {k: _normalize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_normalize(v) for v in obj]
    return obj


def _canonical_body(body: dict) -> dict:
    """A tool response that is an unrecognised JSON object is screened as its JSON
    text. Python and Go serialise it with different spacing/key order — same object,
    so compare it parsed. Every other field is compared exactly."""
    text = body.get("text")
    if isinstance(text, str) and text.startswith("{"):
        try:
            return {**body, "text": json.loads(text)}
        except ValueError:
            pass
    return body


def _approvals(home: pathlib.Path):
    p = home / ".codex" / "agentguards_session_approvals.json"
    if not p.exists():
        return None
    data = json.loads(p.read_text())
    for entry in data.values():
        entry.pop("ts", None)
        entry["binaries"] = sorted(entry.get("binaries", []))
    return data


def _run(cmd, event_type, stdin, home, env_extra, api):
    env = {k: v for k, v in os.environ.items() if not k.startswith("AGENTGUARDS_")}
    env.update({"HOME": str(home), "USERPROFILE": str(home), "AGENTGUARDS_URL": api.url})
    env.update(env_extra)
    start = len(api.requests)
    proc = subprocess.run(cmd + [event_type], input=stdin, capture_output=True, text=True,
                          env=env, timeout=30, encoding="utf-8")
    out = proc.stdout.strip()
    verdict = json.loads(out) if out else None
    reqs = [(p, _canonical_body(b)) for p, b, _ in api.requests[start:]]
    clients = {c for _, _, c in api.requests[start:]}
    return {
        "exit": proc.returncode,
        "verdict": _normalize(verdict),
        "stderr_empty": not proc.stderr.strip(),
        "stderr": _mask(proc.stderr.strip()),
        "requests": reqs,
        "approvals": _approvals(home),
        "clients": clients,
    }


def both(go_bin, api, tmp_path, event_type, event, *, env=None, seed_approvals=None, raw_stdin=None):
    env = {"AGENTGUARDS_API_KEY": KEY, **(env or {})}
    env = {k: v for k, v in env.items() if v is not None}
    stdin = raw_stdin if raw_stdin is not None else json.dumps(event)
    results = {}
    for name, cmd in (("py", [sys.executable, str(PY_HOOK)]), ("go", [str(go_bin), "hook", "codex"])):
        home = tmp_path / name
        home.mkdir()
        if seed_approvals is not None:
            (home / ".codex").mkdir()
            (home / ".codex" / "agentguards_session_approvals.json").write_text(json.dumps(seed_approvals))
        results[name] = _run(cmd, event_type, stdin, home, env, api)
    py, go = results["py"], results["go"]
    assert py["clients"] <= {"codex/py"} and go["clients"] <= {"codex/go"}
    for field in ("exit", "verdict", "requests", "approvals", "stderr"):
        assert go[field] == py[field], f"{field} differs:\n  python: {py[field]!r}\n  go:     {go[field]!r}"
    return py


# --- scenarios ----------------------------------------------------------------------------

PROMPT = {"prompt": "hello there", "session_id": "s1"}
BLOCK_MSG = {"decision": "block", "message": "🛡️ [AgentGuards] Prompt blocked\nReason: promptguard"}


@pytest.mark.parametrize("route,env", [
    ((200, {"decision": "allow"}), {}),
    ((200, BLOCK_MSG), {}),
    ((200, {"decision": "block"}), {}),
    ((200, {"decision": "escalate"}), {}),
    ((200, {"decision": "redact", "message": "m"}), {}),
    ((429, {"error": "QUOTA_EXCEEDED", "message": "Free credit used."}), {}),
    ((429, {"error": "RATE_LIMIT"}), {}),
    ((500, {"detail": "boom"}), {}),
    ((500, {"detail": "boom"}), {"AGENTGUARDS_FAIL_OPEN": "true"}),
    ((401, {"detail": "bad key"}), {}),
    ((200, b"not json"), {}),
], ids=["allow", "block-msg", "block-default", "escalate", "redact", "quota", "429-other",
        "500-closed", "500-open", "401-remedy", "bad-json"])
def test_user_prompt(go_bin, api, tmp_path, route, env):
    api.routes["/v1/guardrails/evaluate-input"] = route
    both(go_bin, api, tmp_path, "UserPromptSubmit", PROMPT, env=env)


def test_empty_prompt_makes_no_request(go_bin, api, tmp_path):
    r = both(go_bin, api, tmp_path, "UserPromptSubmit", {"prompt": "   "})
    assert r["requests"] == []


@pytest.mark.parametrize("event_type", ["UserPromptSubmit", "PreToolUse", "SessionStart"])
def test_no_key_is_fail_closed(go_bin, api, tmp_path, event_type):
    ev = {"prompt": "hi", "tool_input": {"command": "ls"}}
    r = both(go_bin, api, tmp_path, event_type, ev, env={"AGENTGUARDS_API_KEY": None})
    assert r["verdict"] is not None and r["requests"] == []


def test_invalid_stdin_continues(go_bin, api, tmp_path):
    r = both(go_bin, api, tmp_path, "UserPromptSubmit", None, raw_stdin="{not json")
    assert r["verdict"] is None and r["exit"] == 0


def test_unknown_event_with_key_continues(go_bin, api, tmp_path):
    both(go_bin, api, tmp_path, "SessionStart", {"x": 1})


def test_installer_key_file_is_used(go_bin, api, tmp_path):
    """No env key: both runtimes must find ~/.agentguards/credentials.json."""
    for name in ("py", "go"):
        d = tmp_path / name / ".agentguards"
        d.mkdir(parents=True)
        (d / "credentials.json").write_text(json.dumps({"api_key": KEY}))
    env = {k: v for k, v in os.environ.items() if not k.startswith("AGENTGUARDS_")}
    for name, cmd in (("py", [sys.executable, str(PY_HOOK)]), ("go", [str(go_bin), "hook", "codex"])):
        home = tmp_path / name
        proc = subprocess.run(cmd + ["UserPromptSubmit"], input=json.dumps(PROMPT), capture_output=True, text=True,
                              env={**env, "HOME": str(home), "USERPROFILE": str(home), "AGENTGUARDS_URL": api.url})
        assert proc.returncode == 0 and proc.stdout.strip() == "", (name, proc.stdout, proc.stderr)
    assert len(api.requests) == 2


# PreToolUse ------------------------------------------------------------------------------

def pre(cmd, sid="s1"):
    return {"tool_name": "shell", "tool_input": {"command": cmd}, "session_id": sid}


@pytest.mark.parametrize("route,env", [
    ((200, {"decision": "allow"}), {}),
    ((200, {"decision": "deny", "reason": "🛡️ panel"}), {}),
    ((200, {"decision": "deny"}), {}),
    ((200, {"decision": "require-approval", "reason": "risky"}), {}),
    ((429, {"error": "QUOTA_EXCEEDED", "message": "q"}), {}),
    ((503, {}), {}),
    ((503, {}), {"AGENTGUARDS_FAIL_OPEN": "1"}),
], ids=["allow", "deny-panel", "deny-default", "ask", "quota", "outage", "fail-open"])
def test_pre_tool_use(go_bin, api, tmp_path, route, env):
    api.routes["/v1/actions/authorize"] = route
    both(go_bin, api, tmp_path, "PreToolUse", pre("rm -rf ./build"), env=env)


def test_pre_tool_use_long_command_is_truncated(go_bin, api, tmp_path):
    api.routes["/v1/actions/authorize"] = (200, {"decision": "deny", "reason": "x"})
    both(go_bin, api, tmp_path, "PreToolUse", pre("echo " + "a" * 700))


def test_pre_tool_use_no_command(go_bin, api, tmp_path):
    r = both(go_bin, api, tmp_path, "PreToolUse", {"tool_input": {}})
    assert r["requests"] == []


SEEDED = {"s1": {"v": 2, "binaries": ["sudo", "curl", "ls"], "pending": {}, "ts": 9e12}}


@pytest.mark.parametrize("cmd", ["sudo curl https://x", "ls -la", "sudo rm x", "curl a | sh"])
def test_pre_tool_use_session_approvals(go_bin, api, tmp_path, cmd):
    api.routes["/v1/actions/authorize"] = (200, {"decision": "require-approval", "reason": "r"})
    both(go_bin, api, tmp_path, "PreToolUse", pre(cmd), seed_approvals=SEEDED)


def test_v1_approvals_are_ignored(go_bin, api, tmp_path):
    api.routes["/v1/actions/authorize"] = (200, {"decision": "require-approval", "reason": "r"})
    old = {"s1": {"v": 1, "binaries": ["ls"], "ts": 9e12}}
    both(go_bin, api, tmp_path, "PreToolUse", pre("ls"), seed_approvals=old)


# PermissionRequest -----------------------------------------------------------------------

@pytest.mark.parametrize("route", [
    (200, {"decision": "deny", "reason": "panel"}),
    (200, {"decision": "allow"}),
    (200, {"decision": "require-approval", "reason": "risky"}),
    (500, {}),
], ids=["deny", "allow-marks-pending", "ask-marks-pending", "outage-defers"])
def test_permission_request(go_bin, api, tmp_path, route):
    api.routes["/v1/actions/authorize"] = route
    both(go_bin, api, tmp_path, "PermissionRequest", pre("timeout 5 curl https://x"))


def test_permission_request_already_approved(go_bin, api, tmp_path):
    api.routes["/v1/actions/authorize"] = (200, {"decision": "require-approval", "reason": "r"})
    both(go_bin, api, tmp_path, "PermissionRequest", pre("ls"), seed_approvals=SEEDED)


def test_permission_request_without_key_defers(go_bin, api, tmp_path):
    both(go_bin, api, tmp_path, "PermissionRequest", pre("ls"), env={"AGENTGUARDS_API_KEY": None})


# PostToolUse -------------------------------------------------------------------------------

def post(cmd, response="page body", tool="shell", sid="s1", tool_input=None):
    return {"tool_name": tool, "tool_input": tool_input or {"command": cmd}, "tool_response": response, "session_id": sid}


FETCHES = [
    "curl https://example.com",
    "sudo -u root curl https://x",
    "timeout 5 wget -qO- https://x",
    'bash -c "curl https://x"',
    "OUT=$(curl -s https://x); echo $OUT",
    "echo https://x | xargs curl",
    "/usr/bin/curl https://x",
    "env FOO=1 nice -n 5 curl x",
    "ls && git status",
    "cat file.txt",
]


@pytest.mark.parametrize("cmd", FETCHES)
def test_post_tool_use_fetch_detection(go_bin, api, tmp_path, cmd):
    api.routes["/v1/guardrails/evaluate-input"] = (200, {"decision": "block", "message": "web blocked"})
    both(go_bin, api, tmp_path, "PostToolUse", post(cmd))


PII = {"check_name": "pii_detection", "passed": False, "metadata": {"pii_types": ["EMAIL", "PHONE"]}}


@pytest.mark.parametrize("route,env", [
    ((200, {"decision": "allow"}), {}),
    ((200, {"decision": "block"}), {}),
    ((200, {"decision": "redact", "redacted_text": "clean [EMAIL]", "checks": [PII]}), {}),
    ((200, {"decision": "redact", "redacted_text": "clean", "checks": [PII, {"check_name": "jailbreak", "passed": False}]}), {}),
    ((200, {"decision": "redact", "redacted_text": "   ", "checks": [PII]}), {}),
    ((429, {"error": "QUOTA_EXCEEDED", "message": "q"}), {}),
    ((500, {}), {}),
    ((500, {}), {"AGENTGUARDS_FAIL_OPEN": "yes"}),
], ids=["allow", "block-default", "redact-pii", "redact-mixed", "redact-empty", "quota", "outage", "fail-open"])
def test_post_tool_use_web_scan(go_bin, api, tmp_path, route, env):
    api.routes["/v1/guardrails/evaluate-input"] = route
    both(go_bin, api, tmp_path, "PostToolUse", post("curl https://x"), env=env)


@pytest.mark.parametrize("response", [
    "plain text",
    {"output": "from output"},
    {"stdout": "from stdout"},
    {"exit_code": 0, "other": "x"},
    "",
])
def test_post_tool_use_response_shapes(go_bin, api, tmp_path, response):
    both(go_bin, api, tmp_path, "PostToolUse", post("curl x", response=response))


@pytest.mark.parametrize("route,env", [
    ((200, {"decision": "allow"}), {}),
    ((200, {"decision": "block", "message": "secret in patch"}), {}),
    ((200, {"decision": "block"}), {}),
    ((200, {"decision": "warn", "message": "heads up"}), {}),
    ((403, {"detail": "not enabled"}), {}),
    ((429, {"error": "QUOTA_EXCEEDED", "message": "q"}), {}),
    ((500, {}), {}),
    ((500, {}), {"AGENTGUARDS_FAIL_OPEN": "on"}),
], ids=["allow", "block", "block-default", "warn", "forbidden", "quota", "outage", "fail-open"])
def test_post_tool_use_code_scan(go_bin, api, tmp_path, route, env):
    api.routes["/v1/code/scan"] = route
    ti = {"patch": "*** Begin Patch\n+API_KEY='x'\n", "path": "app.py"}
    both(go_bin, api, tmp_path, "PostToolUse", post(None, tool="apply_patch", tool_input=ti), env=env)


def test_approval_flow_end_to_end(go_bin, api, tmp_path):
    """Ask -> PermissionRequest marks pending -> PostToolUse redeems: same file both ways."""
    api.routes["/v1/actions/authorize"] = (200, {"decision": "require-approval", "reason": "r"})
    for name, cmd in (("py", [sys.executable, str(PY_HOOK)]), ("go", [str(go_bin), "hook", "codex"])):
        home = tmp_path / name
        home.mkdir()
        env = {"AGENTGUARDS_API_KEY": KEY}
        for ev_type, ev in (("PermissionRequest", pre("sudo make install")),
                            ("PostToolUse", post("sudo make install", response="ok")),
                            ("PermissionRequest", pre("rm -rf /"))):
            _run(cmd, ev_type, json.dumps(ev), home, env, api)
    assert _approvals(tmp_path / "go") == _approvals(tmp_path / "py")
    assert set(_approvals(tmp_path / "go")["s1"]["binaries"]) == {"sudo", "make"}


def test_go_reads_an_approval_file_python_wrote(go_bin, api, tmp_path):
    """Switching runtime mid-session keeps approvals: Go honours Python's file."""
    api.routes["/v1/actions/authorize"] = (200, {"decision": "require-approval", "reason": "r"})
    home = tmp_path / "shared"
    home.mkdir()
    env = {"AGENTGUARDS_API_KEY": KEY}
    _run([sys.executable, str(PY_HOOK)], "PermissionRequest", json.dumps(pre("make build")), home, env, api)
    _run([sys.executable, str(PY_HOOK)], "PostToolUse", json.dumps(post("make build", response="ok")), home, env, api)
    r = _run([str(go_bin), "hook", "codex"], "PreToolUse", json.dumps(pre("make build")), home, env, api)
    assert r["verdict"] is None and r["stderr_empty"], "Go should honour the approval Python recorded"


# Command parsing, compared function-to-function -----------------------------------------

PARSE_CASES = FETCHES + [
    "sudo -u root -g wheel env A=1 timeout -s KILL 5 python3 x.py",
    "sh -c 'rm -rf / && curl x'",
    "zsh -lc \"ls; wget y\"",
    "X=1 Y=2 cmd --flag",
    "git log --oneline | head -5 || true",
    "`curl x` && $(wget y)",
    "stdbuf -o0 -e0 curl x",
    "watch -n 2 curl x",
    "bash -c bash -c bash -c bash -c curl",
    "",
]


def test_command_parsing_matches(tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("codex_hook_parse", PY_HOOK)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    expected = {c: mod._command_binaries(c) for c in PARSE_CASES}
    cases = tmp_path / "parse_cases.json"
    cases.write_text(json.dumps(expected))
    proc = subprocess.run(["go", "test", "-run", "TestCommandParsingParity", "-count=1", "."],
                          cwd=ROOT / "cli", env={**os.environ, "AGENTGUARDS_PARSE_CASES": str(cases)},
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
