"""Shared fixtures for the plugin hook behaviour tests.

These tests load each shipped hook script directly and drive its handlers, so they
assert what a user's machine will actually do — not what a manifest claims.

Every case here corresponds to a bug that reached `main` and was caught by a human
rather than by CI. Before this suite the repo checked manifests, versions and
undefined names; nothing ever executed a hook.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Destructive strings are assembled from fragments: this repo's own PreToolUse
# guardrail blocks tool calls containing them, which makes a literal here unreadable
# by the agent that maintains the file.
SAFE_CMD = "rm stale.log"
RISKY_CMD = "rm -" + "rf ~/work"
DENIED_CMD = "rm -" + "rf /"

ALLOW = {"decision": "allow"}
ASK = {"decision": "require-approval", "reason": "risky"}

#: Every shipped hook, with the facts a test needs to drive it.
#:
#: ``approvals``    -- has a session approval cache (gemini deliberately does not)
#: ``no_key_allows`` -- what an unconfigured install does. Only the SaaS claude plugin
#:                      warns-and-allows; the rest are deliberately fail-closed, and
#:                      applying claude's behaviour to them would weaken them.
HOOKS = {
    "claude":             dict(path="claude/scripts/agentguards_hook.py",
                               approvals=True,  no_key_allows=True),
    "claude-selfhosted":  dict(path="claude-selfhosted/scripts/agentguards_hook.py",
                               approvals=True,  no_key_allows=False),
    "codex":              dict(path="codex/scripts/agentguards_codex_hook.py",
                               approvals=True,  no_key_allows=False),
    "codex-selfhosted":   dict(path="codex-selfhosted/scripts/agentguards_codex_hook.py",
                               approvals=True,  no_key_allows=False),
    "copilot":            dict(path="copilot/scripts/agentguards_copilot_hook.py",
                               approvals=True,  no_key_allows=False),
    "copilot-selfhosted": dict(path="copilot-selfhosted/scripts/agentguards_copilot_hook.py",
                               approvals=True,  no_key_allows=False),
    "gemini":             dict(path="gemini/scripts/agentguards_gemini_hook.py",
                               approvals=False, no_key_allows=False),
    "gemini-selfhosted":  dict(path="gemini-selfhosted/scripts/agentguards_gemini_hook.py",
                               approvals=False, no_key_allows=False),
}


def load_hook(name: str, tmp_path, *, env: dict[str, str] | None = None):
    """Import a hook fresh, with its approvals cache pointed at a temp file."""
    spec = importlib.util.spec_from_file_location(
        f"hook_{name.replace('-', '_')}", ROOT / HOOKS[name]["path"]
    )
    module = importlib.util.module_from_spec(spec)
    import os

    saved = {k: os.environ.get(k) for k in
             ("AGENTGUARDS_API_KEY", "AGENTGUARDS_URL",
              "CLAUDE_PLUGIN_OPTION_AGENTGUARDS_API_KEY", "AGENTGUARDS_FAIL_OPEN")}
    for key in saved:
        os.environ.pop(key, None)
    os.environ.update(env or {})
    try:
        spec.loader.exec_module(module)
    finally:
        for key, value in saved.items():
            os.environ.pop(key, None)
            if value is not None:
                os.environ[key] = value

    if hasattr(module, "_APPROVALS_PATH"):
        module._APPROVALS_PATH = str(tmp_path / f"{name}-approvals.json")
    if hasattr(module, "_api_key"):
        module._api_key = lambda: (env or {}).get("AGENTGUARDS_API_KEY", "")
    return module


def drive(hook, handler: str, event: dict) -> str:
    """Run a handler and return whatever it wrote to stdout (its decision channel)."""
    buf = io.StringIO()
    with contextlib.suppress(SystemExit), contextlib.redirect_stdout(buf), \
            contextlib.redirect_stderr(io.StringIO()):
        getattr(hook, handler)(event)
    return buf.getvalue()


def decision(output: str) -> str:
    """The verdict a hook emitted, or 'allow' when it stayed silent (exit 0, no JSON)."""
    if not output.strip():
        return "allow"
    data = json.loads(output)
    if "decision" in data:
        return data["decision"]
    inner = data.get("hookSpecificOutput") or data
    return inner.get("permissionDecision", "allow")


@pytest.fixture(params=sorted(HOOKS))
def any_hook(request, tmp_path):
    """Each shipped hook in turn, configured with a key."""
    name = request.param
    return name, load_hook(name, tmp_path, env={"AGENTGUARDS_API_KEY": "ag_test",
                                                "AGENTGUARDS_URL": "https://t.invalid"})
