"""Hooks find the key the AgentGuards installer saved in ~/.agentguards/credentials.json.

The installer can't set environment variables for an agent that is already running
or was launched from a GUI, so it saves the key to a file instead. The hooks of
the agents it sets up (Claude Code, Codex) must fall back to that file, and only
as the LAST resort: an explicit env var or plugin setting must always win.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Hook → how to read the key it resolved.
SAAS_HOOKS = {
    "claude": ("claude/scripts/agentguards_hook.py", "attr"),
    "codex": ("codex/scripts/agentguards_codex_hook.py", "func"),
}

SAVED = "ag_" + "1" * 32
FROM_ENV = "ag_" + "2" * 32


def _resolved_key(name: str, home: pathlib.Path, monkeypatch) -> str:
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    path, how = SAAS_HOOKS[name]
    spec = importlib.util.spec_from_file_location(f"hook_{name}_creds", ROOT / path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.AGENTGUARDS_API_KEY if how == "attr" else mod._api_key()


def _save(home: pathlib.Path, body: str) -> None:
    (home / ".agentguards").mkdir(parents=True, exist_ok=True)
    (home / ".agentguards" / "credentials.json").write_text(body)


@pytest.fixture
def clean_env(monkeypatch):
    for var in ("AGENTGUARDS_API_KEY", "CLAUDE_PLUGIN_OPTION_AGENTGUARDS_API_KEY"):
        monkeypatch.delenv(var, raising=False)


@pytest.mark.parametrize("name", SAAS_HOOKS)
def test_uses_the_installer_key_when_nothing_else_is_set(name, tmp_path, monkeypatch, clean_env):
    _save(tmp_path, json.dumps({"api_key": SAVED}))
    assert _resolved_key(name, tmp_path, monkeypatch) == SAVED


@pytest.mark.parametrize("name", SAAS_HOOKS)
def test_env_var_wins_over_the_installer_key(name, tmp_path, monkeypatch, clean_env):
    _save(tmp_path, json.dumps({"api_key": SAVED}))
    monkeypatch.setenv("AGENTGUARDS_API_KEY", FROM_ENV)
    assert _resolved_key(name, tmp_path, monkeypatch) == FROM_ENV


@pytest.mark.parametrize("name", SAAS_HOOKS)
@pytest.mark.parametrize(
    "body",
    ["not json", json.dumps(["ag_x"]), json.dumps({"api_key": "sk-not-ours"}), json.dumps({})],
    ids=["malformed", "not-an-object", "wrong-prefix", "no-key"],
)
def test_a_bad_credentials_file_is_ignored_not_fatal(name, body, tmp_path, monkeypatch, clean_env):
    _save(tmp_path, body)
    assert _resolved_key(name, tmp_path, monkeypatch) == ""


@pytest.mark.parametrize("name", SAAS_HOOKS)
def test_no_file_means_no_key(name, tmp_path, monkeypatch, clean_env):
    assert _resolved_key(name, tmp_path, monkeypatch) == ""


def test_claude_plugin_setting_wins_over_the_installer_key(tmp_path, monkeypatch, clean_env):
    _save(tmp_path, json.dumps({"api_key": SAVED}))
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_AGENTGUARDS_API_KEY", FROM_ENV)
    assert _resolved_key("claude", tmp_path, monkeypatch) == FROM_ENV


def test_codex_token_file_wins_over_the_installer_key(tmp_path, monkeypatch, clean_env):
    _save(tmp_path, json.dumps({"api_key": SAVED}))
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "agentguards_token").write_text(FROM_ENV + "\n")
    assert _resolved_key("codex", tmp_path, monkeypatch) == FROM_ENV


def test_empty_codex_token_file_falls_through_to_the_installer_key(tmp_path, monkeypatch, clean_env):
    """A blanked ~/.codex/agentguards_token must not hide the saved key — Codex is
    fail-closed, so resolving "" would block every prompt."""
    _save(tmp_path, json.dumps({"api_key": SAVED}))
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "agentguards_token").write_text("  \n")
    assert _resolved_key("codex", tmp_path, monkeypatch) == SAVED
