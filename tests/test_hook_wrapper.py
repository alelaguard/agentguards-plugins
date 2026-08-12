"""The dispatcher that keeps hooks.json's `command` short.

Claude Code prints a hook's whole command in brackets ahead of its message. With a
561-character inline shell one-liner, a blocked prompt rendered as a wall of shell
before the user reached "Prompt blocked":

    A hook blocked your prompt
    [if [ "$OS" = "Windows_NT" ]; then PS=powershell; command -v powershell …]: 🛡️ …

Moving the dispatch into run-hook.sh takes that to 60 characters. These tests pin the
behaviour that must survive the move — above all that a block is still a block.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "claude" / "scripts" / "run-hook.sh"


def run(event: str, *, path: str | None = None, stdin: str = "{}"):
    env = dict(os.environ, CLAUDE_PLUGIN_ROOT=str(ROOT / "claude"))
    env.pop("AGENTGUARDS_API_KEY", None)
    if path is not None:
        env["PATH"] = path
    return subprocess.run([str(WRAPPER), event], input=stdin, capture_output=True,
                          text=True, env=env)


@pytest.fixture
def no_python(tmp_path):
    """A PATH with a shell but no python3, to exercise the fallback branch."""
    binaries = tmp_path / "bin"
    binaries.mkdir()
    for name in ("bash", "dirname", "pwd", "printf", "echo", "command"):
        found = shutil.which(name)
        if found:
            (binaries / name).symlink_to(found)
    assert shutil.which("python3", path=str(binaries)) is None
    return str(binaries)


def test_the_command_in_the_manifest_stays_short():
    """The whole point. A long command is printed verbatim to the user on a block."""
    hooks = json.loads((ROOT / "claude" / "hooks" / "hooks.json").read_text())["hooks"]
    for event, groups in hooks.items():
        for group in groups:
            for entry in group["hooks"]:
                command = entry["command"]
                assert len(command) < 120, (
                    f"{event}: command is {len(command)} chars. Claude Code prints it "
                    f"in brackets before the hook's message, so anything long makes a "
                    f"block unreadable. Put the logic in run-hook.sh."
                )


def test_the_wrapper_ships_and_is_executable():
    assert WRAPPER.is_file(), "hooks.json points at run-hook.sh; it must ship"
    assert os.access(WRAPPER, os.X_OK), "run-hook.sh must be executable"


def test_a_block_is_still_a_block(tmp_path):
    """Exit code 2 is Claude Code's only blocking signal. If the wrapper swallowed it,
    every block would silently become an allow — the worst possible regression here."""
    real = ROOT / "claude" / "scripts" / "agentguards_hook.py"
    backup = tmp_path / "hook.py"
    shutil.copy(real, backup)
    real.write_text("import sys\nprint('blocked', file=sys.stderr)\nsys.exit(2)\n")
    try:
        assert run("UserPromptSubmit").returncode == 2
    finally:
        shutil.copy(backup, real)


def test_missing_python_never_blocks(no_python):
    """A missing runtime is a setup gap, not a security event. Blocking every message
    over it makes the host look broken rather than unconfigured."""
    assert run("PreToolUse", path=no_python).returncode == 0
    assert run("UserPromptSubmit", path=no_python).returncode == 0


def test_missing_python_warns_on_the_channel_each_event_actually_surfaces(no_python):
    """stderr from a hook that exits 0 reaches only the debug log, so the warning has
    to go somewhere the user will see: permissionDecisionReason at PreToolUse, stdout
    at UserPromptSubmit (which is added to the model's context)."""
    pre = json.loads(run("PreToolUse", path=no_python).stdout)["hookSpecificOutput"]
    assert pre["permissionDecision"] == "allow"
    assert "not protected" in pre["permissionDecisionReason"]

    assert "not protected" in run("UserPromptSubmit", path=no_python).stdout


def test_post_tool_use_stays_silent_without_python(no_python):
    """PostToolUse has no channel that surfaces on a zero exit, so a warning there
    would be noise on every single tool call."""
    assert run("PostToolUse", path=no_python).stdout.strip() == ""
