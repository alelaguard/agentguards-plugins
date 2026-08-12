"""Every hook a plugin declares must be able to start on this platform.

0.2.18 split each Claude hook into a `shell: bash` and a `shell: powershell` entry so
Windows without Git Bash could run them. But `shell` chooses the interpreter; it does
not gate by platform, and Claude Code dispatches all matching hooks in parallel. So
every Linux and macOS user got, on every prompt and every tool call:

    Failed to run: Hook "powershell ... agentguards_hook.ps1 PostToolUse"
    has shell: 'powershell' but no PowerShell

Nothing caught it. The manifest was valid, the JSON parsed, the script existed. What
nobody checked was whether the thing could execute at all.
"""

from __future__ import annotations

import json
import pathlib
import re
import shutil

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFESTS = sorted(ROOT.glob("*/hooks.json")) + sorted(ROOT.glob("*/hooks/hooks.json"))


def declared_hooks(manifest: pathlib.Path):
    events = json.loads(manifest.read_text())["hooks"]
    for event, groups in events.items():
        for group in groups:
            entries = group["hooks"] if isinstance(group, dict) and "hooks" in group else [group]
            for entry in entries:
                yield event, entry


@pytest.mark.parametrize("manifest", MANIFESTS, ids=lambda p: p.parts[-3] if p.name == "hooks.json" and p.parent.name == "hooks" else p.parent.name)
def test_declared_shell_is_available_here(manifest):
    """A hook may only name a shell this platform can actually run.

    Naming `powershell` does not make a hook Windows-only — it makes it fail
    everywhere PowerShell is absent. Platform dispatch belongs *inside* the command.
    """
    for event, entry in declared_hooks(manifest):
        shell = entry.get("shell")
        if shell is None:
            continue
        assert shutil.which(shell), (
            f"{manifest.parent.name} {event}: declares shell={shell!r}, which is not "
            f"installed here. Claude Code runs every matching hook regardless of "
            f"platform, so this errors on every event. Dispatch on $OS inside the "
            f"command instead of declaring a shell that may be missing."
        )


@pytest.mark.parametrize("manifest", MANIFESTS, ids=lambda p: p.parts[-3] if p.name == "hooks.json" and p.parent.name == "hooks" else p.parent.name)
def test_referenced_scripts_exist(manifest):
    """A hook command must point at a file that ships in the plugin."""
    plugin_root = manifest.parent if manifest.name == "hooks.json" and manifest.parent.name != "hooks" else manifest.parent.parent
    for event, entry in declared_hooks(manifest):
        command = entry.get("command", "")
        for token in command.replace('"', " ").split():
            if token.endswith((".py", ".ps1", ".ts")):
                # Strip whichever root placeholder the agent uses, and Gemini's
                # ${/} path separator, leaving a plugin-relative path.
                rel = re.sub(r"\$\{[^}]*\}", "/", token).lstrip("/")
                rel = re.sub(r"/+", "/", rel)
                assert (plugin_root / rel).is_file(), (
                    f"{plugin_root.name} {event}: command references {rel}, "
                    f"which is not in the plugin"
                )
