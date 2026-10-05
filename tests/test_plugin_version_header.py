"""Every SaaS hook that reports its version (X-AgentGuards-Client <agent>/<runtime>/<version>)
must report the version its plugin.json declares — the API decides "outdated" from it."""

from __future__ import annotations

import json
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]

CASES = [
    ("claude/.claude-plugin/plugin.json", "claude/scripts/agentguards_hook.py", "claude/scripts/agentguards_hook.ps1"),
    ("codex/.codex-plugin/plugin.json", "codex/scripts/agentguards_codex_hook.py", "codex/scripts/agentguards_codex_hook.ps1"),
]


@pytest.mark.parametrize("manifest,py,ps1", CASES, ids=["claude", "codex"])
def test_hook_version_matches_plugin_json(manifest, py, ps1):
    version = json.loads((ROOT / manifest).read_text())["version"]
    assert re.search(r'^_PLUGIN_VERSION = "([^"]+)"', (ROOT / py).read_text(), re.M).group(1) == version
    assert re.search(r"^\$PluginVersion = '([^']+)'", (ROOT / ps1).read_text(), re.M).group(1) == version


def test_claude_npm_package_matches_plugin_json():
    assert (json.loads((ROOT / "claude/package.json").read_text())["version"]
            == json.loads((ROOT / "claude/.claude-plugin/plugin.json").read_text())["version"])
