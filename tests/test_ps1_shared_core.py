"""The two PowerShell hooks carry the same shared core inline (each is a single file
the agent runs directly), and both must stay pure ASCII: Windows PowerShell 5.1 reads
a BOM-less script as Windows-1252, which garbles any non-ASCII literal."""

import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
HOOKS = [ROOT / "claude" / "scripts" / "agentguards_hook.ps1",
         ROOT / "codex" / "scripts" / "agentguards_codex_hook.ps1"]
BEGIN, END = "# >>> AGENTGUARDS SHARED CORE", "# <<< AGENTGUARDS SHARED CORE"


def _core(path):
    text = path.read_text(encoding="utf-8")
    return text[text.index(BEGIN):text.index(END)]


def test_shared_core_is_identical():
    claude, codex = (_core(p) for p in HOOKS)
    assert claude == codex, "edit the shared core in both PowerShell hooks"


@pytest.mark.parametrize("path", HOOKS, ids=lambda p: p.parent.parent.name)
def test_hook_is_ascii(path):
    bad = [(n, line) for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
           if not line.isascii()]
    assert not bad, f"non-ASCII lines (build the character from its code point): {bad[:3]}"
