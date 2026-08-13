"""End-to-end smoke test: drives the REAL published Claude Code plugin inside a
container via a pty-attached `claude` session, and asserts on what actually
lands in a user's terminal — not on a hook function's return value.

This complements ../test_hook_security_behaviour.py rather than replacing it:
that suite proves the hook LOGIC is correct by calling its functions directly.
This one proves the INSTALLED, PUBLISHED plugin behaves correctly inside a
real TUI session, which is the only place a UI-rendering bug is visible — e.g.
PR #258, where the block message echoed the raw prompt back. A test that
calls `_block()` directly never touches a terminal and would not have caught it.

Needs a live AGENTGUARDS_API_KEY + ANTHROPIC_API_KEY and network access to prod
SaaS, so it is skipped without them — same reasoning as the monorepo excluding
`promptguard` tests from the default CI sweep. Run this explicitly via the
`test-plugin-e2e` skill before a release, not as part of `pytest tests/`.

Per tests/README.md's rule: watch each assertion fail first before trusting it.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess

import pytest

from drive_session import BLOCK_PROMPT, run_session

pytestmark = pytest.mark.skipif(
    not (os.environ.get("AGENTGUARDS_API_KEY") and os.environ.get("ANTHROPIC_API_KEY")),
    reason="needs a live AGENTGUARDS_API_KEY and ANTHROPIC_API_KEY against prod SaaS "
           "— run via the test-plugin-e2e skill, not the default pytest sweep",
)

E2E_DIR = pathlib.Path(__file__).resolve().parent
IMAGE = "agentguards-claude-e2e"
CONTAINER = "agentguards-claude-e2e-run"

# Known failure signatures already seen in practice, not a generic "any traceback"
# grep — each corresponds to a specific incident:
#   ERR_STREAM_PREMATURE_CLOSE -- git missing from node:22-slim, looks like an SSH
#                                  failure but never reaches SSH (reference-ag-test-container)
#   MCP server disconnected    -- the MCP half of the plugin never came up
#   Traceback (most recent     -- the hook crashed instead of returning allow/block
ERROR_SIGNATURES = (
    "ERR_STREAM_PREMATURE_CLOSE",
    "MCP server disconnected",
    "Traceback (most recent",
)


@pytest.fixture(scope="module")
def session():
    if shutil.which("docker") is None:
        pytest.skip("docker not available")

    subprocess.run(["docker", "build", "-t", IMAGE, str(E2E_DIR)], check=True)
    subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True)
    subprocess.run([
        "docker", "run", "-d", "--name", CONTAINER,
        "--dns", "8.8.8.8", "--dns", "1.1.1.1",
        "-e", f"AGENTGUARDS_API_KEY={os.environ['AGENTGUARDS_API_KEY']}",
        "-e", f"ANTHROPIC_API_KEY={os.environ['ANTHROPIC_API_KEY']}",
        "-w", "/demo", IMAGE,
    ], check=True)
    try:
        yield run_session(CONTAINER)
    finally:
        subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True)


def test_plugin_installs_and_connects(session):
    """/plugin install + /mcp: the published plugin registers and its MCP half
    actually connects — the class of bug 0.2.18 shipped (errored on every
    event, so nothing past this point would ever run for a real user)."""
    assert "agentguards-claude" in session.raw
    assert "agentguards" in session.raw.lower()
    for bad in ("failed to install", "not found", "error installing"):
        assert bad not in session.raw.lower(), session.raw


def test_normal_prompt_gets_a_normal_reply(session):
    """A benign prompt must not trip the guardrail — no block marker anywhere
    before the blocking prompt is even sent."""
    before_block = session.raw.split(BLOCK_PROMPT)[0]
    for marker in ("Prompt blocked", "Request blocked", "🛡️"):
        assert marker not in before_block, (
            f"guardrail fired on a benign prompt (saw {marker!r}):\n{session.raw}"
        )


def test_blocked_prompt_shows_the_readable_block_message(session):
    """The jailbreak prompt must actually be blocked, and the message must be
    the readable, formatted text from `_block()` — never raw JSON, and never
    the prompt echoed back. The echo case is the exact regression PR #258
    fixed: the block message used to carry the attacker's own text into what
    the user (and the model) read next."""
    after = session.raw.split(BLOCK_PROMPT, 1)[-1]
    assert "🛡️" in after or "[AgentGuards]" in after, (
        f"blocking prompt produced no visible block message:\n{session.raw}"
    )
    assert "Decision:" in after or "**Reason:**" in after, (
        f"block message is missing the structured Decision/Reason/Severity shape:\n{after}"
    )
    assert '{"decision"' not in after and '"check_name"' not in after, (
        f"raw check_input JSON leaked to the user instead of the formatted message:\n{after}"
    )
    assert BLOCK_PROMPT not in after, (
        f"the block message echoed the attacker's prompt back — the PR #258 regression:\n{after}"
    )


def test_no_errors_in_transcript(session):
    """Scan the full raw transcript, not just the final rendered screen — some
    errors scroll past before the screen settles."""
    hits = [sig for sig in ERROR_SIGNATURES if sig in session.raw]
    assert not hits, f"error signature(s) found in transcript: {hits}\n{session.raw}"
