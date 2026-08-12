# Plugin hook tests

These load each **shipped** hook script and drive its handlers, so they assert what a
user's machine will actually do — not what a manifest claims.

Run them:

    pytest tests/ -q

## Why they exist

Before this suite, CI validated manifests, versions and undefined names. **Nothing ever
executed a hook.** Every case here is a bug that reached users and was found by a person:

| Test | The bug it would have caught |
|---|---|
| `test_hooks_can_start` | 0.2.18 declared `shell: powershell`, which errored on **every event** for every Linux and macOS user |
| `test_unconfigured_install_behaves_as_that_plugin_intends` | the unconfigured-install fix landed in the monorepo and never reached the published plugin |
| `test_a_silently_allowed_command_never_becomes_an_approval` | `require-approval` was silently downgraded to `allow` |
| `test_every_fetch_form_is_scanned` | `sudo curl`, `bash -c "curl …"` and `$(curl …)` walked past the web-content scan |
| `test_a_blocked_page_is_never_quoted_back_to_the_model` | the block message carried 240 attacker-chosen characters into model context |

## The rule for adding one

**Watch it fail first.** Reintroduce the bug, confirm the test goes red, then restore.
A test nobody has seen fail is a decoration — this repo has already shipped one CI check
that was written to catch a specific bug and provably did not.

## Per-plugin expectations, not one global rule

`conftest.py` records what each plugin is *supposed* to do. The clearest example:
only the SaaS `claude` plugin warns-and-allows when no API key is configured, because
Claude Desktop has no shell profile to export into. The other seven are deliberately
fail-closed in every path, and applying claude's behaviour to them would weaken them.
Gemini has no approval cache at all.

Assert each plugin's own stance. A test that forces them all to behave identically
would be wrong.
