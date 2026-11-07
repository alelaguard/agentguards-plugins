# AgentGuards — Extension Scanner

Extensions run with your full user permissions: they can read your SSH keys, cloud
credentials and source code, and talk to any server. Malicious extensions have been
published to both the VS Code Marketplace and Open VSX.

AgentGuards checks every extension you have installed, and every one you install or
update, and warns you before a risky one can do harm.

## What it checks

- **Malware behaviour** in the extension's code — reading credential files (`~/.ssh`,
  `~/.aws`, browser profiles, crypto wallets), sending data to exfiltration endpoints
  (raw IPs, paste sites, Discord/Telegram webhooks), downloading and running code,
  obfuscated code, and bundled native programs. Signals are judged in combination, so
  a language server that legitimately runs programs isn't flagged for that alone.
- **Known-malware packages** bundled inside the extension.
- **Known vulnerabilities (CVEs)** in bundled dependencies.
- **Publisher reputation** — unverified publishers, very new extensions, and names
  that imitate a popular extension.

## What you see

- **Malicious or high risk:** a warning with a one-click **Uninstall**.
- **Medium risk** (for example, a bundled dependency with a known vulnerability): a
  notification. You can turn these off in settings.
- The **AgentGuards** view in the activity bar lists every extension with its verdict
  and findings.

## Connect your coding agents

The **Coding Agents** view shows whether the **Claude Code** and **Codex** command-line
tools on this computer are protected by AgentGuards, and connects them in one click.
Connected, AgentGuards screens their prompts, shell commands and fetched web content.

Connecting runs the official AgentGuards installer in a terminal, so you see exactly
what it does: it installs the AgentGuards plugin through each agent's own plugin
command and saves your API key to `~/.agentguards/credentials.json`, readable only by
you. The installer is downloaded from the AgentGuards GitHub release and checked
against the release's SHA-256 checksums before it runs. Checking the status tests
the key each agent sends with a read-only request to AgentGuards, which uses no quota.
An agent shows **Protected** only when its key works.

## Privacy

The extension sends AgentGuards only each extension's ID, version and platform, plus
your editor's name. It never sends code, files, or anything from your workspace.
AgentGuards downloads the extension from the public store and checks it on its own
servers.

Extensions installed from a file (`.vsix`) or a private gallery aren't in a public
store, so they're listed as not checked.

## Requirements

An AgentGuards account. Each extension version checked uses one request from your
plan's quota (re-checks of the same version within 30 days are free).
[Create a free account](https://agentguards.co/sign-up).

## Getting started

1. Install the extension. Then look for the AgentGuards shield in the activity bar on the
   left. If it isn't there, reload the window (Command Palette → **Developer: Reload
   Window**). You can also click **AgentGuards: Sign in** in the status bar at the bottom.
2. Click **Sign In** in the AgentGuards view, and approve the editor in your browser —
   or reuse the key the AgentGuards installer already saved, or paste an API key.
3. Your installed extensions are checked within a few minutes. New installs and
   updates are checked automatically.

## Settings

| Setting | Default | |
|---|---|---|
| `agentguards.store` | `auto` | Which store your extensions come from. `auto` uses the VS Code Marketplace in Visual Studio Code and Open VSX in Cursor, Windsurf and VSCodium. |
| `agentguards.notifyMedium` | `true` | Notify about medium-risk findings. Malicious and high-risk extensions always warn. |

## License

[FSL-1.1-MIT](LICENSE). © AlphaOps Ltd.
