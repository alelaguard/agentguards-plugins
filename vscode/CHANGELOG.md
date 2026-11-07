# Changelog

## 0.1.1

- Extensions that are installed but not running yet (waiting for a restart, or disabled) are now checked too, before their code runs. They show as "not running" in the list. Before, they were checked only once they started.
- Windows: a check no longer fails with "EPERM: operation not permitted, rename" when another window or an antivirus scan has the results file open; saving retries for a moment.
- README: if the AgentGuards shield doesn't appear after installing, reload the window or use the status-bar Sign in.

## 0.1.0

- First release: checks installed, new and updated extensions for malware, known-malware packages, vulnerable bundled dependencies and imitation names, on the AgentGuards service.
- Sign in with your browser, the AgentGuards installer key, or an API key.
- Coding Agents view: shows whether the Claude Code and Codex CLIs are protected, and connects them by running the AgentGuards installer.
