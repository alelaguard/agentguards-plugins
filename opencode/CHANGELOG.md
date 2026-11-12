# Changelog

## 0.1.10

**Security fix: update recommended.**

- A command AgentGuards rates `require-approval`, `escalate` or `dry-run` is now always blocked. Before, if the session had already run an allowed command using the same program, it ran without being blocked. For example, a harmless `rm stale.log` let a later `rm -rf ~/work` through. `deny` was never affected. Thanks to [kta1kri](https://github.com/kta1kri) for reporting this.
- Installed from npm? OpenCode keeps the version it first downloaded. To get this release, run `rm -rf ~/.cache/opencode/packages/@agentguardsco` and then restart `opencode`.
