# Changelog

## 0.1.11

- A link that a `bash` command only mentions in a commit or pull-request message, the usual `git commit -m "$(cat <<'EOF' … EOF)"` or `gh pr create --body "$(cat <<'EOF' …)"`, no longer counts as a link being fetched. Before, a message that said `curl https://…` was blocked whenever that site looked like a lookalike. AgentGuards now records the link and lets the command run, unless your account is set to block such links. Links a command really fetches are checked as before. So are links in files the command writes, since a later command could run or read those files.

## 0.1.10

**Security fix: update recommended.**

- A command AgentGuards rates `require-approval`, `escalate` or `dry-run` is now always blocked. Before, if the session had already run an allowed command using the same program, it ran without being blocked. For example, a harmless `rm stale.log` let a later `rm -rf ~/work` through. `deny` was never affected. Thanks to [kta1kri](https://github.com/kta1kri) for reporting this.
- Installed from npm? OpenCode keeps the version it first downloaded. To get this release, run `rm -rf ~/.cache/opencode/packages/@agentguardsco` and then restart `opencode`.
