# AgentGuards plugins

Official [AgentGuards](https://agentguards.co) plugin marketplace — LLM security
guardrails for AI coding agents: jailbreak and prompt-injection detection,
web-content scanning, data-exfiltration blocking, and destructive-command
authorization.

## Plugins

| Plugin | Agent | Description |
|---|---|---|
| [`agentguards-claude`](./claude) | Claude Code | MCP server + enforcing hooks (input, Bash, web-content) and security instructions. |

_Codex support is planned and will land here as a sibling plugin._

## Install (Claude Code)

```
/plugin marketplace add alelaguard/agentguards-plugins
/plugin install agentguards-claude@agentguards
```

Then set your API key (get one at https://agentguards.co/dashboard/keys):

```
export AGENTGUARDS_API_KEY=ag_your_token_here
```

Add that to your shell profile and restart Claude Code, or run
`/agentguards:setup`. See [`claude/README.md`](./claude/README.md) for full
configuration.

## License

MIT
