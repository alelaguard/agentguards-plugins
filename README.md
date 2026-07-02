# AgentGuards plugins

Official [AgentGuards](https://agentguards.co) plugin marketplace — LLM security
guardrails for AI coding agents: jailbreak and prompt-injection detection,
web-content scanning, data-exfiltration blocking, and destructive-command
authorization. Enforcement is configurable — **fail-closed by default**, or
fail-open (availability-first) with a single environment variable.

## Plugins

| Plugin | Agent | Description |
|---|---|---|
| [`agentguards-claude`](./claude) | Claude Code | MCP server + enforcing hooks (input, Bash, web-content) and security instructions. |
| [`agentguards-codex`](./codex) | OpenAI Codex | Enforcing hooks (input, shell, web-content) + MCP server and security instructions. |

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

## Install (OpenAI Codex)

```
codex plugin marketplace add alelaguard/agentguards-plugins
```

Enable the `agentguards-codex` plugin, then set your API key (get one at
https://agentguards.co/dashboard/keys):

```
export AGENTGUARDS_API_KEY=ag_your_token_here
```

Add that to your shell profile and restart Codex. See
[`codex/README.md`](./codex/README.md) for full configuration.

## License

MIT
