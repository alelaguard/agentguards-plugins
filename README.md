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
| [`agentguards-gemini`](./gemini) | Gemini CLI | MCP server + enforcing hooks (input, tool-call, web-content) and security instructions. |
| [`agentguards-copilot`](./copilot) | GitHub Copilot CLI | MCP server + enforcing hooks (input, shell, web-content) and security instructions. |

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

**Alternative: install via npm.** The `claude/` plugin is also published as
[`@agentguards/claude-plugin`](https://www.npmjs.com/package/@agentguards/claude-plugin)
for programmatic use — pinning an exact version in `package.json`, CI
provisioning, or embedding the hook script in your own tooling — outside of
Claude Code's interactive `/plugin` flow:

```
npm install @agentguards/claude-plugin
```

Note this only fetches the plugin's files; it does **not** register hooks,
skills, or the MCP server with Claude Code (that wiring happens through
`/plugin install` above). Use the npm package when you need the raw files,
use `/plugin install` when you want it running in Claude Code.

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

## Install (Gemini CLI)

Gemini CLI's `extensions install` only supports single-extension repos, so
install by cloning and linking the subdirectory:

```
git clone https://github.com/alelaguard/agentguards-plugins.git
gemini extensions link agentguards-plugins/gemini
```

Then set your API key (get one at https://agentguards.co/dashboard/keys):

```
export AGENTGUARDS_API_KEY=ag_your_token_here
```

Add that to your shell profile and restart Gemini CLI. See
[`gemini/README.md`](./gemini/README.md) for full configuration.

## Install (GitHub Copilot CLI)

```
copilot plugin install alelaguard/agentguards-plugins:copilot
```

Then set your API key (get one at https://agentguards.co/dashboard/keys):

```
export AGENTGUARDS_API_KEY=ag_your_token_here
```

Add that to your shell profile and restart Copilot CLI. See
[`copilot/README.md`](./copilot/README.md) for full configuration.

## License

MIT
