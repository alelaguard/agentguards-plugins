# AgentGuards plugins

Official [AgentGuards](https://agentguards.co) plugin marketplace — LLM security
guardrails for AI coding agents: jailbreak and prompt-injection detection,
web-content scanning, data-exfiltration blocking, and destructive-command
authorization. Enforcement is configurable — **fail-closed by default**, or
fail-open (availability-first) with a single environment variable.

## Plugins

| Plugin | Agent | Deployment | Version | Description |
|---|---|---|---|---|
| [`agentguards-claude`](./claude) | Claude Code | hosted | `0.2.29` | MCP server + enforcing hooks (input, Bash, web-content) and security instructions. |
| [`agentguards-codex`](./codex) | OpenAI Codex | hosted | `0.2.13` | Enforcing hooks (input, shell, web-content) + MCP server and security instructions. |
| [`agentguards-gemini`](./gemini) | Gemini CLI | hosted | `0.1.8` | MCP server + enforcing hooks (input, tool-call, web-content) and security instructions. |
| [`agentguards-copilot`](./copilot) | GitHub Copilot CLI | hosted | `0.1.6` | MCP server + enforcing hooks (input, shell, web-content) and security instructions. |
| [`@agentguardsco/opencode-plugin`](./opencode) | OpenCode | hosted | `0.1.6` | Enforcing plugin (prompt, `bash`, web-content), + MCP server and security instructions. |
| [`agentguards-claude-selfhosted`](./claude-selfhosted) | Claude Code | self-hosted | `0.1.11` | Hooks only — no bundled MCP server, and no default URL, so it can never talk to the hosted service by accident. |
| [`agentguards-codex-selfhosted`](./codex-selfhosted) | OpenAI Codex | self-hosted | `0.1.6` | Hooks only — no bundled MCP server, and no default URL. |
| [`agentguards-gemini-selfhosted`](./gemini-selfhosted) | Gemini CLI | self-hosted | `0.1.5` | Hooks only — no bundled MCP server, and no default URL. |
| [`agentguards-copilot-selfhosted`](./copilot-selfhosted) | GitHub Copilot CLI | self-hosted | `0.1.4` | Hooks only — no bundled MCP server, and no default URL. |

Versions above are the current release in this repo; `.github/workflows/plugin-integrity.yml` fails the build if they drift from the plugin manifests. To see what you actually have installed, use your agent's own listing (`/plugin` in Claude Code).
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
[`@agentguardsco/claude-plugin`](https://www.npmjs.com/package/@agentguardsco/claude-plugin)
for programmatic use — pinning an exact version in `package.json`, CI
provisioning, or embedding the hook script in your own tooling — outside of
Claude Code's interactive `/plugin` flow:

```
npm install @agentguardsco/claude-plugin
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

## Install (OpenCode)

```
opencode plugin @agentguardsco/opencode-plugin
```

Then set your API key (get one at https://agentguards.co/dashboard/keys):

```
export AGENTGUARDS_API_KEY=ag_your_token_here
```

Add that to your shell profile and restart OpenCode. See
[`opencode/README.md`](./opencode/README.md) for full configuration, including
MCP server setup (a separate step for OpenCode, unlike the other agents above).

## License

MIT
