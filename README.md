# AgentGuards plugins

Official [AgentGuards](https://agentguards.co) plugin marketplace — LLM security
guardrails for AI coding agents: jailbreak and prompt-injection detection,
web-content scanning, data-exfiltration blocking, and destructive-command
authorization. Enforcement is configurable — **fail-closed by default**, or
fail-open (availability-first) with a single environment variable.

## Plugins

| Plugin | Agent | Deployment | Version | Description |
|---|---|---|---|---|
| [`agentguards-claude`](./claude) | Claude Code | hosted | `0.2.37` | Enforcing hooks (input, Bash, web-content with pre-fetch URL check, code scan). No MCP server. |
| [`agentguards-codex`](./codex) | OpenAI Codex | hosted | `0.2.24` | Enforcing hooks (input, shell, web-content with pre-fetch URL check, code scan). No MCP server. |
| [`agentguards-gemini`](./gemini) | Gemini CLI | hosted | `0.1.10` | MCP server + enforcing hooks (input, tool-call, web-content with pre-fetch URL check) and security instructions. |
| [`agentguards-copilot`](./copilot) | GitHub Copilot CLI | hosted | `0.1.9` | MCP server + enforcing hooks (input, shell, web-content with pre-fetch URL check) and security instructions. |
| [`@agentguardsco/opencode-plugin`](./opencode) | OpenCode | hosted | `0.1.9` | Enforcing plugin (prompt, `bash`, web-content with pre-fetch URL check), + MCP server and security instructions. |
| [`agentguards-claude-selfhosted`](./claude-selfhosted) | Claude Code | self-hosted | `0.1.11` | Hooks only — no bundled MCP server, and no default URL, so it can never talk to the hosted service by accident. |
| [`agentguards-codex-selfhosted`](./codex-selfhosted) | OpenAI Codex | self-hosted | `0.1.6` | Hooks only — no bundled MCP server, and no default URL. |
| [`agentguards-gemini-selfhosted`](./gemini-selfhosted) | Gemini CLI | self-hosted | `0.1.5` | Hooks only — no bundled MCP server, and no default URL. |
| [`agentguards-copilot-selfhosted`](./copilot-selfhosted) | GitHub Copilot CLI | self-hosted | `0.1.4` | Hooks only — no bundled MCP server, and no default URL. |

Versions above are the current release in this repo; our release checks fail if they drift from the plugin manifests. To see what you actually have installed, use your agent's own listing (`/plugin` in Claude Code).
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

## About this repository

This repository holds the released plugins and is what every install method reads from. It is
published from our private development repository on each release, so it doesn't carry our
tests or development history. Issues and security reports are welcome
([`SECURITY.md`](./SECURITY.md)); we can't accept pull requests here.

## License

The hosted plugins (`claude/`, `codex/`, `gemini/`, `copilot/`, `opencode/`) are source-available
under the [Functional Source License 1.1, MIT Future License](https://fsl.software): free to read,
use and modify for anything except a competing product, and each version becomes MIT two years
after release. The self-hosted plugins and everything else here are MIT. Earlier releases stay MIT.
See [`LICENSING.md`](./LICENSING.md) for the details and [`TRADEMARKS.md`](./TRADEMARKS.md) for the
name and logo.
