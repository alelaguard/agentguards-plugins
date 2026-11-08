# Security Policy

AgentGuards builds security tooling, and we take the security of these plugins
seriously.

## Reporting a Vulnerability

If you discover a security vulnerability in this plugin, please report it
privately:

- **Email:** support@agentguards.co
- Please include a description, reproduction steps, and impact assessment.
- Do **not** open a public issue for security-sensitive reports.

We aim to acknowledge reports within 3 business days and to provide a resolution
timeline after triage.

## Scope

This policy covers this plugin bundle (`claude-directory/`): its manifest,
MCP configuration and skill. The hosted AgentGuards service, REST API and MCP
server are covered separately at https://agentguards.co.

## Supported Versions

The latest published version of each plugin is supported. Fixes are shipped on
the `main` branch and released via the marketplace.

## Handling of Secrets

This plugin stores and reads no credentials itself, and asks you to paste none.
You connect your AgentGuards account through the MCP server's sign-in (OAuth).

The access token that sign-in produces is an AgentGuards API key for your
account, listed under Keys in your dashboard. It does not expire on its own and
works for your account's whole API, not only these scans. Claude Code stores it
and sends it only to the AgentGuards MCP server over HTTPS. Clearing the sign-in
in Claude Code (`/mcp` → Clear authentication) deletes Claude Code's copy but
does not revoke the key: revoke it in the dashboard, especially if you think it
was exposed.
