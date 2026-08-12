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

This policy covers this plugin bundle (`claude-selfhosted/`), its hook scripts, and its
manifests. The hosted AgentGuards service and REST
API are covered separately at https://agentguards.co.

## Supported Versions

The latest published version of each plugin is supported. Fixes are shipped on
the `main` branch and released via the marketplace.

## Handling of Secrets

These plugins never store credentials. The AgentGuards API key is read from the
`AGENTGUARDS_API_KEY` environment variable at runtime and is never committed,
logged, or transmitted anywhere except to the configured AgentGuards endpoint
over HTTPS.
