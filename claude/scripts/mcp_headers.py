#!/usr/bin/env python3
"""Emits the AgentGuards MCP server's auth header as JSON on stdout.

Resolves the API key from the plugin's userConfig prompt first (populated as
CLAUDE_PLUGIN_OPTION_AGENTGUARDS_API_KEY — the only way to configure this in
surfaces with no shell, like Claude Desktop's Chat tab), falling back to the
AGENTGUARDS_API_KEY environment variable for existing CLI setups that export
it in their shell profile. Existing CLI users are unaffected either way.
"""

import json
import os

api_key = os.getenv("CLAUDE_PLUGIN_OPTION_AGENTGUARDS_API_KEY") or os.getenv("AGENTGUARDS_API_KEY", "")
print(json.dumps({"X-API-Key": api_key}))
