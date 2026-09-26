package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// existingKey is a key an earlier, manual setup left where an agent's hook reads
// it before ~/.agentguards/credentials.json.
type existingKey struct {
	Key   string
	Where string // shown to the user; never the key itself
}

// existingAgentKeys finds keys from setups that predate the installer. The hooks
// prefer these over the saved key, so signing in again while one exists mints a
// key the hooks never use — and on a plan at its key limit, the sign-in page
// offers to replace the old key, which revokes the one the hooks still send and
// blocks every prompt. Reusing the key that is already there avoids both.
//
// Sources, in the order the hooks read them: Claude Code's settings.json env
// block, the Claude plugin's saved "AgentGuards API key" setting, and Codex's
// ~/.codex/agentguards_token. On macOS Claude Code keeps plugin settings in the
// Keychain, which is not read here (it would prompt the user); on Linux and
// Windows they are in .credentials.json.
func existingAgentKeys() []existingKey {
	var found []existingKey
	seen := map[string]bool{}
	add := func(k, where string) {
		k = strings.TrimSpace(k)
		if validKey(k) && !seen[k] {
			seen[k] = true
			found = append(found, existingKey{k, where})
		}
	}
	if dir := claudeConfigDir(); dir != "" {
		var settings struct {
			Env map[string]string `json:"env"`
		}
		if readJSON(filepath.Join(dir, "settings.json"), &settings) {
			add(settings.Env["AGENTGUARDS_API_KEY"], "Claude Code's settings.json")
		}
		var creds struct {
			PluginSecrets map[string]map[string]string `json:"pluginSecrets"`
		}
		if readJSON(filepath.Join(dir, ".credentials.json"), &creds) {
			add(creds.PluginSecrets["agentguards-claude@agentguards"]["agentguards_api_key"],
				"the Claude Code plugin's settings")
		}
	}
	add(codexTokenFileKey(), "~/.codex/agentguards_token")
	return found
}

// claudeConfigDir is where Claude Code keeps its settings: CLAUDE_CONFIG_DIR, or ~/.claude.
func claudeConfigDir() string {
	if d := os.Getenv("CLAUDE_CONFIG_DIR"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".claude")
}

// readJSON decodes path into out, reporting whether it could. A missing or
// malformed file just means there is no key there.
func readJSON(path string, out any) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return json.Unmarshal(b, out) == nil
}
