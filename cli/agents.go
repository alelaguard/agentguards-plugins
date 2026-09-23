package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Where every plugin ships from. One repo, one marketplace per agent.
const (
	pluginRepo    = "alelaguard/agentguards-plugins"
	pluginRepoGit = "https://github.com/" + pluginRepo + ".git"
)

// Agent installs and removes AgentGuards for one coding agent, always through
// that agent's own CLI where one exists, so we never hand-edit its config.
type Agent struct {
	ID        string // shown to the user and sent in the approval label
	Name      string
	Binary    string
	Installed func() (bool, error)
	Install   func() error
	Uninstall func() error
	// NextStep is printed after a successful install, if the agent needs one.
	NextStep string
}

// run executes an agent CLI and returns its combined output. Swapped in tests.
var run = func(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Stdin = nil
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, lastLines(string(out), 6))
	}
	return string(out), nil
}

var lookPath = exec.LookPath

// pluginSource is where agents install AgentGuards from: the GitHub repo, or —
// for testing an unreleased change — a local checkout of it, named by
// AGENTGUARDS_PLUGIN_SOURCE. Only the source changes; every command is the same.
func pluginSource() (local string, ok bool) {
	p := os.Getenv("AGENTGUARDS_PLUGIN_SOURCE")
	return p, p != ""
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// The agents the installer sets up. Gemini CLI, Copilot CLI and OpenCode
// plugins exist too, but are installed by hand (see their pages on
// agentguards.co) — the installer deliberately covers Claude Code and Codex only.
func allAgents() []*Agent {
	return []*Agent{claudeAgent(), codexAgent()}
}

// detectAgents returns the agents whose CLI is on PATH.
func detectAgents() []*Agent {
	var found []*Agent
	for _, a := range allAgents() {
		if _, err := lookPath(a.Binary); err == nil {
			found = append(found, a)
		}
	}
	return found
}

// --- Claude Code --------------------------------------------------------------

func claudeAgent() *Agent {
	const plugin = "agentguards-claude@agentguards"
	installed := func() (bool, error) {
		out, err := run("claude", "plugin", "list", "--json")
		if err != nil {
			return false, err
		}
		var list []struct {
			ID      string `json:"id"`
			Enabled bool   `json:"enabled"`
		}
		if err := json.Unmarshal([]byte(out), &list); err != nil {
			return false, fmt.Errorf("could not read `claude plugin list --json`: %w", err)
		}
		for _, p := range list {
			if p.ID == plugin {
				return true, nil
			}
		}
		return false, nil
	}
	return &Agent{
		ID: "claude-code", Name: "Claude Code", Binary: "claude",
		Installed: installed,
		Install: func() error {
			if ok, err := hasClaudeMarketplace(); err != nil {
				return err
			} else if !ok {
				src := pluginRepo
				if local, ok := pluginSource(); ok {
					src = local
				}
				if _, err := run("claude", "plugin", "marketplace", "add", src); err != nil {
					return err
				}
			} else if _, err := run("claude", "plugin", "marketplace", "update", "agentguards"); err != nil {
				return err
			}
			if ok, err := installed(); err != nil || ok {
				return err // already installed: marketplace update above refreshes it
			}
			_, err := run("claude", "plugin", "install", plugin, "--scope", "user")
			return err
		},
		Uninstall: func() error {
			if ok, err := installed(); err != nil || !ok {
				return err
			}
			_, err := run("claude", "plugin", "uninstall", plugin)
			return err
		},
		NextStep: "Restart any open Claude Code sessions.",
	}
}

func hasClaudeMarketplace() (bool, error) {
	out, err := run("claude", "plugin", "marketplace", "list", "--json")
	if err != nil {
		return false, err
	}
	var list []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return false, fmt.Errorf("could not read `claude plugin marketplace list --json`: %w", err)
	}
	for _, m := range list {
		if m.Name == "agentguards" {
			return true, nil
		}
	}
	return false, nil
}

// --- Codex --------------------------------------------------------------------

func codexAgent() *Agent {
	const plugin = "agentguards-codex@agentguards-codex"
	installed := func() (bool, error) {
		out, err := run("codex", "plugin", "list")
		if err != nil {
			return false, err
		}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == plugin && strings.HasPrefix(f[1], "installed") {
				return true, nil
			}
		}
		return false, nil
	}
	return &Agent{
		ID: "codex", Name: "Codex", Binary: "codex",
		Installed: installed,
		Install: func() error {
			out, err := run("codex", "plugin", "marketplace", "list")
			if err != nil {
				return err
			}
			if !strings.Contains(out, "agentguards-codex") {
				src := pluginRepoGit
				if local, ok := pluginSource(); ok {
					src = local
				}
				if _, err := run("codex", "plugin", "marketplace", "add", src); err != nil {
					return err
				}
			} else if _, err := run("codex", "plugin", "marketplace", "upgrade", "agentguards-codex"); err != nil {
				// Only refreshes an existing marketplace (and only git ones can be).
				// Failing it must not fail a setup that is otherwise complete.
				if ok, ierr := installed(); ierr == nil && ok {
					return nil
				}
				return err
			}
			if ok, err := installed(); err != nil || ok {
				return err
			}
			_, err = run("codex", "plugin", "add", plugin)
			return err
		},
		Uninstall: func() error {
			if ok, err := installed(); err != nil || !ok {
				return err
			}
			_, err := run("codex", "plugin", "remove", plugin)
			return err
		},
		// Codex asks once before running newly installed hooks. That is the user's
		// decision to make, so the installer never bypasses it.
		NextStep: "Restart Codex. On first launch it asks you to trust the AgentGuards hooks — accept it, or nothing is screened.",
	}
}
