package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Where every plugin ships from. One repo, one marketplace per agent.
const (
	pluginRepo    = "alelaguard/agentguards-plugins"
	pluginRepoGit = "https://github.com/" + pluginRepo + ".git"
)

// installState distinguishes a disabled plugin from an active one: a disabled
// AgentGuards plugin runs no hooks, so it must never read as "protected".
type installState int

const (
	notInstalled installState = iota
	installedDisabled
	installedEnabled
)

// Agent installs and removes AgentGuards for one coding agent, always through
// that agent's own CLI where one exists, so we never hand-edit its config.
type Agent struct {
	ID        string // shown to the user and sent in the approval label
	Name      string
	Binary    string
	State     func() (installState, error)
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
// Limits, since this is a test aid: it only applies when the marketplace isn't
// registered yet (use a clean home), and it does NOT make Codex install local
// code — the Codex marketplace pins its plugin to GitHub main (git-subdir).
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
	state := func() (installState, error) {
		out, err := run("claude", "plugin", "list", "--json")
		if err != nil {
			return notInstalled, err
		}
		var list []struct {
			ID      string `json:"id"`
			Enabled bool   `json:"enabled"`
		}
		if err := json.Unmarshal([]byte(out), &list); err != nil {
			return notInstalled, fmt.Errorf("could not read `claude plugin list --json`: %w", err)
		}
		for _, p := range list {
			if p.ID == plugin {
				if p.Enabled {
					return installedEnabled, nil
				}
				return installedDisabled, nil
			}
		}
		return notInstalled, nil
	}
	return &Agent{
		ID: "claude-code", Name: "Claude Code", Binary: "claude",
		State: state,
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
			st, err := state()
			if err != nil {
				return err
			}
			switch st {
			case notInstalled:
				_, err = run("claude", "plugin", "install", plugin, "--scope", "user")
				return err
			case installedDisabled:
				if _, err := run("claude", "plugin", "enable", plugin); err != nil {
					return err
				}
			}
			// Already installed: bring it to the version the refreshed marketplace has
			// — a re-run is how users pick up hook fixes.
			_, err = run("claude", "plugin", "update", plugin)
			return err
		},
		Uninstall: func() error {
			if st, err := state(); err != nil || st == notInstalled {
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

// codexMinVersion is the oldest Codex plugin the installer leaves in place. 0.2.18
// dropped the bundled MCP server (it read only AGENTGUARDS_API_KEY, so it failed for
// anyone set up by the installer); 0.2.17 was the first whose hooks run as
// PowerShell on Windows. Codex has no plugin update command, so older installs are
// replaced.
const codexMinVersion = "0.2.18"

var semverRe = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// codexPluginVersion reads the installed version from `codex plugin list`, "" if unknown.
func codexPluginVersion() string {
	out, err := run("codex", "plugin", "list")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "agentguards-codex@agentguards-codex" {
			continue
		}
		for _, x := range f[1:] {
			if semverRe.MatchString(x) {
				return x
			}
		}
	}
	return ""
}

// versionLess compares dotted numeric versions ("0.2.9" < "0.2.16").
func versionLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x < y
		}
	}
	return len(pa) < len(pb)
}

func codexAgent() *Agent {
	const plugin = "agentguards-codex@agentguards-codex"
	// `codex plugin list` prints e.g. "agentguards-codex@agentguards-codex  installed, enabled  0.2.15".
	state := func() (installState, error) {
		out, err := run("codex", "plugin", "list")
		if err != nil {
			return notInstalled, err
		}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) < 2 || f[0] != plugin || !strings.HasPrefix(f[1], "installed") {
				continue
			}
			if strings.Contains(line, "disabled") {
				return installedDisabled, nil
			}
			return installedEnabled, nil
		}
		return notInstalled, nil
	}
	return &Agent{
		ID: "codex", Name: "Codex", Binary: "codex",
		State: state,
		Install: func() error {
			out, err := run("codex", "plugin", "marketplace", "list")
			if err != nil {
				return err
			}
			var refreshErr error
			if !strings.Contains(out, "agentguards-codex") {
				src := pluginRepoGit
				if local, ok := pluginSource(); ok {
					src = local
				}
				if _, err := run("codex", "plugin", "marketplace", "add", src); err != nil {
					return err
				}
			} else if _, err := run("codex", "plugin", "marketplace", "upgrade", "agentguards-codex"); err != nil {
				// Only refreshes the catalog (and only git marketplaces can be). The
				// existing snapshot still installs, so a failure here isn't fatal.
				refreshErr = err
			}
			st, err := state()
			if err != nil {
				return err
			}
			switch st {
			case installedEnabled:
				// Codex has no plugin update command: an install older than
				// codexMinVersion is replaced (Codex may then ask to re-trust
				// the hooks once — that's its own safety check).
				if v := codexPluginVersion(); v != "" && versionLess(v, codexMinVersion) {
					if _, err := run("codex", "plugin", "remove", plugin); err != nil {
						return err
					}
					_, err := run("codex", "plugin", "add", plugin)
					return err
				}
				return nil
			case installedDisabled:
				// Codex has no CLI command to re-enable a plugin.
				return fmt.Errorf("AgentGuards is installed but disabled in Codex — enable it in Codex's plugin settings, or nothing is screened")
			}
			if _, err := run("codex", "plugin", "add", plugin); err != nil {
				if refreshErr != nil {
					return fmt.Errorf("%w (and refreshing the marketplace failed: %v)", err, refreshErr)
				}
				return err
			}
			return nil
		},
		Uninstall: func() error {
			if st, err := state(); err != nil || st == notInstalled {
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
