package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// hookRuntimeWarning explains the one thing an install can't fix. The hooks of
// both agents are scripts: PowerShell on Windows (always present) and python3
// elsewhere. Without a working python3 they cannot run, so the user must hear
// about it rather than discover it.
func hookRuntimeWarning() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	if pythonWorks("python3") {
		return ""
	}
	return "python3 isn't installed (or is only a placeholder that asks you to install it), and the AgentGuards hooks for Claude Code and Codex need it. Until it is, neither is protected. Install Python 3, then restart your agent."
}

// pythonWorks runs the interpreter rather than trusting PATH: Windows ships
// python/python3 placeholders that only open the Microsoft Store, and a fresh Mac's
// python3 only offers to install the developer tools. Neither can run a hook.
var pythonWorks = func(name string) bool {
	path, err := lookPath(name)
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "--version").CombinedOutput()
	return err == nil && strings.HasPrefix(strings.TrimSpace(string(out)), "Python 3")
}

// doctorReport is what `agentguards doctor --json` prints: the same checks as the
// text output, plus each agent's state, for tools that show it (the VS Code
// extension). Never contains the key.
type doctorReport struct {
	Version    string `json:"version"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	KeyFound   bool   `json:"key_found"`
	KeyWorks   bool   `json:"key_works"`
	KeyChecked bool   `json:"key_checked"` // false with --offline
	// Codex sends the key in ~/.codex/agentguards_token instead of the saved one.
	CodexKeyOverride bool          `json:"codex_key_override"`
	KeySource        string        `json:"key_source,omitempty"`
	HookRuntime      bool          `json:"hook_runtime_ok"`
	Agents           []doctorAgent `json:"agents"`
	Checks           []doctorCheck `json:"checks"`
	Problems         int           `json:"problems"`
}

type doctorAgent struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// "enabled" (protected), "disabled", "not_installed", "error" (couldn't check),
	// or "not_found" (the agent's CLI isn't on PATH).
	State string `json:"state"`
	// Outdated: the plugin is installed but older than this installer requires
	// (`agentguards install` upgrades it).
	Outdated bool `json:"outdated,omitempty"`
	// The key this agent's hook sends, by where it comes from (never the key):
	// "claude_settings", "claude_plugin", "codex_token", "env" or "saved"
	// (~/.agentguards/credentials.json). KeyFound is false when there is none, or
	// when the file it would use doesn't hold an AgentGuards key.
	KeySource string `json:"key_source,omitempty"`
	KeyFound  bool   `json:"key_found"`
	// With --check-agent-keys: "works", "rejected" (revoked or unknown key),
	// "unknown" (AgentGuards couldn't be reached), or "other_server" (the agent's
	// hook uses another AgentGuards server, so its key isn't sent or checked).
	// Omitted when not checked.
	KeyStatus string `json:"key_status,omitempty"`
	Error     string `json:"error,omitempty"`
}

type doctorCheck struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

func cmdDoctor(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the result as JSON (for tools); exit status as usual")
	offline := fs.Bool("offline", false, "skip the test screening request (it uses a request from your plan)")
	agentKeys := fs.Bool("check-agent-keys", false, "check the key each agent sends with a read-only request (uses no quota)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var emit func(doctorCheck)
	if !*asJSON {
		// Text: each line as soon as it is checked, as before (some checks wait on the
		// network or an agent's CLI).
		fmt.Fprintf(out, "AgentGuards doctor (%s, %s/%s)\n\n", version, runtime.GOOS, runtime.GOARCH)
		emit = func(c doctorCheck) {
			mark := "✓"
			if !c.OK {
				mark = "✗"
			}
			fmt.Fprintf(out, "%s %s\n", mark, c.Message)
		}
	}
	r := runDoctor(!*offline, *agentKeys, emit)
	if *asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	if r.Problems > 0 {
		return fmt.Errorf("%d problem(s) found", r.Problems)
	}
	if !*asJSON {
		if *offline {
			fmt.Fprintln(out, "\nAll good, but the key was not tested (--offline). Run without --offline to test it.")
		} else {
			fmt.Fprintln(out, "\nAll good.")
		}
	}
	return nil
}

// runDoctor checks the setup. checkKeys=false skips the test screening requests
// (each uses a quota request). checkAgentKeys tests the key each agent sends with a
// read-only request that uses no quota, for tools that poll it.
func runDoctor(checkKeys, checkAgentKeys bool, emit func(doctorCheck)) *doctorReport {
	r := &doctorReport{Version: version, OS: runtime.GOOS, Arch: runtime.GOARCH, Agents: []doctorAgent{}}
	add := func(c doctorCheck) {
		r.Checks = append(r.Checks, c)
		if emit != nil {
			emit(c)
		}
	}
	ok := func(format string, a ...any) { add(doctorCheck{true, fmt.Sprintf(format, a...)}) }
	bad := func(format string, a ...any) {
		r.Problems++
		add(doctorCheck{false, fmt.Sprintf(format, a...)})
	}

	// The key: env var wins, exactly like the hooks.
	key := os.Getenv("AGENTGUARDS_API_KEY")
	source := "AGENTGUARDS_API_KEY"
	if key == "" {
		if c, err := loadCredentials(); err == nil {
			key, source = c.APIKey, "~/.agentguards/credentials.json"
		} else if errors.Is(err, os.ErrNotExist) {
			bad("no API key — run `agentguards install` (or `agentguards login`)")
		} else {
			bad("saved key is unreadable: %v — run `agentguards login`", err)
		}
	}
	if key != "" {
		r.KeyFound, r.KeySource = true, source
		// Presence and prefix only: never print the key itself.
		ok("API key found (%s, starts %s…)", source, key[:min(6, len(key))])
		if !checkKeys {
			// not tested: neither works nor fails
		} else if err := checkKey(key); err != nil {
			bad("%v", err)
		} else {
			r.KeyWorks = true
			ok("AgentGuards at %s accepted it and screened a test request", apiBase())
		}
		r.KeyChecked = checkKeys
	}

	// The Codex hook prefers its own token file over the saved key, so an old key
	// there is what Codex really sends — check that one too, or doctor would
	// report "All good" while Codex uses a revoked key.
	if tok := codexTokenFileKey(); tok != "" && !validKey(tok) {
		bad("~/.codex/agentguards_token doesn't hold an AgentGuards key, and Codex sends it instead of the saved one — delete the file or put a working key in it")
	} else if tok != "" && tok != key {
		r.CodexKeyOverride = true
		if !checkKeys {
			ok("Codex uses its own key from ~/.codex/agentguards_token (not tested: --offline)")
		} else if err := checkKey(tok); err != nil {
			bad("Codex uses ~/.codex/agentguards_token (it overrides the saved key), and that key failed: %v — delete the file or put a working key in it", err)
		} else {
			ok("Codex uses its own key from ~/.codex/agentguards_token, which works")
		}
	}

	if warn := hookRuntimeWarning(); warn != "" {
		bad("%s", warn)
	} else {
		r.HookRuntime = true
		ok("hook runtime available (%s)", hookRuntimeName())
	}

	agents := detectAgents()
	if len(agents) == 0 {
		bad("no supported coding agent found")
	}
	found := map[string]bool{}
	for _, a := range agents {
		found[a.ID] = true
	}
	for _, a := range allAgents() {
		if !found[a.ID] {
			r.Agents = append(r.Agents, doctorAgent{ID: a.ID, Name: a.Name, State: "not_found"})
		}
	}
	outdated := map[string]bool{}
	for _, a := range agents {
		if a.ID != "codex" {
			continue
		}
		if v := codexPluginVersion(); v != "" && versionLess(v, codexMinVersion) {
			outdated[a.ID] = true
			bad("Codex plugin %s is older than %s — run `agentguards install` to upgrade it", v, codexMinVersion)
		}
	}
	tested := map[string]string{} // key -> status: one request per distinct key
	for _, a := range agents {
		st, err := a.State()
		ag := doctorAgent{ID: a.ID, Name: a.Name, Outdated: outdated[a.ID]}
		var agentKey string
		ag.KeySource, agentKey, ag.KeyFound = agentKeyFor(a.ID)
		if checkAgentKeys && ag.KeyFound && agentURL(a.ID) != apiBase() {
			// Its hook talks to another server (e.g. a self-hosted instance): its key
			// means nothing here, and must not be sent here.
			ag.KeyStatus = "other_server"
		} else if checkAgentKeys && ag.KeyFound {
			status, seen := tested[agentKey]
			if !seen {
				status = keyStatus(agentKey)
				tested[agentKey] = status
			}
			ag.KeyStatus = status
			switch status {
			case "works":
				ok("%s: AgentGuards accepts the key it sends (%s)", a.Name, keySourceLabel(ag.KeySource))
			case "rejected":
				bad("%s: AgentGuards rejects the key it sends (%s), so nothing it does is screened — put a working key there", a.Name, keySourceLabel(ag.KeySource))
			}
		}
		switch {
		case err != nil:
			ag.State, ag.Error = "error", firstLine(err.Error())
			bad("%s: couldn't check (%v)", a.Name, firstLine(err.Error()))
		case st == installedEnabled:
			ag.State = "enabled"
			ok("%s: AgentGuards installed", a.Name)
		case st == installedDisabled:
			ag.State = "disabled"
			bad("%s: AgentGuards is installed but DISABLED — nothing is screened. Run `agentguards install` to re-enable it", a.Name)
		default:
			ag.State = "not_installed"
			bad("%s: AgentGuards not installed — run `agentguards install`", a.Name)
		}
		r.Agents = append(r.Agents, ag)
	}
	return r
}

// agentKeyFor is the key the agent's hook sends and where it comes from, in the
// order the hooks look (see existingAgentKeys): an agent-specific setting first,
// then the environment, then the saved key. found is false when there is none, or
// when the file it would use doesn't hold an AgentGuards key. The key is only ever
// sent to AgentGuards to check it, never printed.
func agentKeyFor(id string) (source, key string, found bool) {
	switch id {
	case "claude-code":
		settingsKey, pluginKey := claudeKeys()
		if settingsKey != "" {
			return "claude_settings", settingsKey, true
		}
		if pluginKey != "" {
			return "claude_plugin", pluginKey, true
		}
	case "codex":
		if tok := codexTokenFileKey(); tok != "" {
			if !validKey(tok) {
				return "codex_token", "", false
			}
			return "codex_token", tok, true
		}
	}
	if env := strings.TrimSpace(os.Getenv("AGENTGUARDS_API_KEY")); validKey(env) {
		return "env", env, true
	}
	if c, err := loadCredentials(); err == nil && c.APIKey != "" {
		return "saved", c.APIKey, true
	}
	return "", "", false
}

// agentURL is the server the agent's hook sends to: Claude Code's settings.json
// env block can set AGENTGUARDS_URL for its hook; otherwise the environment's, as
// apiBase().
func agentURL(id string) string {
	if id == "claude-code" {
		if u := claudeSettingsURL(); u != "" {
			return u
		}
	}
	return apiBase()
}

func keySourceLabel(source string) string {
	switch source {
	case "claude_settings":
		return "from Claude Code's settings.json"
	case "claude_plugin":
		return "from the Claude Code plugin's settings"
	case "codex_token":
		return "from ~/.codex/agentguards_token"
	case "env":
		return "from AGENTGUARDS_API_KEY"
	case "saved":
		return "the saved key"
	}
	return source
}

func firstLine(s string) string {
	for i, c := range s {
		if c == '\n' {
			return s[:i]
		}
	}
	return s
}

// codexTokenFileKey is the key in ~/.codex/agentguards_token (the manual Codex
// setup), which the Codex hook uses before the saved key. "" if none.
func codexTokenFileKey() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(home, ".codex", "agentguards_token"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func hookRuntimeName() string {
	if runtime.GOOS == "windows" {
		return "PowerShell"
	}
	return "python3"
}
