package main

import (
	"context"
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

func cmdDoctor(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	problems := 0
	ok := func(format string, a ...any) { fmt.Fprintf(out, "✓ "+format+"\n", a...) }
	bad := func(format string, a ...any) { problems++; fmt.Fprintf(out, "✗ "+format+"\n", a...) }

	fmt.Fprintf(out, "AgentGuards doctor (%s, %s/%s)\n\n", version, runtime.GOOS, runtime.GOARCH)

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
		// Presence and prefix only: never print the key itself.
		ok("API key found (%s, starts %s…)", source, key[:min(6, len(key))])
		if err := checkKey(key); err != nil {
			bad("%v", err)
		} else {
			ok("AgentGuards at %s accepted it and screened a test request", apiBase())
		}
	}

	// The Codex hook prefers its own token file over the saved key, so an old key
	// there is what Codex really sends — check that one too, or doctor would
	// report "All good" while Codex uses a revoked key.
	if tok := codexTokenFileKey(); tok != "" && tok != key {
		if err := checkKey(tok); err != nil {
			bad("Codex uses ~/.codex/agentguards_token (it overrides the saved key), and that key failed: %v — delete the file or put a working key in it", err)
		} else {
			ok("Codex uses its own key from ~/.codex/agentguards_token, which works")
		}
	}

	if warn := hookRuntimeWarning(); warn != "" {
		bad("%s", warn)
	} else {
		ok("hook runtime available (%s)", hookRuntimeName())
	}

	agents := detectAgents()
	if len(agents) == 0 {
		bad("no supported coding agent found")
	}
	for _, a := range agents {
		if a.ID != "codex" {
			continue
		}
		if v := codexPluginVersion(); v != "" && versionLess(v, codexMinVersion) {
			bad("Codex plugin %s is older than %s — run `agentguards install` to upgrade it", v, codexMinVersion)
		}
	}
	for _, a := range agents {
		st, err := a.State()
		switch {
		case err != nil:
			bad("%s: couldn't check (%v)", a.Name, firstLine(err.Error()))
		case st == installedEnabled:
			ok("%s: AgentGuards installed", a.Name)
		case st == installedDisabled:
			bad("%s: AgentGuards is installed but DISABLED — nothing is screened. Run `agentguards install` to re-enable it", a.Name)
		default:
			bad("%s: AgentGuards not installed — run `agentguards install`", a.Name)
		}
	}

	if problems > 0 {
		return fmt.Errorf("%d problem(s) found", problems)
	}
	fmt.Fprintln(out, "\nAll good.")
	return nil
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
