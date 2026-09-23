package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
)

// hookRuntimeWarning explains the one thing an install can't fix: until the hooks
// run inside this binary, they need Python (or PowerShell for Claude on Windows).
// Without it the Claude hook lets everything through and the Codex hook blocks —
// so the user must hear about it, not discover it.
func hookRuntimeWarning() string {
	if runtime.GOOS == "windows" {
		if _, err := lookPath("python3"); err == nil {
			return ""
		}
		if _, err := lookPath("python"); err == nil {
			return ""
		}
		return "Python isn't installed. Claude Code is covered (it uses PowerShell), but the Codex hook needs Python: https://www.python.org/downloads/"
	}
	if _, err := lookPath("python3"); err == nil {
		return ""
	}
	return "python3 isn't installed, and the AgentGuards hooks need it to run. Until it is, Claude Code is NOT protected and Codex blocks every prompt. Install Python 3, then restart your agents."
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

	if warn := hookRuntimeWarning(); warn != "" {
		bad("%s", warn)
	} else {
		ok("hook runtime available")
	}

	agents := detectAgents()
	if len(agents) == 0 {
		bad("no supported coding agent found")
	}
	for _, a := range agents {
		installed, err := a.Installed()
		switch {
		case err != nil:
			bad("%s: couldn't check (%v)", a.Name, firstLine(err.Error()))
		case installed:
			ok("%s: AgentGuards installed", a.Name)
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
