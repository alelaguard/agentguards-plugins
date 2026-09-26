// Command agentguards installs AgentGuards guardrails into the coding agents on
// this computer: it signs you in through the browser, installs the AgentGuards
// plugin into each agent it finds, and saves your key where the hooks read it.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// version is set at build time: -ldflags "-X main.version=1.2.3".
var version = "dev"

const usage = `AgentGuards installer

Usage:
  agentguards install     Sign in and protect every coding agent on this computer
  agentguards doctor      Check that AgentGuards is set up and working
  agentguards uninstall   Remove AgentGuards from your agents
  agentguards login       Sign in again and save a new key
  agentguards version     Print the version

Run "agentguards <command> -h" for a command's options.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "install":
		err = cmdInstall(os.Args[2:], os.Stdout, os.Stdin)
	case "doctor":
		err = cmdDoctor(os.Args[2:], os.Stdout)
	case "uninstall":
		err = cmdUninstall(os.Args[2:], os.Stdout, os.Stdin)
	case "login":
		err = cmdLogin(os.Args[2:], os.Stdout)
	case "version", "--version", "-v":
		fmt.Println("agentguards", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n✗ %v\n", err)
		os.Exit(1)
	}
}

func agentIDs(agents []*Agent) []string {
	ids := make([]string, len(agents))
	for i, a := range agents {
		ids[i] = a.ID
	}
	return ids
}

func selectAgents(only string) ([]*Agent, error) {
	found := detectAgents()
	if only == "" {
		return found, nil
	}
	want := map[string]bool{}
	for _, id := range strings.Split(only, ",") {
		want[strings.TrimSpace(id)] = true
	}
	var picked []*Agent
	for _, a := range allAgents() {
		if want[a.ID] {
			if _, err := lookPath(a.Binary); err != nil {
				return nil, fmt.Errorf("%s isn't installed (no %q on PATH)", a.Name, a.Binary)
			}
			picked = append(picked, a)
			delete(want, a.ID)
		}
	}
	for id := range want {
		return nil, fmt.Errorf("unknown agent %q (choose from: %s)", id, strings.Join(agentIDs(allAgents()), ", "))
	}
	return picked, nil
}

// confirm asks a yes/no question. Default yes. A non-interactive stdin with no
// --yes is an error rather than a silent "yes": installing changes the user's tools.
func confirm(in io.Reader, out io.Writer, question string) (bool, error) {
	if f, ok := in.(*os.File); ok {
		if st, err := f.Stat(); err == nil && st.Mode()&os.ModeCharDevice == 0 {
			return false, errors.New("no terminal to ask for confirmation — re-run with --yes")
		}
	}
	fmt.Fprintf(out, "%s [Y/n] ", question)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "" || a == "y" || a == "yes", nil
}

// inCloudSession reports a Claude Code cloud sandbox (e.g. Cowork): its home dir
// is thrown away when the session ends, so nothing installed there survives.
func inCloudSession() bool {
	return os.Getenv("CLAUDE_CODE_REMOTE") == "true"
}

// resolveKey picks the key to use: --key, then AGENTGUARDS_API_KEY, then a saved
// key that still works, then a working key from an earlier manual agent setup,
// then browser sign-in.
func resolveKey(out io.Writer, flagKey string, agents []string, openBrowser bool) (string, bool, error) {
	if k := strings.TrimSpace(flagKey); k != "" {
		if !validKey(k) {
			return "", false, errors.New("--key must be an AgentGuards key (starts with ag_)")
		}
		return k, true, nil
	}
	if k := strings.TrimSpace(os.Getenv("AGENTGUARDS_API_KEY")); validKey(k) {
		fmt.Fprintln(out, "Using the key from AGENTGUARDS_API_KEY.")
		return k, true, nil
	}
	if c, err := loadCredentials(); err == nil {
		switch err := checkKey(c.APIKey); {
		case err == nil:
			fmt.Fprintln(out, "Using your saved AgentGuards key.")
			return c.APIKey, false, nil
		case errors.Is(err, errKeyRejected):
			fmt.Fprintln(out, "Your saved key was revoked — let's get a new one.")
		default:
			// Can't tell whether the key works (offline, timeout, quota): keep it.
			// Signing in again here would only mint another key.
			return "", false, fmt.Errorf("couldn't check your saved key: %v — try again in a moment", err)
		}
	}
	// A key from an earlier manual setup: reuse it rather than mint one the hooks
	// would never send (see existingAgentKeys). isNew so it is saved for every agent.
	for _, e := range existingAgentKeys() {
		switch err := checkKey(e.Key); {
		case err == nil:
			fmt.Fprintf(out, "Using the AgentGuards key already set in %s.\n", e.Where)
			return e.Key, true, nil
		case errors.Is(err, errKeyRejected):
			fmt.Fprintf(out, "The key in %s was revoked — skipping it.\n", e.Where)
		default:
			return "", false, fmt.Errorf("couldn't check the key in %s: %v — try again in a moment", e.Where, err)
		}
	}
	k, err := deviceLogin(out, agents, openBrowser)
	return k, true, err
}

// adoptKey saves a key and then checks it. A key minted by sign-in already exists
// on the server, so it is saved FIRST: if the check then hits a blip (timeout,
// quota), throwing it away would orphan it. Only an outright rejection is fatal.
func adoptKey(out io.Writer, k string) error {
	if err := saveCredentials(Credentials{APIKey: k}); err != nil {
		return fmt.Errorf("saving your key: %w", err)
	}
	if err := checkKey(k); err != nil {
		if errors.Is(err, errKeyRejected) {
			return fmt.Errorf("that key doesn't work: %w", err)
		}
		fmt.Fprintf(out, "⚠ Key saved, but a test request failed: %v. Run `agentguards doctor` once you're back online.\n", err)
	}
	return nil
}

func cmdInstall(args []string, out io.Writer, in io.Reader) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask for confirmation")
	key := fs.String("key", "", "use this ag_ key instead of signing in (for CI)")
	only := fs.String("agents", "", "comma-separated agents to set up (default: all found): "+strings.Join(agentIDs(allAgents()), ","))
	noBrowser := fs.Bool("no-browser", false, "print the sign-in link instead of opening a browser")
	force := fs.Bool("force", false, "install even inside a Claude Code cloud session")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if inCloudSession() && !*force {
		return errors.New("this is a Claude Code cloud session — its home folder is discarded when the session ends, " +
			"so nothing installed here would last. Set AGENTGUARDS_API_KEY on the cloud environment instead " +
			"(see https://agentguards.co/docs), or pass --force")
	}

	agents, err := selectAgents(*only)
	if err != nil {
		return err
	}
	if len(agents) == 0 {
		return fmt.Errorf("no supported coding agent found on this computer.\n  The installer sets up Claude Code and Codex — install one, then run this again.\n  (Using Gemini CLI, Copilot CLI or OpenCode? Set those up by hand: https://agentguards.co/docs)")
	}

	fmt.Fprintf(out, "AgentGuards installer %s\n\nFound:\n", version)
	for _, a := range agents {
		fmt.Fprintf(out, "  • %s\n", a.Name)
	}
	fmt.Fprintln(out, "\nThis will sign you in to AgentGuards, install the AgentGuards plugin into each of these,")
	fmt.Fprintln(out, "and save your API key to ~/.agentguards/credentials.json (readable only by you).")
	if !*yes {
		ok, err := confirm(in, out, "\nContinue?")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("cancelled — nothing was changed")
		}
	}

	apiKey, isNew, err := resolveKey(out, *key, agentIDs(agents), !*noBrowser)
	if err != nil {
		return err
	}
	if isNew {
		if err := adoptKey(out, apiKey); err != nil {
			return err
		}
	}
	p, _ := credentialsPath()
	fmt.Fprintf(out, "\n✓ Signed in. Key saved to %s\n\n", p)
	if tok := codexTokenFileKey(); tok != "" && tok != apiKey {
		fmt.Fprintln(out, "⚠ ~/.codex/agentguards_token holds a different key, and Codex uses it before the saved one.")
		fmt.Fprintln(out, "  Delete that file to have Codex use the key you just saved.")
	}

	var failed []string
	var next []string
	for _, a := range agents {
		fmt.Fprintf(out, "Setting up %s... ", a.Name)
		if err := a.Install(); err != nil {
			fmt.Fprintf(out, "✗\n    %s\n", strings.ReplaceAll(err.Error(), "\n", "\n    "))
			failed = append(failed, a.Name)
			continue
		}
		fmt.Fprintln(out, "✓")
		if a.NextStep != "" {
			next = append(next, a.NextStep)
		}
	}

	if warn := hookRuntimeWarning(); warn != "" {
		fmt.Fprintf(out, "\n⚠ %s\n", warn)
	}
	if len(next) > 0 {
		fmt.Fprintln(out, "\nNext:")
		for _, n := range next {
			fmt.Fprintf(out, "  • %s\n", n)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("could not set up: %s. The rest are protected. Run `agentguards doctor` for details", strings.Join(failed, ", "))
	}
	fmt.Fprintln(out, "\n✓ Done. AgentGuards now screens your agents' prompts, commands and fetched web content.")
	fmt.Fprintln(out, "  Check anytime with: agentguards doctor")
	return nil
}

func cmdLogin(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	noBrowser := fs.Bool("no-browser", false, "print the sign-in link instead of opening a browser")
	if err := fs.Parse(args); err != nil {
		return err
	}
	k, err := deviceLogin(out, agentIDs(detectAgents()), !*noBrowser)
	if err != nil {
		return err
	}
	if err := adoptKey(out, k); err != nil {
		return err
	}
	p, _ := credentialsPath()
	fmt.Fprintf(out, "\n✓ Signed in. Key saved to %s\n", p)
	return nil
}

func cmdUninstall(args []string, out io.Writer, in io.Reader) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask for confirmation")
	keepKey := fs.Bool("keep-key", false, "leave ~/.agentguards/credentials.json in place")
	if err := fs.Parse(args); err != nil {
		return err
	}
	agents := detectAgents()
	if !*yes {
		ok, err := confirm(in, out, "Remove AgentGuards from "+strings.Join(agentIDs(agents), ", ")+"?")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("cancelled — nothing was changed")
		}
	}
	var failed []string
	for _, a := range agents {
		fmt.Fprintf(out, "Removing from %s... ", a.Name)
		if err := a.Uninstall(); err != nil {
			fmt.Fprintf(out, "✗\n    %s\n", strings.ReplaceAll(err.Error(), "\n", "\n    "))
			failed = append(failed, a.Name)
			continue
		}
		fmt.Fprintln(out, "✓")
	}
	if len(failed) > 0 {
		// A plugin still installed without its key blocks (Codex) or stops
		// screening (Claude) — keep the key until it's really gone.
		return fmt.Errorf("could not fully remove from: %s. Your saved key was kept so those plugins keep working; run uninstall again once they're removed", strings.Join(failed, ", "))
	}
	if !*keepKey {
		if err := removeCredentials(); err != nil {
			return err
		}
		fmt.Fprintln(out, "Removed the saved key (it still exists in your dashboard — revoke it there if you no longer need it).")
	}
	return nil
}
