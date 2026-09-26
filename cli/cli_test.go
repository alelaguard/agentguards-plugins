package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// Built at runtime, not written as a literal: a key-shaped string in source is
// exactly what the secret scanner is meant to catch (the Python tests do the same).
var goodKey = "ag_" + strings.Repeat("0123456789abcdef", 2)

func withHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("AGENTGUARDS_API_KEY", "")
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	return home
}

// --- credentials ---------------------------------------------------------------

func TestCredentialsRoundTripAndPermissions(t *testing.T) {
	withHome(t)
	if err := saveCredentials(Credentials{APIKey: goodKey}); err != nil {
		t.Fatal(err)
	}
	c, err := loadCredentials()
	if err != nil || c.APIKey != goodKey {
		t.Fatalf("load = %+v, %v", c, err)
	}
	if runtime.GOOS != "windows" {
		p, _ := credentialsPath()
		st, _ := os.Stat(p)
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("credentials mode = %v, want 0600", st.Mode().Perm())
		}
		dir, _ := configDir()
		dst, _ := os.Stat(dir)
		if dst.Mode().Perm() != 0o700 {
			t.Fatalf("config dir mode = %v, want 0700", dst.Mode().Perm())
		}
	}
	// The file shape is what the hooks parse.
	p, _ := credentialsPath()
	var raw map[string]string
	b, _ := os.ReadFile(p)
	if err := json.Unmarshal(b, &raw); err != nil || raw["api_key"] != goodKey {
		t.Fatalf("hooks read {\"api_key\": ...}; got %s", b)
	}
}

func TestLoadRejectsNonAgentGuardsKey(t *testing.T) {
	home := withHome(t)
	os.MkdirAll(filepath.Join(home, ".agentguards"), 0o700)
	os.WriteFile(filepath.Join(home, ".agentguards", "credentials.json"), []byte(`{"api_key":"sk-nope"}`), 0o600)
	if _, err := loadCredentials(); err == nil {
		t.Fatal("expected an error for a non-ag_ key")
	}
}

// --- device login ----------------------------------------------------------------

type fakeAPI struct {
	mu        sync.Mutex
	polls     int
	responses []string // body of each successive /v1/device/token response
	label     string
	client    string
}

func (f *fakeAPI) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.client = r.Header.Get("X-AgentGuards-Client")
		switch r.URL.Path {
		case "/v1/device/code":
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			f.label = body["client_label"]
			io.WriteString(w, `{"device_code":"dev-secret","user_code":"BCDF-GHJK","verification_uri":"https://x/device","verification_uri_complete":"https://x/device?code=BCDF-GHJK","expires_in":600,"interval":5}`)
		case "/v1/device/token":
			resp := f.responses[min(f.polls, len(f.responses)-1)]
			f.polls++
			if strings.Contains(resp, "api_key") {
				io.WriteString(w, resp)
				return
			}
			w.WriteHeader(400)
			io.WriteString(w, resp)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
}

func runLogin(t *testing.T, responses ...string) (string, error, *fakeAPI) {
	t.Helper()
	f := &fakeAPI{responses: responses}
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	t.Setenv("AGENTGUARDS_URL", srv.URL)
	var slept []time.Duration
	old := sleep
	sleep = func(d time.Duration) { slept = append(slept, d) }
	t.Cleanup(func() { sleep = old })
	var out bytes.Buffer
	key, err := deviceLogin(&out, []string{"claude-code", "codex"}, false)
	if !strings.Contains(out.String(), "https://x/device?code=BCDF-GHJK") || !strings.Contains(out.String(), "BCDF-GHJK") {
		t.Errorf("login output must show the link and the code:\n%s", out.String())
	}
	return key, err, f
}

func TestLoginPollsUntilApproved(t *testing.T) {
	key, err, f := runLogin(t,
		`{"error":"authorization_pending"}`,
		`{"error":"authorization_pending"}`,
		`{"api_key":"`+goodKey+`","token_id":"01234567","key_name":"installer"}`,
	)
	if err != nil || key != goodKey {
		t.Fatalf("got %q, %v", key, err)
	}
	if f.polls != 3 {
		t.Fatalf("polls = %d, want 3", f.polls)
	}
	if !strings.HasPrefix(f.client, "installer/") {
		t.Fatalf("X-AgentGuards-Client = %q", f.client)
	}
	if !strings.HasPrefix(f.label, "claude-code, codex") {
		t.Fatalf("client_label = %q", f.label)
	}
}

func TestLoginErrorsAreActionable(t *testing.T) {
	for errCode, want := range map[string]string{
		"access_denied":     "denied",
		"expired_token":     "expired",
		"key_limit_reached": "key limit",
		"invalid_grant":     "sign-in failed",
	} {
		t.Run(errCode, func(t *testing.T) {
			_, err, _ := runLogin(t, `{"error":"`+errCode+`"}`)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("err = %v, want it to mention %q", err, want)
			}
		})
	}
}

func TestLoginBacksOffOnSlowDown(t *testing.T) {
	f := &fakeAPI{responses: []string{`{"error":"slow_down"}`, `{"api_key":"` + goodKey + `"}`}}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	t.Setenv("AGENTGUARDS_URL", srv.URL)
	var slept []time.Duration
	old := sleep
	sleep = func(d time.Duration) { slept = append(slept, d) }
	defer func() { sleep = old }()
	if _, err := deviceLogin(io.Discard, nil, false); err != nil {
		t.Fatal(err)
	}
	if len(slept) != 2 || slept[1] <= slept[0] {
		t.Fatalf("expected a longer wait after slow_down, got %v", slept)
	}
}

func TestClientLabelIsSanitised(t *testing.T) {
	l := clientLabel([]string{`<script>"x"</script>`})
	if strings.ContainsAny(l, `<>"`) {
		t.Fatalf("label not sanitised: %q", l)
	}
}

// --- per-agent commands ----------------------------------------------------------

type fakeRunner struct {
	calls   []string
	replies map[string]string // "claude plugin list --json" → stdout
}

func (f *fakeRunner) install(t *testing.T) {
	t.Helper()
	old := run
	run = func(name string, args ...string) (string, error) {
		cmd := name + " " + strings.Join(args, " ")
		f.calls = append(f.calls, cmd)
		return f.replies[cmd], nil
	}
	t.Cleanup(func() { run = old })
}

func TestClaudeFreshInstall(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"claude plugin marketplace list --json": `[]`,
		"claude plugin list --json":             `[]`,
	}}
	f.install(t)
	if err := claudeAgent().Install(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"claude plugin marketplace list --json",
		"claude plugin marketplace add alelaguard/agentguards-plugins",
		"claude plugin list --json",
		"claude plugin install agentguards-claude@agentguards --scope user",
	}
	if strings.Join(f.calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s\nwant:\n%s", strings.Join(f.calls, "\n"), strings.Join(want, "\n"))
	}
}

func TestClaudeReinstallIsIdempotent(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"claude plugin marketplace list --json": `[{"name":"agentguards"}]`,
		"claude plugin list --json":             `[{"id":"agentguards-claude@agentguards","enabled":true}]`,
	}}
	f.install(t)
	if err := claudeAgent().Install(); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		if strings.Contains(c, " install ") || strings.Contains(c, "marketplace add") {
			t.Fatalf("re-running must not reinstall; ran %q", c)
		}
	}
	joined := strings.Join(f.calls, "\n")
	if !strings.Contains(joined, "claude plugin marketplace update agentguards") ||
		!strings.Contains(joined, "claude plugin update agentguards-claude@agentguards") {
		t.Fatalf("re-running must refresh the marketplace AND update the plugin (how users get hook fixes):\n%s", joined)
	}
}

func TestCodexInstallAndDetection(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"codex plugin marketplace list": "MARKETPLACE ROOT\nopenai-curated /x\n",
		"codex plugin list":             "PLUGIN STATUS\nagentguards-codex@agentguards-codex  not installed\n",
	}}
	f.install(t)
	if err := codexAgent().Install(); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(f.calls, "\n")
	for _, want := range []string{
		"codex plugin marketplace add https://github.com/alelaguard/agentguards-plugins.git",
		"codex plugin add agentguards-codex@agentguards-codex",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in:\n%s", want, joined)
		}
	}
	// "not installed" must not read as installed.
	f.replies["codex plugin list"] = "agentguards-codex@agentguards-codex  installed, enabled  0.2.15\n"
	if st, _ := codexAgent().State(); st != installedEnabled {
		t.Fatal("installed, enabled should be detected")
	}
}

// --- confirmation ---------------------------------------------------------------

func TestConfirmRefusesWithoutATerminal(t *testing.T) {
	r, w, _ := os.Pipe()
	w.WriteString("y\n")
	w.Close()
	if _, err := confirm(r, io.Discard, "ok?"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("a piped stdin must not count as consent; err = %v", err)
	}
}

func TestConfirmDefaultsToYes(t *testing.T) {
	ok, err := confirm(strings.NewReader("\n"), io.Discard, "ok?")
	if err != nil || !ok {
		t.Fatalf("got %v, %v", ok, err)
	}
	ok, _ = confirm(strings.NewReader("n\n"), io.Discard, "ok?")
	if ok {
		t.Fatal("n must decline")
	}
}

func TestInstallRefusesInACloudSession(t *testing.T) {
	withHome(t)
	t.Setenv("CLAUDE_CODE_REMOTE", "true")
	err := cmdInstall([]string{"--yes"}, io.Discard, strings.NewReader(""))
	if err == nil || !strings.Contains(err.Error(), "cloud session") {
		t.Fatalf("err = %v", err)
	}
}

func TestCodexRefreshFailureDoesNotFailAnExistingInstall(t *testing.T) {
	old := run
	run = func(name string, args ...string) (string, error) {
		cmd := name + " " + strings.Join(args, " ")
		switch cmd {
		case "codex plugin marketplace list":
			return "agentguards-codex /x\n", nil
		case "codex plugin marketplace upgrade agentguards-codex":
			return "", io.ErrUnexpectedEOF // e.g. not a git marketplace
		case "codex plugin list":
			return "agentguards-codex@agentguards-codex  installed, enabled  0.2.18\n", nil
		}
		t.Fatalf("unexpected command %q", cmd)
		return "", nil
	}
	defer func() { run = old }()
	if err := codexAgent().Install(); err != nil {
		t.Fatalf("already installed: a failed refresh must not fail setup, got %v", err)
	}
}

// --- review fixes -----------------------------------------------------------------

func TestDisabledClaudePluginIsReEnabled(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"claude plugin marketplace list --json": `[{"name":"agentguards"}]`,
		"claude plugin list --json":             `[{"id":"agentguards-claude@agentguards","enabled":false}]`,
	}}
	f.install(t)
	if st, _ := claudeAgent().State(); st != installedDisabled {
		t.Fatalf("a disabled plugin must not read as protected; state = %v", st)
	}
	if err := claudeAgent().Install(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(f.calls, "\n"), "claude plugin enable agentguards-claude@agentguards") {
		t.Fatalf("install must re-enable a disabled plugin; calls:\n%s", strings.Join(f.calls, "\n"))
	}
}

func TestDisabledCodexPluginIsReportedNotSilentlyAccepted(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"codex plugin marketplace list": "agentguards-codex /x\n",
		"codex plugin list":             "agentguards-codex@agentguards-codex  installed, disabled  0.2.15\n",
	}}
	f.install(t)
	err := codexAgent().Install()
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("err = %v", err)
	}
}

func TestCodexRefreshFailureStillInstallsWhenMissing(t *testing.T) {
	var calls []string
	old := run
	run = func(name string, args ...string) (string, error) {
		cmd := name + " " + strings.Join(args, " ")
		calls = append(calls, cmd)
		switch cmd {
		case "codex plugin marketplace list":
			return "agentguards-codex /x\n", nil
		case "codex plugin marketplace upgrade agentguards-codex":
			return "", io.ErrUnexpectedEOF
		case "codex plugin list":
			return "agentguards-codex@agentguards-codex  not installed\n", nil
		}
		return "", nil
	}
	defer func() { run = old }()
	if err := codexAgent().Install(); err != nil {
		t.Fatal(err)
	}
	if calls[len(calls)-1] != "codex plugin add agentguards-codex@agentguards-codex" {
		t.Fatalf("a failed refresh must not stop the install; calls: %v", calls)
	}
}

// keyAPI answers evaluate-input with a fixed status and counts device-flow calls.
func keyAPI(t *testing.T, status int) *int {
	t.Helper()
	deviceCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/guardrails/evaluate-input":
			w.WriteHeader(status)
			io.WriteString(w, `{"decision":"allow"}`)
		default:
			deviceCalls++
			w.WriteHeader(500)
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("AGENTGUARDS_URL", srv.URL)
	return &deviceCalls
}

func TestSavedKeyIsKeptOnATransientFailure(t *testing.T) {
	for _, status := range []int{429, 500, 503} {
		withHome(t)
		saveCredentials(Credentials{APIKey: goodKey})
		deviceCalls := keyAPI(t, status)
		_, _, err := resolveKey(io.Discard, "", nil, false)
		if err == nil {
			t.Fatalf("HTTP %d: expected an error, not a new sign-in", status)
		}
		if *deviceCalls != 0 {
			t.Fatalf("HTTP %d: must not start a new sign-in (it would mint another key)", status)
		}
		if c, _ := loadCredentials(); c.APIKey != goodKey {
			t.Fatalf("HTTP %d: saved key must be kept", status)
		}
	}
}

func TestRevokedSavedKeyTriggersSignIn(t *testing.T) {
	withHome(t)
	saveCredentials(Credentials{APIKey: goodKey})
	deviceCalls := keyAPI(t, 401)
	resolveKey(io.Discard, "", nil, false)
	if *deviceCalls == 0 {
		t.Fatal("a revoked key should lead to a new sign-in")
	}
}

func TestNewKeyIsSavedEvenIfItsCheckHitsABlip(t *testing.T) {
	withHome(t)
	keyAPI(t, 503)
	if err := adoptKey(io.Discard, goodKey); err != nil {
		t.Fatalf("a transient check failure must not discard a minted key: %v", err)
	}
	if c, err := loadCredentials(); err != nil || c.APIKey != goodKey {
		t.Fatal("the minted key must be saved")
	}
}

func TestUninstallKeepsTheKeyIfARemovalFailed(t *testing.T) {
	home := withHome(t)
	saveCredentials(Credentials{APIKey: goodKey})
	// Put fake claude/codex on PATH so both are "detected".
	bin := filepath.Join(home, "bin")
	os.MkdirAll(bin, 0o755)
	oldLook := lookPath
	lookPath = func(string) (string, error) { return bin, nil }
	defer func() { lookPath = oldLook }()
	old := run
	run = func(name string, args ...string) (string, error) {
		cmd := name + " " + strings.Join(args, " ")
		switch cmd {
		case "claude plugin list --json":
			return `[{"id":"agentguards-claude@agentguards","enabled":true}]`, nil
		case "codex plugin list":
			return "agentguards-codex@agentguards-codex  installed, enabled\n", nil
		case "codex plugin remove agentguards-codex@agentguards-codex":
			return "", io.ErrUnexpectedEOF
		}
		return "", nil
	}
	defer func() { run = old }()
	if err := cmdUninstall([]string{"--yes"}, io.Discard, strings.NewReader("")); err == nil {
		t.Fatal("a failed removal must be reported")
	}
	if _, err := loadCredentials(); err != nil {
		t.Fatal("the key must be kept while a plugin that needs it is still installed")
	}
}

func TestDoctorChecksTheCodexTokenFileKey(t *testing.T) {
	home := withHome(t)
	saveCredentials(Credentials{APIKey: goodKey})
	os.MkdirAll(filepath.Join(home, ".codex"), 0o755)
	stale := "ag_" + strings.Repeat("f", 32)
	os.WriteFile(filepath.Join(home, ".codex", "agentguards_token"), []byte(stale+"\n"), 0o600)
	if codexTokenFileKey() != stale {
		t.Fatal("must read the Codex token file")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") == stale {
			w.WriteHeader(401)
			return
		}
		io.WriteString(w, `{"decision":"allow"}`)
	}))
	defer srv.Close()
	t.Setenv("AGENTGUARDS_URL", srv.URL)
	oldLook := lookPath
	lookPath = func(string) (string, error) { return "", os.ErrNotExist }
	defer func() { lookPath = oldLook }()
	var out bytes.Buffer
	cmdDoctor(nil, &out)
	if !strings.Contains(out.String(), "agentguards_token") || !strings.Contains(out.String(), "✗ Codex uses") {
		t.Fatalf("doctor must flag the stale key Codex actually uses:\n%s", out.String())
	}
}

func TestPythonPlaceholderIsNotPython(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell script as the fake interpreter")
	}
	dir := t.TempDir()
	// Like the Windows Store alias / macOS stub: on PATH, but can't run anything.
	stub := filepath.Join(dir, "python3")
	os.WriteFile(stub, []byte("#!/bin/sh\necho 'Python was not found; run without arguments to install from the Microsoft Store'\nexit 9009\n"), 0o755)
	oldLook := lookPath
	lookPath = func(name string) (string, error) { return stub, nil }
	defer func() { lookPath = oldLook }()
	if pythonWorks("python3") {
		t.Fatal("a placeholder must not count as Python")
	}
	if hookRuntimeWarning() == "" {
		t.Fatal("doctor/install must warn when only a placeholder exists")
	}
	os.WriteFile(stub, []byte("#!/bin/sh\necho 'Python 3.12.3'\n"), 0o755)
	if !pythonWorks("python3") {
		t.Fatal("a real python3 must count")
	}
}

func TestVersionLess(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{{"0.2.9", "0.2.16", true}, {"0.2.15", "0.2.16", true}, {"0.2.16", "0.2.16", false}, {"0.3.0", "0.2.16", false}, {"1.0.0", "0.9.9", false}} {
		if got := versionLess(c.a, c.b); got != c.want {
			t.Errorf("versionLess(%s, %s) = %v", c.a, c.b, got)
		}
	}
}

func TestOldCodexPluginIsUpgradedOnReinstall(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"codex plugin marketplace list": "agentguards-codex /x\n",
		"codex plugin list":             "agentguards-codex@agentguards-codex  installed, enabled  0.2.15  https://github.com/...\n",
	}}
	f.install(t)
	if err := codexAgent().Install(); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(f.calls, "\n")
	if !strings.Contains(joined, "codex plugin remove agentguards-codex@agentguards-codex") ||
		!strings.Contains(joined, "codex plugin add agentguards-codex@agentguards-codex") {
		t.Fatalf("a pre-0.2.18 Codex plugin must be replaced:\n%s", joined)
	}
}

func TestCurrentCodexPluginIsLeftAlone(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"codex plugin marketplace list": "agentguards-codex /x\n",
		"codex plugin list":             "agentguards-codex@agentguards-codex  installed, enabled  0.2.18\n",
	}}
	f.install(t)
	codexAgent().Install()
	for _, c := range f.calls {
		if strings.Contains(c, "plugin remove") || strings.Contains(c, "plugin add") {
			t.Fatalf("up-to-date plugin must not be reinstalled (it would re-prompt for hook trust): %q", c)
		}
	}
}

// --- keys from earlier manual setups -------------------------------------------

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Each place an earlier manual setup leaves a key the hooks read before the saved one.
var existingKeySetups = map[string]func(t *testing.T, home string){
	"claude plugin setting": func(t *testing.T, home string) {
		writeFile(t, filepath.Join(home, ".claude", ".credentials.json"),
			`{"pluginSecrets":{"agentguards-claude@agentguards":{"agentguards_api_key":"`+goodKey+`"}}}`)
	},
	"claude settings env": func(t *testing.T, home string) {
		writeFile(t, filepath.Join(home, ".claude", "settings.json"),
			`{"env":{"AGENTGUARDS_API_KEY":"`+goodKey+`"}}`)
	},
	"codex token file": func(t *testing.T, home string) {
		writeFile(t, filepath.Join(home, ".codex", "agentguards_token"), goodKey+"\n")
	},
}

func TestExistingAgentKeyIsReusedNotReMinted(t *testing.T) {
	for name, setup := range existingKeySetups {
		home := withHome(t)
		setup(t, home)
		deviceCalls := keyAPI(t, 200)
		k, isNew, err := resolveKey(io.Discard, "", nil, false)
		if err != nil || k != goodKey {
			t.Fatalf("%s: expected the existing key, got %q, %v", name, k, err)
		}
		if !isNew {
			t.Fatalf("%s: the reused key must be saved so every agent's hook gets it", name)
		}
		if *deviceCalls != 0 {
			t.Fatalf("%s: must not sign in again (it would mint a key the hooks never send)", name)
		}
	}
}

func TestClaudeConfigDirIsHonoured(t *testing.T) {
	withHome(t)
	dir := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", dir)
	writeFile(t, filepath.Join(dir, "settings.json"), `{"env":{"AGENTGUARDS_API_KEY":"`+goodKey+`"}}`)
	if got := existingAgentKeys(); len(got) != 1 || got[0].Key != goodKey {
		t.Fatalf("expected the key from CLAUDE_CONFIG_DIR, got %v", got)
	}
}

func TestRevokedExistingKeyTriggersSignIn(t *testing.T) {
	home := withHome(t)
	existingKeySetups["claude plugin setting"](t, home)
	deviceCalls := keyAPI(t, 401)
	resolveKey(io.Discard, "", nil, false)
	if *deviceCalls == 0 {
		t.Fatal("a revoked existing key should lead to a new sign-in")
	}
}

func TestExistingKeyTransientFailureDoesNotSignIn(t *testing.T) {
	home := withHome(t)
	existingKeySetups["claude plugin setting"](t, home)
	deviceCalls := keyAPI(t, 503)
	if _, _, err := resolveKey(io.Discard, "", nil, false); err == nil {
		t.Fatal("expected an error, not a new sign-in")
	}
	if *deviceCalls != 0 {
		t.Fatal("a transient failure must not start a sign-in (it would mint another key)")
	}
}

func TestExistingKeyOutputNeverShowsTheKey(t *testing.T) {
	home := withHome(t)
	existingKeySetups["claude plugin setting"](t, home)
	keyAPI(t, 200)
	var out bytes.Buffer
	resolveKey(&out, "", nil, false)
	if strings.Contains(out.String(), goodKey) || !strings.Contains(out.String(), "plugin's settings") {
		t.Fatalf("output should name where the key came from, never the key: %q", out.String())
	}
}

func TestMalformedAgentConfigIsIgnored(t *testing.T) {
	home := withHome(t)
	writeFile(t, filepath.Join(home, ".claude", ".credentials.json"), `{"pluginSecrets": "nope"`)
	writeFile(t, filepath.Join(home, ".claude", "settings.json"), `{"env":{"AGENTGUARDS_API_KEY":"not-a-key"}}`)
	if got := existingAgentKeys(); len(got) != 0 {
		t.Fatalf("expected no keys, got %d", len(got))
	}
}
