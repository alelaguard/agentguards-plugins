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
	if !strings.Contains(strings.Join(f.calls, "\n"), "claude plugin marketplace update agentguards") {
		t.Fatal("re-running should refresh the marketplace so the plugin updates")
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
	if ok, _ := codexAgent().Installed(); !ok {
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
			return "agentguards-codex@agentguards-codex  installed, enabled  0.2.15\n", nil
		}
		t.Fatalf("unexpected command %q", cmd)
		return "", nil
	}
	defer func() { run = old }()
	if err := codexAgent().Install(); err != nil {
		t.Fatalf("already installed: a failed refresh must not fail setup, got %v", err)
	}
}
