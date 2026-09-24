package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

// TestCommandParsingParity compares commandBinaries with the Python hook's
// _command_binaries on cases the parity test writes out (see
// tests/test_codex_go_parity.py). Skipped when run on its own.
func TestCommandParsingParity(t *testing.T) {
	path := os.Getenv("AGENTGUARDS_PARSE_CASES")
	if path == "" {
		t.Skip("run via tests/test_codex_go_parity.py")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string][]string
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	for cmd, exp := range want {
		got := commandBinaries(cmd)
		if len(got) == 0 && len(exp) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, exp) {
			t.Errorf("%q:\n  python: %q\n  go:     %q", cmd, exp, got)
		}
	}
}

// A fetched page larger than any read cap must still be screened: a truncated
// event fails to parse, and an unparseable event continues unscreened.
func TestHugeEventIsStillScreened(t *testing.T) {
	var got int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = len(b)
		io.WriteString(w, `{"decision":"block","message":"blocked"}`)
	}))
	defer srv.Close()
	t.Setenv("AGENTGUARDS_URL", srv.URL)
	t.Setenv("AGENTGUARDS_API_KEY", "ag_"+strings.Repeat("7", 32))
	page := strings.Repeat("x", 40<<20)
	ev, _ := json.Marshal(map[string]any{"tool_name": "shell", "tool_input": map[string]any{"command": "curl https://x"}, "tool_response": page})
	var out, errOut bytes.Buffer
	if code := cmdHook([]string{"codex", "PostToolUse"}, bytes.NewReader(ev), &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), `"decision":"block"`) || got < 40<<20 {
		t.Fatalf("40 MB page must reach the scanner and be blocked; sent %d bytes, out %q", got, out.String())
	}
}
