package main

import (
	"encoding/json"
	"os"
	"reflect"
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
