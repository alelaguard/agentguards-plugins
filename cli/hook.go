package main

// `agentguards hook <agent> <event>` — the guardrail hooks, running inside this
// binary instead of Python (or PowerShell on Windows). One implementation for
// every OS; the plugins call it when it's installed and fall back to their
// scripts when it isn't.
//
// PARITY: each agent's handler is a line-by-line port of that agent's Python hook
// (codex/scripts/agentguards_codex_hook.py, ...). tests/test_codex_go_parity.py
// feeds both the same events against the same mock API and requires the same
// decisions, requests and approval-cache contents. Change both together.

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// errExit ends a handler: the decision has been written, stop processing.
// Mirrors the Python hooks' sys.exit(0) after every verdict.
var errExit = errors.New("hook finished")

type hookIO struct {
	out, errOut io.Writer
}

// emit writes one JSON verdict to stdout and ends the handler.
func (h hookIO) emit(v any) error {
	enc := json.NewEncoder(h.out)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return errExit
}

func (h hookIO) warn(format string, a ...any) {
	fmt.Fprintf(h.errOut, format+"\n", a...)
}

// hookAgents are the agents `agentguards hook` can run. The plugin launchers ask
// `agentguards hook --supports <agent>` first and fall back to their own scripts
// when the installed binary is too old to know that agent (0.1.0 had no hooks).
var hookAgents = set("codex")

func cmdHook(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 2 && args[0] == "--supports" {
		if hookAgents[args[1]] {
			return 0
		}
		return 1
	}
	if len(args) < 2 {
		fmt.Fprintln(stderr, "usage: agentguards hook <agent> <event>   (agent: codex)")
		return 2
	}
	agent, event := args[0], args[1]
	// The whole event, however large: a truncated event fails to parse, and an
	// unparseable event continues unscreened — a size cap would be a bypass.
	raw, _ := io.ReadAll(stdin)
	h := hookIO{out: stdout, errOut: stderr}
	var err error
	switch agent {
	case "codex":
		err = runCodexHook(h, event, raw)
	default:
		fmt.Fprintf(stderr, "unknown hook agent %q\n", agent)
		return 2
	}
	if err != nil && !errors.Is(err, errExit) {
		fmt.Fprintf(stderr, "AgentGuards hook error: %v\n", err)
		return 1
	}
	return 0
}

// --- API ------------------------------------------------------------------------

type quotaError struct{ msg string }

func (e *quotaError) Error() string { return e.msg }

type forbiddenError struct{ detail string }

func (e *forbiddenError) Error() string { return e.detail }

// httpStatusError is any other non-2xx: an outage as far as the hook is concerned.
type httpStatusError struct {
	code   int
	status string
}

func (e *httpStatusError) Error() string { return fmt.Sprintf("HTTP Error %d: %s", e.code, e.status) }

func truthyEnv(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func failOpen() bool { return truthyEnv("AGENTGUARDS_FAIL_OPEN") }

func expandHome(p string) string {
	if strings.HasPrefix(p, "~") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}

// hookHTTPClient honours the same TLS options as the Python hooks: a pinned CA
// bundle for a self-hosted appliance, or (evaluation only) no verification.
func hookHTTPClient(timeout time.Duration) (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if bundle := strings.TrimSpace(os.Getenv("AGENTGUARDS_CA_BUNDLE")); bundle != "" {
		pem, err := os.ReadFile(expandHome(bundle))
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates in AGENTGUARDS_CA_BUNDLE %s", bundle)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool}
	} else if truthyEnv("AGENTGUARDS_TLS_NO_VERIFY") {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit opt-in, as in the Python hooks
	}
	return &http.Client{Timeout: timeout, Transport: tr}, nil
}

func hookBaseURL(fallback string) string {
	if u := strings.TrimRight(os.Getenv("AGENTGUARDS_URL"), "/"); u != "" {
		return u
	}
	return fallback
}

// hookPost mirrors the Python hooks' _post: JSON in, JSON out; 429 QUOTA_EXCEEDED
// and 403 are distinct errors, anything else non-2xx is an outage.
func hookPost(client, apiKey, path string, payload any, timeout time.Duration) (map[string]any, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, hookBaseURL("https://prod.agentguards.co")+path, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("X-AgentGuards-Client", client)
	hc, err := hookHTTPClient(timeout)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode == 429 {
		var m map[string]any
		if json.Unmarshal(body, &m) == nil && m["error"] == "QUOTA_EXCEEDED" {
			msg, _ := m["message"].(string)
			if msg == "" {
				msg = "Request quota reached."
			}
			return nil, &quotaError{msg}
		}
	}
	if resp.StatusCode == 403 {
		var m map[string]any
		detail := "Forbidden"
		if json.Unmarshal(body, &m) == nil {
			if d, ok := m["detail"].(string); ok && d != "" {
				detail = d
			}
		}
		return nil, &forbiddenError{detail}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &httpStatusError{resp.StatusCode, http.StatusText(resp.StatusCode)}
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("invalid response from AgentGuards: %w", err)
	}
	return out, nil
}

// unreachableRemedy mirrors _unreachable_remedy: certificate advice for TLS
// failures, credential advice for a 401, the fail-open escape hatch otherwise.
func unreachableRemedy(err error) string {
	if bundle := strings.TrimSpace(os.Getenv("AGENTGUARDS_CA_BUNDLE")); bundle != "" {
		if _, statErr := os.Stat(expandHome(bundle)); statErr != nil {
			return fmt.Sprintf("AGENTGUARDS_CA_BUNDLE points at %s, which does not exist. Save the "+
				"appliance's certificate there first:\n"+
				"      openssl s_client -connect <host>:443 -showcerts </dev/null 2>/dev/null "+
				"| openssl x509 > %s\n"+
				"Or unset AGENTGUARDS_CA_BUNDLE to go back to the public CA roots.", bundle, bundle)
		}
	}
	// Same test as the Python hooks' _is_tls_trust_error: a verification failure,
	// not any error that happens to mention certificates.
	var authErr x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var invalidErr x509.CertificateInvalidError
	var verifyErr *tls.CertificateVerificationError
	if errors.As(err, &authErr) || errors.As(err, &hostErr) || errors.As(err, &invalidErr) ||
		errors.As(err, &verifyErr) {
		return "The server's certificate is not trusted. A self-hosted appliance signs " +
			"its own certificate on first boot, so this is expected until you install " +
			"a real one.\n" +
			"  • Best: install your own certificate at Settings -> TLS certificate, and " +
			"reach the appliance by the hostname it is issued for.\n" +
			"  • Or pin the appliance's certificate:\n" +
			"      openssl s_client -connect <host>:443 -showcerts </dev/null 2>/dev/null " +
			"| openssl x509 > ~/.agentguards-appliance.pem\n" +
			"      export AGENTGUARDS_CA_BUNDLE=~/.agentguards-appliance.pem\n" +
			"  • Evaluating on a private network: export AGENTGUARDS_TLS_NO_VERIFY=true"
	}
	var hs *httpStatusError
	if errors.As(err, &hs) && hs.code == 401 {
		return "The API key was rejected. Check AGENTGUARDS_API_KEY matches a key on this " +
			"instance (Admin console -> API keys), and that AGENTGUARDS_URL points at " +
			"the right one. Do not use AGENTGUARDS_FAIL_OPEN for this — the service is " +
			"healthy and turning off screening would not fix the credential."
	}
	return "Set AGENTGUARDS_FAIL_OPEN=true to allow requests while the service is down."
}

// installerKey is ~/.agentguards/credentials.json's key — the same rule as the
// Python hooks' _installer_key: any value starting "ag_" (no length check, so the
// two runtimes agree on what "configured" means).
func installerKey() string {
	p, err := credentialsPath()
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	var c map[string]any
	if json.Unmarshal(b, &c) != nil {
		return ""
	}
	key := strings.TrimSpace(fmt.Sprint(c["api_key"]))
	if c["api_key"] == nil || !strings.HasPrefix(key, "ag_") {
		return ""
	}
	return key
}

// --- command parsing (mirrors _segments / _resolve_binaries) ----------------------

// Commands that run ANOTHER command; values are the options that consume the
// following token, so `sudo -u root curl` doesn't mistake "root" for the command.
var hookWrappers = map[string]map[string]bool{
	"sudo":     set("-u", "-g", "-p", "-C", "-U", "-r", "-t", "-h"),
	"doas":     set("-u", "-C"),
	"env":      set("-u", "-C", "-S"),
	"timeout":  set("-s", "-k", "--signal", "--kill-after"),
	"nohup":    set(),
	"nice":     set("-n", "--adjustment"),
	"ionice":   set("-c", "-n", "-p", "-t"),
	"stdbuf":   set("-i", "-o", "-e"),
	"command":  set(),
	"xargs":    set("-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s", "--max-args"),
	"time":     set("-o", "-f", "--output", "--format"),
	"setsid":   set(),
	"unbuffer": set(),
	"watch":    set("-n", "--interval"),
	"script":   set("-c"),
}

var hookShells = set("sh", "bash", "zsh", "dash", "ksh", "ash", "busybox")

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, i := range items {
		m[i] = true
	}
	return m
}

var (
	substitutionRe = regexp.MustCompile("\\$\\(([^()]*)\\)|`([^`]*)`")
	segmentSplitRe = regexp.MustCompile(`\|\||&&|[|;&\n]`)
	assignmentRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
	durationRe     = regexp.MustCompile(`^\d+(\.\d+)?[smhd]?$`)
)

func commandSegments(command string) []string {
	var parts []string
	remainder := substitutionRe.ReplaceAllStringFunc(command, func(m string) string {
		sub := substitutionRe.FindStringSubmatch(m)
		inner := sub[1]
		if inner == "" {
			inner = sub[2]
		}
		parts = append(parts, inner)
		return " "
	})
	return append(parts, segmentSplitRe.Split(remainder, -1)...)
}

func resolveBinaries(segment string, depth int) []string {
	tokens := strings.Fields(segment)
	var found []string
	idx := 0
	for idx < len(tokens) {
		token := tokens[idx]
		if assignmentRe.MatchString(token) { // leading VAR=val
			idx++
			continue
		}
		name := token[strings.LastIndex(token, "/")+1:]
		found = append(found, name)

		if hookShells[name] && depth < 3 {
			// Recurse into the string after -c, which the shell will execute.
			for j := idx + 1; j < len(tokens)-1; j++ {
				if tokens[j] == "-c" || (strings.HasPrefix(tokens[j], "-") && strings.Contains(tokens[j][1:], "c")) {
					nested := strings.Trim(strings.Join(tokens[j+1:], " "), "\"'")
					found = append(found, resolveBinaries(nested, depth+1)...)
					break
				}
			}
			break
		}

		takesValue, isWrapper := hookWrappers[name]
		if !isWrapper || depth >= 3 {
			break
		}
		// Step over the wrapper's own options to reach the command it runs.
		idx++
		for idx < len(tokens) {
			arg := tokens[idx]
			if arg == "--" {
				idx++
				break
			}
			if strings.HasPrefix(arg, "-") {
				idx++
				if takesValue[arg] && idx < len(tokens) {
					idx++
				}
				continue
			}
			if durationRe.MatchString(arg) { // timeout 5, nice 10
				idx++
				continue
			}
			break
		}
	}
	return found
}

func commandBinaries(command string) []string {
	var out []string
	for _, seg := range commandSegments(command) {
		out = append(out, resolveBinaries(seg, 0)...)
	}
	return out
}

var fetchBinaries = set("curl", "wget", "http", "https", "fetch", "aria2c")

func isFetchCommand(command string) bool {
	for _, b := range commandBinaries(command) {
		if fetchBinaries[b] {
			return true
		}
	}
	return false
}

// --- per-session approval cache (same file and format as the Python hooks) ---------

const (
	approvalsVersion = 2
	sessionTTL       = 7 * 24 * 3600
)

type approvalEntry struct {
	V        float64             `json:"v"`
	Binaries []string            `json:"binaries"`
	Pending  map[string][]string `json:"pending"`
	TS       float64             `json:"ts"`
}

type approvalStore struct{ path string }

func (s approvalStore) load() map[string]approvalEntry {
	out := map[string]approvalEntry{}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return out
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(b, &raw) != nil {
		return out
	}
	for sid, r := range raw {
		var e approvalEntry
		// Only current-format entries: v1 recorded commands nobody was asked about.
		if json.Unmarshal(r, &e) == nil && e.V == approvalsVersion {
			out[sid] = e
		}
	}
	return out
}

func (s approvalStore) write(data map[string]approvalEntry) {
	now := float64(time.Now().UnixNano()) / 1e9
	for sid, e := range data {
		if now-e.TS >= sessionTTL {
			delete(data, sid)
		}
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return
	}
	b, err := json.Marshal(data)
	if err != nil {
		return
	}
	// 0600: this file decides whether a command is re-prompted, so anything able to
	// write it could pre-approve binaries for the session.
	f, err := os.OpenFile(s.path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return
	}
	_, _ = f.Write(b)
	_ = f.Close()
}

func (s approvalStore) approvedBinaries(sessionID string) map[string]bool {
	if sessionID == "" {
		return map[string]bool{}
	}
	return set(s.load()[sessionID].Binaries...)
}

// commandKey: a pending approval can only be redeemed by the exact command it was
// granted for. The command text itself is never stored.
func commandKey(command string) string {
	sum := sha256.Sum256([]byte(command))
	return hex.EncodeToString(sum[:])[:16]
}

func sortedUnique(items []string) []string {
	m := set(items...)
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// markPending records that a human IS BEING ASKED about this exact command.
func (s approvalStore) markPending(sessionID, command string) {
	if sessionID == "" || command == "" {
		return
	}
	data := s.load()
	entry := data[sessionID]
	pending := map[string][]string{}
	for k, v := range entry.Pending {
		pending[k] = v
	}
	pending[commandKey(command)] = sortedUnique(commandBinaries(command))
	data[sessionID] = approvalEntry{
		V: approvalsVersion, Binaries: sortedUnique(entry.Binaries), Pending: pending,
		TS: float64(time.Now().UnixNano()) / 1e9,
	}
	s.write(data)
}

// redeemPending: the command ran; if a human was asked about it, it was approved.
func (s approvalStore) redeemPending(sessionID, command string) {
	if sessionID == "" || command == "" {
		return
	}
	data := s.load()
	entry, ok := data[sessionID]
	if !ok {
		return
	}
	pending := map[string][]string{}
	for k, v := range entry.Pending {
		pending[k] = v
	}
	key := commandKey(command)
	bins, had := pending[key]
	if !had {
		return
	}
	delete(pending, key)
	data[sessionID] = approvalEntry{
		V: approvalsVersion, Binaries: sortedUnique(append(append([]string{}, entry.Binaries...), bins...)),
		Pending: pending, TS: float64(time.Now().UnixNano()) / 1e9,
	}
	s.write(data)
}

// --- small helpers for loosely typed hook events ------------------------------------

func str(v any) string {
	s, _ := v.(string)
	return s
}

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}

// commandText accepts a shell command as a string or an argv list (joined), so a
// list-shaped command is still screened rather than crashing the hook.
func commandText(v any) string {
	switch c := v.(type) {
	case string:
		return c
	case []any:
		parts := make([]string, 0, len(c))
		for _, p := range c {
			parts = append(parts, fmt.Sprint(p))
		}
		return strings.Join(parts, " ")
	}
	return ""
}
