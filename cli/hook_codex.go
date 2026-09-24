package main

// Codex hook — a port of codex/scripts/agentguards_codex_hook.py. Keep the two in
// step; tests/test_codex_go_parity.py fails when they diverge. Comments explaining
// WHY each branch exists live in the Python file; they are not repeated here.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const codexClient = "codex/go"

func codexAPIKey() string {
	if k := strings.TrimSpace(os.Getenv("AGENTGUARDS_API_KEY")); k != "" {
		return k
	}
	if home, err := os.UserHomeDir(); err == nil {
		if b, err := os.ReadFile(filepath.Join(home, ".codex", "agentguards_token")); err == nil {
			if t := strings.TrimSpace(string(b)); t != "" {
				return t
			}
		}
	}
	return installerKey()
}

func codexApprovals() approvalStore {
	home, _ := os.UserHomeDir()
	return approvalStore{path: filepath.Join(home, ".codex", "agentguards_session_approvals.json")}
}

func codexPost(path string, payload any, timeout time.Duration) (map[string]any, error) {
	return hookPost(codexClient, codexAPIKey(), path, payload, timeout)
}

// --- verdicts ---------------------------------------------------------------------

func (h hookIO) codexContinue() error { return errExit }

func (h hookIO) codexBlockPrompt(reason string) error {
	return h.emit(map[string]any{"decision": "block", "reason": reason})
}

func (h hookIO) codexBlockOutput(reason string) error {
	return h.emit(map[string]any{
		"decision": "block",
		"reason":   reason,
		"hookSpecificOutput": map[string]any{
			"hookEventName":     "PostToolUse",
			"additionalContext": "AgentGuards withheld fetched web content: " + reason,
		},
	})
}

func (h hookIO) codexRedactOutput(redacted string, piiTypes []string) error {
	what := ""
	if len(piiTypes) > 0 {
		what = " (" + strings.Join(piiTypes, ", ") + ")"
	}
	return h.emit(map[string]any{
		"decision": "block",
		"reason": redacted + "\n\n[AgentGuards redacted sensitive values" + what + " from this " +
			"content. The rest of the result is intact and safe to use.]",
		"hookSpecificOutput": map[string]any{
			"hookEventName": "PostToolUse",
			"additionalContext": "AgentGuards redacted sensitive values" + what + " from the fetched " +
				"content. The remaining content is intact — use it normally.",
		},
	})
}

func (h hookIO) codexAsk(reason string) error {
	h.warn("%s", reason)
	return errExit
}

func (h hookIO) codexDeny(reason string) error {
	return h.emit(map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName":            "PreToolUse",
		"permissionDecision":       "deny",
		"permissionDecisionReason": reason,
	}})
}

func (h hookIO) codexPermissionAllow() error {
	return h.emit(map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName": "PermissionRequest",
		"decision":      map[string]any{"behavior": "allow"},
	}})
}

func (h hookIO) codexPermissionDeny(message string) error {
	return h.emit(map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName": "PermissionRequest",
		"decision":      map[string]any{"behavior": "deny", "message": message},
	}})
}

// --- web / code scanning ----------------------------------------------------------------

var piiChecks = set("presidio", "pii_detection", "secret_detection")

func failingChecks(result map[string]any) []map[string]any {
	var out []map[string]any
	checks, _ := result["checks"].([]any)
	for _, c := range checks {
		m := obj(c)
		// Python: `not c.get("passed", True)` — absent counts as passing; false, null,
		// 0 and "" all count as FAILING. A null must not hide a non-PII failure.
		if v, present := m["passed"]; present && !pyTruthy(v) {
			out = append(out, m)
		}
	}
	return out
}

func onlyPIIFailed(result map[string]any) bool {
	failing := failingChecks(result)
	if len(failing) == 0 {
		return false
	}
	for _, c := range failing {
		if !piiChecks[str(c["check_name"])] {
			return false
		}
	}
	return true
}

func redactedEntityTypes(result map[string]any) []string {
	var types []string
	seen := map[string]bool{}
	for _, c := range failingChecks(result) {
		list, _ := obj(c["metadata"])["pii_types"].([]any)
		for _, t := range list {
			s := fmt.Sprint(t)
			if !seen[s] {
				seen[s] = true
				types = append(types, s)
			}
		}
	}
	return types
}

func extractToolResponse(event map[string]any) string {
	switch r := event["tool_response"].(type) {
	case string:
		return r
	case map[string]any:
		for _, k := range []string{"output", "stdout", "content", "text", "result"} {
			if s, ok := r[k].(string); ok && s != "" {
				return s
			}
		}
		b, _ := json.Marshal(r)
		return string(b)
	}
	return ""
}

func (h hookIO) codexScanWebOutput(content string) error {
	if strings.TrimSpace(content) == "" {
		return nil
	}
	result, err := codexPost("/v1/guardrails/evaluate-input",
		map[string]any{"text": content, "use_case": "web_fetch", "channel": "codex_hook"}, 10*time.Second)
	if err != nil {
		var q *quotaError
		if errors.As(err, &q) {
			return h.codexBlockOutput("AgentGuards request quota reached: " + q.msg + " Fetched web content withheld.")
		}
		if failOpen() {
			h.warn("AgentGuards: service unreachable (%v), allowing web content (AGENTGUARDS_FAIL_OPEN=true)", err)
			return nil
		}
		return h.codexBlockOutput(fmt.Sprintf("AgentGuards unreachable (%v) — fetched web content withheld (fail-closed).", err))
	}
	decision := decisionOf(result)
	if redacted, ok := result["redacted_text"].(string); ok && decision == "redact" &&
		strings.TrimSpace(redacted) != "" && onlyPIIFailed(result) {
		return h.codexRedactOutput(redacted, redactedEntityTypes(result))
	}
	if decision != "allow" {
		msg := str(result["message"])
		if msg == "" {
			msg = "🛡️ [AgentGuards] Web content blocked\nDecision: block\nReason: policy - flagged by AgentGuards guardrails\nSeverity: high"
		}
		return h.codexBlockOutput(msg)
	}
	return nil
}

func decisionOf(result map[string]any) string {
	if d, ok := result["decision"].(string); ok {
		return d
	}
	return "allow"
}

func extractWriteContent(toolInput map[string]any) (string, string) {
	filePath := str(toolInput["file_path"])
	if filePath == "" {
		filePath = str(toolInput["path"])
	}
	for _, k := range []string{"patch", "input", "diff", "content"} {
		if s, ok := toolInput[k].(string); ok && s != "" {
			return filePath, s
		}
	}
	return filePath, ""
}

func (h hookIO) codexScanCode(toolInput map[string]any) error {
	filePath, content := extractWriteContent(toolInput)
	if strings.TrimSpace(content) == "" {
		return nil
	}
	shown := filePath
	if shown == "" {
		shown = "file"
	}
	h.warn("AgentGuards: scanning %s for security issues...", shown)
	var fp any
	if filePath != "" {
		fp = filePath
	}
	result, err := codexPost("/v1/code/scan", map[string]any{"content": content, "file_path": fp}, 8*time.Second)
	if err != nil {
		var f *forbiddenError
		var q *quotaError
		switch {
		case errors.As(err, &f):
			return nil
		case errors.As(err, &q):
			return h.codexBlockOutput("AgentGuards request quota reached: " + q.msg + " Write withheld.")
		case failOpen():
			h.warn("AgentGuards: code scan unreachable (%v), allowing write (AGENTGUARDS_FAIL_OPEN=true)", err)
			return nil
		}
		return h.codexBlockOutput(fmt.Sprintf("AgentGuards unreachable (%v) — write withheld (fail-closed).", err))
	}
	switch decisionOf(result) {
	case "block":
		msg := str(result["message"])
		if msg == "" {
			msg = "[AgentGuards] Code scan blocked"
		}
		return h.codexBlockOutput(msg)
	case "warn":
		if msg := str(result["message"]); msg != "" {
			h.warn("%s", msg)
		}
	}
	return nil
}

// --- handlers -------------------------------------------------------------------------

func (h hookIO) codexUserPrompt(event map[string]any) error {
	prompt := str(event["prompt"])
	if strings.TrimSpace(prompt) == "" {
		return h.codexContinue()
	}
	result, err := codexPost("/v1/guardrails/evaluate-input", map[string]any{"text": prompt, "use_case": "check"}, 10*time.Second)
	if err != nil {
		var q *quotaError
		if errors.As(err, &q) {
			return h.codexBlockPrompt("[AgentGuards] Request quota reached: " + q.msg)
		}
		if failOpen() {
			h.warn("AgentGuards: service unreachable (%v), allowing prompt (AGENTGUARDS_FAIL_OPEN=true)", err)
			return h.codexContinue()
		}
		return h.codexBlockPrompt(fmt.Sprintf("[AgentGuards] Prompt blocked: service unreachable (%v); the hook is "+
			"fail-closed. %s", err, unreachableRemedy(err)))
	}
	switch decisionOf(result) {
	case "block", "escalate", "redact":
		msg := str(result["message"])
		if msg == "" {
			msg = "🛡️ [AgentGuards] Prompt blocked\nReason: policy - flagged by AgentGuards guardrails"
		}
		return h.codexBlockPrompt(msg)
	}
	return h.codexContinue()
}

const defaultCommandBlockedPanel = "🛡️ [AgentGuards] Command blocked\nDecision: deny\nReason: policy - flagged by AgentGuards guardrails\nSeverity: high"

func shownCommand(command string) string {
	r := []rune(command) // characters, like Python's len()/slicing
	if len(r) <= 500 {
		return command
	}
	return string(r[:500]) + "..."
}

func allApproved(binaries []string, approved map[string]bool) bool {
	if len(binaries) == 0 {
		return false
	}
	for _, b := range binaries {
		if !approved[b] {
			return false
		}
	}
	return true
}

func authorizePayload(toolName string, command any) map[string]any {
	if toolName == "" {
		toolName = "shell"
	}
	return map[string]any{"action": "shell_command", "tool": toolName, "parameters": map[string]any{"command": command}}
}

func (h hookIO) codexPreToolUse(event map[string]any) error {
	toolName := str(event["tool_name"])
	rawCommand := obj(event["tool_input"])["command"]
	command := commandText(rawCommand)
	sessionID := str(event["session_id"])
	if command == "" {
		return h.codexContinue()
	}
	result, err := codexPost("/v1/actions/authorize", authorizePayload(toolName, rawCommand), 10*time.Second)
	if err != nil {
		var q *quotaError
		if errors.As(err, &q) {
			return h.codexDeny("AgentGuards request quota reached: " + q.msg)
		}
		if failOpen() {
			h.warn("AgentGuards: service unreachable (%v), allowing tool call (AGENTGUARDS_FAIL_OPEN=true)", err)
			return h.codexContinue()
		}
		return h.codexDeny(fmt.Sprintf("AgentGuards is unreachable (%v) and the hook is fail-closed. %s", err, unreachableRemedy(err)))
	}
	decision := decisionOf(result)
	reason := str(result["reason"])
	if reason == "" {
		reason = defaultCommandBlockedPanel
	}
	shown := shownCommand(command)
	if decision == "deny" {
		return h.codexDeny(reason + "\n\n    " + shown)
	}
	if decision == "allow" {
		return h.codexContinue()
	}
	if allApproved(commandBinaries(command), codexApprovals().approvedBinaries(sessionID)) {
		return h.codexContinue()
	}
	return h.codexAsk(reason + "\n\n    " + shown)
}

func (h hookIO) codexPermissionRequest(event map[string]any) error {
	toolName := str(event["tool_name"])
	rawCommand := obj(event["tool_input"])["command"]
	command := commandText(rawCommand)
	sessionID := str(event["session_id"])
	if command == "" {
		return h.codexContinue()
	}
	result, err := codexPost("/v1/actions/authorize", authorizePayload(toolName, rawCommand), 10*time.Second)
	if err != nil {
		return h.codexContinue() // the user is already being asked; don't hard-block their approval
	}
	decision := decisionOf(result)
	reason := str(result["reason"])
	if reason == "" {
		reason = defaultCommandBlockedPanel
	}
	shown := shownCommand(command)
	if decision == "deny" {
		return h.codexPermissionDeny(reason + "\n\n    " + shown)
	}
	store := codexApprovals()
	if allApproved(commandBinaries(command), store.approvedBinaries(sessionID)) {
		return h.codexPermissionAllow()
	}
	store.markPending(sessionID, command)
	if decision != "allow" {
		h.warn("%s", reason+"\n\n    "+shown)
	}
	return h.codexContinue()
}

func (h hookIO) codexPostToolUse(event map[string]any) error {
	toolName := str(event["tool_name"])
	toolInput := obj(event["tool_input"])
	command := commandText(toolInput["command"])
	if command != "" && isFetchCommand(command) {
		if err := h.codexScanWebOutput(extractToolResponse(event)); err != nil {
			return err
		}
	}
	if toolName == "apply_patch" {
		if err := h.codexScanCode(toolInput); err != nil {
			return err
		}
	}
	if command != "" {
		codexApprovals().redeemPending(str(event["session_id"]), command)
	}
	return h.codexContinue()
}

func runCodexHook(h hookIO, eventType string, raw []byte) error {
	var event map[string]any
	if err := json.Unmarshal(raw, &event); err != nil || event == nil {
		return h.codexContinue()
	}
	switch eventType {
	case "PostToolUse":
		return h.codexPostToolUse(event)
	case "PermissionRequest":
		return h.codexPermissionRequest(event)
	}
	if codexAPIKey() == "" {
		message := "AgentGuards is not configured: save your ag_ token to " +
			"~/.codex/agentguards_token (or set AGENTGUARDS_API_KEY). The hook is fail-closed."
		if eventType == "PreToolUse" {
			return h.codexDeny(message)
		}
		return h.codexBlockPrompt(message)
	}
	switch eventType {
	case "UserPromptSubmit":
		return h.codexUserPrompt(event)
	case "PreToolUse":
		return h.codexPreToolUse(event)
	}
	return h.codexContinue()
}

// pyTruthy mirrors Python truthiness for decoded JSON values.
func pyTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}
