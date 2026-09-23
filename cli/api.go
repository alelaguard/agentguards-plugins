package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

var httpClient = &http.Client{Timeout: 20 * time.Second}

// apiBase is the AgentGuards REST base. AGENTGUARDS_URL overrides it (the same
// variable the hooks read), e.g. for testing against a local API.
func apiBase() string {
	if u := strings.TrimRight(os.Getenv("AGENTGUARDS_URL"), "/"); u != "" {
		return u
	}
	return "https://prod.agentguards.co"
}

// postJSON sends body as JSON and decodes the response into out (if non-nil).
// It returns the HTTP status so callers can read RFC 8628 errors from 400s.
func postJSON(path string, body any, apiKey string, out any) (int, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequest(http.MethodPost, apiBase()+path, bytes.NewReader(b))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AgentGuards-Client", "installer/"+version)
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("unexpected response (HTTP %d)", resp.StatusCode)
		}
	}
	return resp.StatusCode, nil
}

// checkKey sends one harmless screening request with the key. It is also the
// tenant's first request, which is what the dashboard counts as "connected".
func checkKey(apiKey string) error {
	var out struct {
		Decision string `json:"decision"`
		Detail   any    `json:"detail"`
	}
	status, err := postJSON("/v1/guardrails/evaluate-input",
		map[string]string{"text": "AgentGuards installer connectivity check"}, apiKey, &out)
	if err != nil {
		return fmt.Errorf("could not reach AgentGuards at %s: %w", apiBase(), err)
	}
	switch {
	case status == 401 || status == 403:
		return fmt.Errorf("the key was rejected (HTTP %d)", status)
	case status == 429:
		return fmt.Errorf("the key works, but this account is over its request quota (HTTP 429)")
	case status != 200:
		return fmt.Errorf("unexpected response from AgentGuards (HTTP %d)", status)
	}
	return nil
}
