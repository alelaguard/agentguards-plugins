package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

type deviceCode struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type tokenResponse struct {
	APIKey  string `json:"api_key"`
	KeyName string `json:"key_name"`
	Error   string `json:"error"`
}

// sleep is swapped out in tests so polling doesn't take real seconds.
var sleep = time.Sleep

var labelUnsafe = regexp.MustCompile(`[^A-Za-z0-9 ._@,+/-]`)

// clientLabel is what the approval page shows as "the installer reports", e.g.
// "claude-code, codex @ edo-laptop". Display only — the server treats it as untrusted.
func clientLabel(agents []string) string {
	host, _ := os.Hostname()
	label := strings.Join(agents, ", ")
	if host != "" {
		label += " @ " + host
	}
	label = labelUnsafe.ReplaceAllString(label, "")
	if len(label) > 80 {
		label = label[:80]
	}
	return label
}

// deviceLogin runs the browser approval flow and returns a freshly minted key.
func deviceLogin(out io.Writer, agents []string, openBrowser bool) (string, error) {
	var dc deviceCode
	status, err := postJSON("/v1/device/code", map[string]string{"client_label": clientLabel(agents)}, "", &dc)
	if err != nil {
		return "", fmt.Errorf("could not reach AgentGuards at %s: %w", apiBase(), err)
	}
	if status == 429 {
		return "", errors.New("too many sign-in attempts from this network — wait a minute and try again")
	}
	if status != 200 || dc.DeviceCode == "" {
		return "", fmt.Errorf("could not start sign-in (HTTP %d)", status)
	}

	fmt.Fprintf(out, "\nTo connect this computer, approve it in your browser:\n\n")
	fmt.Fprintf(out, "    %s\n\n", dc.VerificationURIComplete)
	fmt.Fprintf(out, "and check the code matches:  %s\n\n", dc.UserCode)
	fmt.Fprintf(out, "No account yet? You can sign up on that page — it's free.\n")
	if openBrowser && tryOpenBrowser(dc.VerificationURIComplete) {
		fmt.Fprintf(out, "(Opened your browser. If it didn't appear, open the link above.)\n")
	}
	fmt.Fprintf(out, "\nWaiting for approval (expires in %d minutes)...\n", max(1, dc.ExpiresIn/60))

	interval := time.Duration(max(dc.Interval, 1)) * time.Second
	deadline := time.Now().Add(time.Duration(dc.ExpiresIn+30) * time.Second)
	for time.Now().Before(deadline) {
		sleep(interval)
		var tr tokenResponse
		status, err := postJSON("/v1/device/token", map[string]string{"device_code": dc.DeviceCode}, "", &tr)
		if err != nil {
			continue // transient network error: keep polling until the code expires
		}
		if status == 200 && validKey(tr.APIKey) {
			return tr.APIKey, nil
		}
		switch tr.Error {
		case "authorization_pending":
		case "slow_down":
			interval += 5 * time.Second
		case "access_denied":
			return "", errors.New("the request was denied in the browser")
		case "expired_token":
			return "", errors.New("the code expired before it was approved — run the installer again")
		case "key_limit_reached":
			return "", errors.New("your plan's API-key limit was reached, so no key was created — run the installer again and choose a key to replace")
		default:
			return "", fmt.Errorf("sign-in failed (HTTP %d %s)", status, tr.Error)
		}
	}
	return "", errors.New("timed out waiting for approval — run the installer again")
}

// tryOpenBrowser opens url without blocking; failure is fine, the URL is printed.
func tryOpenBrowser(url string) bool {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return false // headless (SSH, container): don't pretend
		}
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Stdout, cmd.Stderr = nil, nil
	return cmd.Start() == nil
}
