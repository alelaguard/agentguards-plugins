"""Tiny stand-in for the AgentGuards API, for the installer end-to-end CI job.

Blocks any text containing "ignore all previous instructions", allows the rest,
accepts any ag_ key, and records which client sent each request so the job can
prove which runtime a hook really used (e.g. Codex -> "codex/go").
GET /_requests returns the log. Usage: python mock_api.py PORT
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = []


class Handler(BaseHTTPRequestHandler):
    def _send(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        if self.path == "/_requests":
            self._send(200, LOG)
        else:
            self._send(404, {"detail": "not found"})

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        LOG.append({"path": self.path, "client": self.headers.get("X-AgentGuards-Client", "")})
        if not self.headers.get("X-API-Key", "").startswith("ag_"):
            return self._send(401, {"detail": "bad key"})
        if self.path == "/v1/guardrails/evaluate-input":
            if "ignore all previous instructions" in str(body.get("text", "")).lower():
                return self._send(200, {"decision": "block",
                                        "message": "🛡️ [AgentGuards] Prompt blocked\nReason: mock - jailbreak"})
            return self._send(200, {"decision": "allow", "checks": []})
        if self.path == "/v1/actions/authorize":
            return self._send(200, {"decision": "allow"})
        if self.path == "/v1/code/scan":
            return self._send(200, {"decision": "allow"})
        return self._send(404, {"detail": "not found"})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
