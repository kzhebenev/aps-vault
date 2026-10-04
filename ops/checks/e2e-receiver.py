"""A rotation receiver for the browser check (ops/checks/ui-e2e.mjs). Runs as a container on the
e2e compose network, so the backend reaches it by name while the host firewall stays untouched.

  POST /rotate          — what the vault calls: records headers + body, answers the current status
  GET  /received        — JSON list of {headers, body} for the test to inspect
  POST /status/<code>   — make the receiver answer <code> from now on (500 = "refused")
  POST /reset           — forget everything, status back to 200
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

RECEIVED = []
STATE = {"status": 200}


class H(BaseHTTPRequestHandler):
    def _send(self, code, body=b"{}"):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/received":
            return self._send(200, json.dumps(RECEIVED).encode())
        self._send(404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n).decode("utf-8", "replace")
        if self.path == "/rotate":
            RECEIVED.append({"headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})
            return self._send(STATE["status"])
        if self.path.startswith("/status/"):
            STATE["status"] = int(self.path.rsplit("/", 1)[1])
            return self._send(200)
        if self.path == "/reset":
            RECEIVED.clear(); STATE["status"] = 200
            return self._send(200)
        self._send(404)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8190), H).serve_forever()
