"""
Proxy simulator for RFC validation tests.

Runs as `mitmproxy` user. Listens on:
  - :18080 (HTTP) — intercepts redirected HTTP traffic, serves responses
  - :18443 (TCP)  — intercepts redirected HTTPS traffic, sends marker bytes

Supports:
  - GET /__health      — health check with mode and request count
  - GET /__log         — request log (JSON array of paths)
  - GET /__slow/*      — 2-second delayed response (for in-flight tests)
  - POST /__activate-mitm — switch mode from passthrough to mitm
  - Any other GET      — returns "OK path=<path> mode=<mode>"
"""

import http.server
import socketserver
import json
import socket
import threading
import time

HTTP_PORT = 18080
TLS_PORT = 18443

state = {"mode": "passthrough", "count": 0, "log": []}


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress default logging

    def do_GET(self):
        state["count"] += 1
        state["log"].append(self.path)

        if self.path == "/__health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            body = json.dumps({
                "ok": True,
                "count": state["count"],
                "mode": state["mode"],
                "tls_conns": tls_state["conns"],
            })
            self.wfile.write(body.encode())
            return

        if self.path == "/__log":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(state["log"]).encode())
            return

        if self.path.startswith("/__slow"):
            time.sleep(2)

        body = f"OK path={self.path} mode={state['mode']}"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length:
            self.rfile.read(content_length)

        if self.path == "/__activate-mitm":
            state["mode"] = "mitm"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"activated": True, "mode": "mitm"}).encode())
            return

        self.send_response(200)
        self.end_headers()


# TLS passthrough: raw TCP server that accepts connections and sends a marker.
# In real proxy-adapter, this would peek SNI and decide bypass vs MITM.
tls_state = {"conns": 0}


def tls_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("", TLS_PORT))
    srv.listen(128)
    while True:
        client, _ = srv.accept()
        tls_state["conns"] += 1
        try:
            client.sendall(b"TLS_PASSTHROUGH_REACHED")
        except Exception:
            pass
        finally:
            client.close()


threading.Thread(target=tls_server, daemon=True).start()

socketserver.ThreadingTCPServer.allow_reuse_address = True

with socketserver.ThreadingTCPServer(("", HTTP_PORT), ProxyHandler) as httpd:
    httpd.daemon_threads = True
    print(f"Proxy on :{HTTP_PORT} (HTTP) :{TLS_PORT} (TLS)", flush=True)
    httpd.serve_forever()
