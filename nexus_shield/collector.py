"""Central collector. Nodes POST events; it also serves the current vaccine back to nodes.
Optional shared-token auth; request bodies capped at 64 KiB."""
import json, threading
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from .telemetry import Event, append

class Collector:
    def __init__(self, host="127.0.0.1", port=0, token="", log=None):
        self.events, self.vaccines, self.token, self.log = [], [], token, log
        self.lock = threading.Lock()
        outer = self

        class H(BaseHTTPRequestHandler):
            def _send(self, code, obj):
                b = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers(); self.wfile.write(b)

            def _ok(self):
                if outer.token and self.headers.get("X-Token") != outer.token:
                    self._send(401, {"error": "unauthorized"}); return False
                return True

            def do_POST(self):
                if not self._ok(): return
                try:
                    n = int(self.headers.get("Content-Length", 0))
                    if n > 65536: raise ValueError("too large")
                    d = json.loads(self.rfile.read(n))
                    if self.path == "/events":
                        ev = Event(**d)
                        with outer.lock:
                            outer.events.append(ev)
                            if outer.log: append(outer.log, ev)
                    elif self.path == "/vaccine":
                        with outer.lock: outer.vaccines = d if isinstance(d, list) else [d]
                    else:
                        return self._send(404, {})
                except (ValueError, TypeError, KeyError):
                    return self._send(400, {"error": "bad request"})
                self._send(200, {"ok": True})

            def do_GET(self):
                if not self._ok(): return
                with outer.lock:
                    if self.path == "/vaccine": return self._send(200, outer.vaccines)
                    if self.path == "/events": return self._send(200, [asdict(e) for e in outer.events])
                self._send(404, {})

            def log_message(self, *a): pass

        self.httpd = ThreadingHTTPServer((host, port), H)
        self.url = "http://%s:%d" % self.httpd.server_address

    def start(self):
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start(); return self

    def stop(self):
        self.httpd.shutdown(); self.httpd.server_close()
