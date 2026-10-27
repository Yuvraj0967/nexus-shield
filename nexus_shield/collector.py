"""Central collector. Nodes POST events; it also serves the current vaccine set back to nodes.
Shared-token auth (constant-time compare), 64 KiB body cap, SQLite persistence, optional TLS."""
import hmac, json, ssl, threading
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from .store import Store
from .telemetry import Event

class Collector:
    def __init__(self, host="127.0.0.1", port=0, token="", db=":memory:", certfile=None, keyfile=None):
        self.store, self.token = Store(db), token
        outer = self

        class H(BaseHTTPRequestHandler):
            def _send(self, code, obj):
                b = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers(); self.wfile.write(b)

            def _ok(self):
                got = self.headers.get("X-Token", "")
                if outer.token and not hmac.compare_digest(got.encode(), outer.token.encode()):
                    self._send(401, {"error": "unauthorized"}); return False
                return True

            def do_POST(self):
                if not self._ok(): return
                try:
                    n = int(self.headers.get("Content-Length", 0))
                    if n > 65536: raise ValueError("too large")
                    d = json.loads(self.rfile.read(n))
                    if self.path == "/events":
                        outer.store.add(Event(**d))
                    elif self.path == "/vaccine":
                        outer.store.set_vaccines(d if isinstance(d, list) else [d])
                    else:
                        return self._send(404, {})
                except (ValueError, TypeError, KeyError):
                    return self._send(400, {"error": "bad request"})
                self._send(200, {"ok": True})

            def do_GET(self):
                if not self._ok(): return
                if self.path == "/vaccine": return self._send(200, outer.store.vaccines())
                if self.path == "/events": return self._send(200, [asdict(e) for e in outer.store.events()])
                if self.path == "/healthz": return self._send(200, {"ok": True})
                self._send(404, {})

            def log_message(self, *a): pass

        self.httpd = ThreadingHTTPServer((host, port), H)
        scheme = "http"
        if certfile:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(certfile, keyfile)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True); scheme = "https"
        self.url = "%s://%s:%d" % ((scheme,) + self.httpd.server_address[:2])

    @property
    def events(self): return self.store.events()

    @property
    def vaccines(self): return self.store.vaccines()

    @vaccines.setter
    def vaccines(self, v): self.store.set_vaccines(v)

    def start(self):
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start(); return self

    def stop(self):
        self.httpd.shutdown(); self.httpd.server_close()
