"""Central collector.

Nodes POST events and GET the vaccine set; admins can do everything. Features: per-node tokens (a node can only
submit events for itself), constant-time token checks, per-principal token-bucket rate limiting, 64 KiB body cap,
strict validation, SQLite persistence, optional TLS, Prometheus `/metrics`.
"""

from __future__ import annotations

import hmac
import json
import ssl
import threading
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .log import log
from .store import Store
from .telemetry import Event

MAX_BODY = 65536


class Auth:
    """Admin token + per-node tokens. With none configured the collector is open (lab use only)."""

    def __init__(self, admin: str = "", nodes: dict[str, str] | None = None) -> None:
        self.admin, self.nodes = admin, dict(nodes or {})

    @property
    def open(self) -> bool:
        return not self.admin and not self.nodes

    def who(self, token: str) -> tuple[str, str] | None:
        """Return ("admin", "") or ("node", name); None if the token is unknown."""
        if self.open:
            return ("admin", "")
        t = token.encode()
        found: tuple[str, str] | None = None
        if self.admin and hmac.compare_digest(t, self.admin.encode()):
            found = ("admin", "")
        for name, tok in self.nodes.items():  # no early exit: constant work per request
            if hmac.compare_digest(t, tok.encode()) and found is None:
                found = ("node", name)
        return found


class RateLimiter:
    def __init__(self, rate: float = 50.0, burst: float = 100.0, clock: Callable[[], float] = time.monotonic) -> None:
        self.rate, self.burst, self.clock = rate, burst, clock
        self.state: dict[str, tuple[float, float]] = {}
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = self.clock()
        with self.lock:
            tokens, last = self.state.get(key, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            ok = tokens >= 1
            self.state[key] = (tokens - 1 if ok else tokens, now)
            return ok


class Collector:
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        token: str = "",
        db: str = ":memory:",
        certfile: str | None = None,
        keyfile: str | None = None,
        node_tokens: dict[str, str] | None = None,
        rate: float = 50.0,
        burst: float = 100.0,
    ) -> None:
        self.store = Store(db)
        self.auth = Auth(token, node_tokens)
        self.limiter = RateLimiter(rate, burst)
        self.metrics: Counter[str] = Counter()
        outer = self

        class H(BaseHTTPRequestHandler):
            def _send(self, code: int, obj: Any, ctype: str = "application/json") -> None:
                b = obj.encode() if isinstance(obj, str) else json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def _principal(self, admin_only: bool = False, node_ok: bool = False) -> tuple[str, str] | None:
                who = outer.auth.who(self.headers.get("X-Token", ""))
                if who is None:
                    outer.metrics["auth_failures_total"] += 1
                    log.warning("auth failure from %s", self.client_address[0])
                    self._send(401, {"error": "unauthorized"})
                    return None
                key = who[1] or "admin" if not outer.auth.open else "anon:" + self.client_address[0]
                if not outer.limiter.allow(key):
                    outer.metrics["rate_limited_total"] += 1
                    self._send(429, {"error": "rate limited"})
                    return None
                if who[0] == "node" and not node_ok:
                    outer.metrics["forbidden_total"] += 1
                    self._send(403, {"error": "forbidden"})
                    return None
                return who

            def do_POST(self) -> None:
                who = self._principal(node_ok=self.path == "/events")
                if who is None:
                    return
                try:
                    n = int(self.headers.get("Content-Length", 0))
                    if n > MAX_BODY:
                        raise ValueError("too large")
                    d = json.loads(self.rfile.read(n))
                    if self.path == "/events":
                        ev = Event(**d)
                        if who[0] == "node" and ev.node != who[1]:
                            outer.metrics["forbidden_total"] += 1
                            return self._send(403, {"error": "node mismatch"})
                        outer.store.add(ev)
                        outer.metrics["events_total"] += 1
                    elif self.path == "/vaccine":
                        outer.store.set_vaccines(d if isinstance(d, list) else [d])
                    else:
                        return self._send(404, {})
                except (ValueError, TypeError, KeyError):
                    outer.metrics["bad_requests_total"] += 1
                    return self._send(400, {"error": "bad request"})
                self._send(200, {"ok": True})

            def do_GET(self) -> None:
                who = self._principal(node_ok=self.path in ("/vaccine", "/healthz"))
                if who is None:
                    return
                if self.path == "/vaccine":
                    return self._send(200, outer.store.vaccines())
                if self.path == "/events":
                    return self._send(200, [asdict(e) for e in outer.store.events()])
                if self.path == "/healthz":
                    return self._send(200, {"ok": True})
                if self.path == "/metrics":
                    return self._send(200, outer.render_metrics(), "text/plain; version=0.0.4")
                self._send(404, {})

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                pass

        self.httpd = ThreadingHTTPServer((host, port), H)
        scheme = "http"
        if certfile:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile, keyfile)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
            scheme = "https"
        host_, port_ = self.httpd.server_address[:2]
        self.url = f"{scheme}://{host_!s}:{port_}"

    def render_metrics(self) -> str:
        names = ["events_total", "auth_failures_total", "rate_limited_total", "forbidden_total", "bad_requests_total"]
        lines = []
        for n in names:
            lines += [f"# TYPE nexus_{n} counter", f"nexus_{n} {self.metrics[n]}"]
        lines += [
            "# TYPE nexus_events_stored gauge",
            f"nexus_events_stored {self.store.count()}",
            "# TYPE nexus_vaccines_active gauge",
            f"nexus_vaccines_active {len(self.store.vaccines())}",
        ]
        return "\n".join(lines) + "\n"

    @property
    def events(self) -> list[Event]:
        return self.store.events()

    @property
    def vaccines(self) -> list[dict[str, Any]]:
        return self.store.vaccines()

    @vaccines.setter
    def vaccines(self, v: list[dict[str, Any]]) -> None:
        self.store.set_vaccines(v)

    def start(self) -> Collector:
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.store.close()
