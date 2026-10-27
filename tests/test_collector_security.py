import json
import urllib.error
import urllib.request
from typing import Any

import pytest

from nexus_shield.collector import Auth, Collector, RateLimiter


def call(c: Collector, method: str, path: str, tok: str = "", data: Any = None) -> tuple[int, Any]:
    req = urllib.request.Request(
        c.url + path, json.dumps(data).encode() if data is not None else None, {"X-Token": tok}, method=method
    )
    try:
        with urllib.request.urlopen(req) as r:
            body = r.read().decode()
            return r.status, (json.loads(body) if body.startswith(("{", "[")) else body)
    except urllib.error.HTTPError as e:
        return e.code, None


EV = {"ts": 1.0, "node": "n1", "src": "1.2.3.4:5", "payloads": ["x"]}


@pytest.fixture
def col():
    c = Collector(token="adm", node_tokens={"n1": "t1", "n2": "t2"}).start()
    yield c
    c.stop()


def test_roles(col):
    assert call(col, "POST", "/events", "t1", EV)[0] == 200  # node posts its own events
    assert call(col, "POST", "/events", "t2", EV)[0] == 403  # ...but not for another node
    assert call(col, "GET", "/vaccine", "t1")[0] == 200  # nodes may read vaccines
    assert call(col, "GET", "/events", "t1")[0] == 403  # nodes may not read events
    assert call(col, "POST", "/vaccine", "t1", [])[0] == 403  # nor publish vaccines
    assert call(col, "POST", "/vaccine", "adm", [{"id": "x", "tokens": [], "min_hits": 1}])[0] == 200
    assert call(col, "GET", "/events", "adm")[0] == 200
    assert call(col, "GET", "/events", "nope")[0] == 401
    assert call(col, "GET", "/events", "")[0] == 401


def test_metrics(col):
    call(col, "POST", "/events", "t1", EV)
    call(col, "GET", "/events", "bad")
    call(col, "POST", "/events", "t1", {"bogus": 1})
    status, text = call(col, "GET", "/metrics", "adm")
    assert status == 200
    assert "nexus_events_total 1" in text and "nexus_auth_failures_total 1" in text
    assert "nexus_bad_requests_total 1" in text and "nexus_events_stored 1" in text
    assert call(col, "GET", "/metrics", "t1")[0] == 403


def test_oversize_body_rejected(col):
    assert call(col, "POST", "/events", "adm", {**EV, "payloads": ["x" * 70000]})[0] == 400


def test_unknown_paths(col):
    assert call(col, "GET", "/nope", "adm")[0] == 404
    assert call(col, "POST", "/nope", "adm", {})[0] == 404


def test_rate_limit_http():
    c = Collector(token="adm", rate=0.001, burst=3).start()
    try:
        codes = [call(c, "GET", "/healthz", "adm")[0] for _ in range(5)]
        assert codes[:3] == [200, 200, 200] and codes[3:] == [429, 429]
        assert "nexus_rate_limited_total 2" in c.render_metrics()
    finally:
        c.stop()


def test_rate_limiter_refill():
    now = [0.0]
    rl = RateLimiter(rate=1.0, burst=2.0, clock=lambda: now[0])
    assert rl.allow("a") and rl.allow("a") and not rl.allow("a")
    assert rl.allow("b")  # independent buckets
    now[0] = 1.0
    assert rl.allow("a") and not rl.allow("a")


def test_auth_open_and_lookup():
    assert Auth().open and Auth().who("anything") == ("admin", "")
    a = Auth("adm", {"n": "tok"})
    assert a.who("adm") == ("admin", "") and a.who("tok") == ("node", "n") and a.who("x") is None
