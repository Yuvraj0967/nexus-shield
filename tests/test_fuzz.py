import asyncio
import json
import random
import urllib.error
import urllib.request

from nexus_shield import honeypot
from nexus_shield.collector import Collector


def test_collector_never_5xx_on_garbage():
    c = Collector(token="t").start()
    rnd = random.Random(7)
    try:
        for _ in range(150):
            kind = rnd.choice(["bytes", "json", "fields"])
            if kind == "bytes":
                body = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 200)))
            elif kind == "json":
                body = json.dumps(rnd.choice([None, 1, "s", [], [1, 2], {"a": {"b": 1}}])).encode()
            else:
                body = json.dumps(
                    {
                        "ts": rnd.choice([1, "x", None]),
                        "node": rnd.choice(["n", 5]),
                        "src": "a:1",
                        "payloads": rnd.choice([["a"], "str", 3]),
                        "extra": 1,
                    }
                ).encode()
            req = urllib.request.Request(c.url + "/events", body, {"X-Token": "t"})
            try:
                code = urllib.request.urlopen(req).status
            except urllib.error.HTTPError as e:
                code = e.code
            assert code < 500
    finally:
        c.stop()


def test_node_survives_garbage_and_limits_lines():
    async def go():
        srv = await honeypot.start(port=0)
        port = srv.sockets[0].getsockname()[1]
        rnd = random.Random(3)
        for _ in range(10):  # binary junk, huge lines, abrupt close
            r, w = await asyncio.open_connection("127.0.0.1", port)
            await r.read(5)
            w.write(bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 3000))) + b"\n" + b"A" * 200000)
            await w.drain()
            w.close()
        await asyncio.sleep(0.2)
        r, w = await asyncio.open_connection("127.0.0.1", port)  # still serving
        assert (await r.read(5)).startswith(b"Ubun")
        w.close()
        srv.close()

    asyncio.run(go())


def test_node_keeps_local_log_when_collector_down(tmp_path):
    async def go():
        log = str(tmp_path / "e.jsonl")
        srv = await honeypot.start(port=0, log=log, collector="http://127.0.0.1:9", token="x")
        port = srv.sockets[0].getsockname()[1]
        r, w = await asyncio.open_connection("127.0.0.1", port)
        await r.read(5)
        w.write(b"root\nwget x\n")
        await w.drain()
        w.close()
        await asyncio.sleep(1.0)
        srv.close()
        return log

    log = asyncio.run(go())
    with open(log) as f:
        assert [json.loads(line)["payloads"] for line in f] == [["root", "wget x"]]
