"""Low-interaction honeypot node: fake login/shell prompt. Executes nothing, binds to loopback by default.
If a collector is configured, each session is forwarded and the node tags sessions matching published vaccines."""
import asyncio, json, time, urllib.request
from dataclasses import asdict
from .telemetry import Event, append
from . import vaccine as vx

BANNER = b"Ubuntu 22.04 LTS\r\nlogin: "
MAX_LINES, MAX_LEN, TIMEOUT = 50, 512, 30

def _http(url, token, data=None):
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None,
                                 headers={"X-Token": token, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=3) as r:
        return json.loads(r.read())

async def _finish(ev, log, collector, token):
    loop = asyncio.get_running_loop()
    if collector:
        try:
            for v in await loop.run_in_executor(None, _http, collector + "/vaccine", token):
                if vx.matches(v, ev): ev.tags.append("vaccine:" + v["id"])
        except Exception: pass
    if log: append(log, ev)
    if collector:
        try: await loop.run_in_executor(None, _http, collector + "/events", token, asdict(ev))
        except Exception: pass   # collector down: local log still has it

async def _handle(r, w, node, log, collector, token):
    src = "%s:%s" % w.get_extra_info("peername")[:2]
    ev = Event(ts=time.time(), node=node, src=src)
    w.write(BANNER); await w.drain()
    last = time.monotonic()
    try:
        for _ in range(MAX_LINES):
            line = await asyncio.wait_for(r.readline(), TIMEOUT)
            if not line: break
            now = time.monotonic()
            ev.payloads.append(line[:MAX_LEN].decode("utf-8", "replace").strip())
            ev.gaps.append(round(now - last, 3)); last = now
            w.write(b"$ "); await w.drain()
    except (asyncio.TimeoutError, ConnectionError):
        pass
    finally:
        w.close()
        if ev.payloads: await _finish(ev, log, collector, token)

async def start(host="127.0.0.1", port=2323, node="node-1", log=None, collector=None, token=""):
    return await asyncio.start_server(lambda r, w: _handle(r, w, node, log, collector, token), host, port)

async def serve(**kw):
    srv = await start(**kw)
    async with srv: await srv.serve_forever()
