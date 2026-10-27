"""Low-interaction honeypot: fake login/shell prompt. Executes nothing, binds to loopback by default."""
import asyncio, time
from .telemetry import Event, append

BANNER = b"Ubuntu 22.04 LTS\r\nlogin: "
MAX_LINES, MAX_LEN, TIMEOUT = 50, 512, 30

async def _handle(r, w, node, log):
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
        if ev.payloads: append(log, ev)

async def serve(host="127.0.0.1", port=2323, node="node-1", log="events.jsonl"):
    srv = await asyncio.start_server(lambda r, w: _handle(r, w, node, log), host, port)
    async with srv: await srv.serve_forever()
