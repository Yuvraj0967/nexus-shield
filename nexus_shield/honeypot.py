"""Low-interaction honeypot node: fake login/shell prompt. Executes nothing, binds to loopback by default.

If a collector is configured, each session is forwarded and tagged with any published vaccine it matches.
Sessions are always written to the local log first, so nothing is lost when the collector is down
(use `nexus-shield replay` to resend)."""

from __future__ import annotations

import asyncio
import json
import ssl
import time
import urllib.request
from dataclasses import asdict
from typing import Any

from . import vaccine as vx
from .log import log
from .telemetry import Event, append

BANNER = b"Ubuntu 22.04 LTS\r\nlogin: "
MAX_LINES, MAX_LEN, TIMEOUT, MAX_CONN = 50, 512, 30, 64


def _http(url: str, token: str, data: Any = None, cafile: str | None = None) -> Any:
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode() if data is not None else None,
        headers={"X-Token": token, "Content-Type": "application/json"},
    )
    ctx = ssl.create_default_context(cafile=cafile) if url.startswith("https") else None
    with urllib.request.urlopen(req, timeout=3, context=ctx) as r:
        return json.loads(r.read())


async def _finish(ev: Event, log_path: str | None, collector: str | None, token: str, cafile: str | None) -> None:
    loop = asyncio.get_running_loop()
    if collector:
        try:
            for v in await loop.run_in_executor(None, _http, collector + "/vaccine", token, None, cafile):
                if vx.matches(v, ev):
                    ev.tags.append("vaccine:" + v["id"])
        except Exception as e:  # network/auth/parse: still record the session
            log.warning("vaccine fetch failed: %s", e)
    if log_path:
        append(log_path, ev)
    if collector:
        try:
            await loop.run_in_executor(None, _http, collector + "/events", token, asdict(ev), cafile)
        except Exception as e:
            log.warning("forward failed (kept in local log): %s", e)
    log.info("session node=%s src=%s lines=%d tags=%s", ev.node, ev.src, len(ev.payloads), ev.tags)


async def _handle(
    r: asyncio.StreamReader,
    w: asyncio.StreamWriter,
    node: str,
    log_path: str | None,
    collector: str | None,
    token: str,
    cafile: str | None = None,
) -> None:
    src = "%s:%s" % w.get_extra_info("peername")[:2]
    ev = Event(ts=time.time(), node=node, src=src)
    w.write(BANNER)
    await w.drain()
    last = time.monotonic()
    try:
        for _ in range(MAX_LINES):
            line = await asyncio.wait_for(r.readline(), TIMEOUT)
            if not line:
                break
            now = time.monotonic()
            ev.payloads.append(line[:MAX_LEN].decode("utf-8", "replace").strip())
            ev.gaps.append(round(now - last, 3))
            last = now
            w.write(b"$ ")
            await w.drain()
    except (TimeoutError, ConnectionError, ValueError):  # ValueError: line over the stream limit
        pass
    finally:
        w.close()
        if ev.payloads:
            await _finish(ev, log_path, collector, token, cafile)


async def start(
    host: str = "127.0.0.1",
    port: int = 2323,
    node: str = "node-1",
    log: str | None = None,
    collector: str | None = None,
    token: str = "",
    cafile: str | None = None,
    max_conn: int = MAX_CONN,
) -> asyncio.Server:
    sem = asyncio.Semaphore(max_conn)

    async def guarded(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        if sem.locked():  # connection cap: drop excess instead of queueing
            w.close()
            return
        async with sem:
            await _handle(r, w, node, log, collector, token, cafile)

    return await asyncio.start_server(guarded, host, port)


async def serve(**kw: Any) -> None:
    srv = await start(**kw)
    async with srv:
        await srv.serve_forever()
