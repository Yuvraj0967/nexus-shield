from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
import tomllib
from typing import Any

from . import __version__, analysis, capture, honeypot, report, sdr, telemetry, vaccine
from .collector import Collector
from .log import log, setup
from .store import Store
from .telemetry import Event


def _events(path: str) -> list[Event]:
    return Store(path).events() if path.endswith(".db") else telemetry.load(path)


def load_config(path: str | None) -> dict[str, Any]:
    """TOML config: one table per subcommand (`[collector]`, `[run]`, ...); keys match the long option names."""
    if not path:
        return {}
    with open(path, "rb") as f:
        return tomllib.load(f)


def build_parser(cfg: dict[str, Any]) -> argparse.ArgumentParser:
    tok = os.environ.get("NEXUS_TOKEN", "")
    p = argparse.ArgumentParser(prog="nexus-shield")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--config", default=os.environ.get("NEXUS_CONFIG"), help="TOML config file (flags override it)")
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    s = p.add_subparsers(dest="cmd", required=True)
    r = s.add_parser("run", help="start a honeypot node")
    r.add_argument("--host", default="127.0.0.1")
    r.add_argument("--port", type=int, default=2323)
    r.add_argument("--node", default="node-1")
    r.add_argument("--log", default="events.jsonl", help="local session log (spool if the collector is down)")
    r.add_argument("--collector")
    r.add_argument("--token", default=tok)
    r.add_argument("--cafile")
    r.add_argument("--max-conn", type=int, default=honeypot.MAX_CONN)
    c = s.add_parser("collector", help="start the central collector")
    c.add_argument("--host", default="127.0.0.1")
    c.add_argument("--port", type=int, default=8080)
    c.add_argument("--token", default=tok, help="admin token")
    c.add_argument("--db", default="collected.db")
    c.add_argument("--certfile")
    c.add_argument("--keyfile")
    c.add_argument("--rate", type=float, default=50.0, help="requests/s per principal")
    c.add_argument("--burst", type=float, default=100.0)
    c.set_defaults(  # per-node credentials: config `node_tokens = { "node-1" = "..." }` or env NEXUS_NODE_TOKENS (JSON)
        node_tokens=json.loads(os.environ.get("NEXUS_NODE_TOKENS", "{}"))
    )
    a = s.add_parser("analyze", help="cluster sessions, attribute via SDR observations, build vaccines")
    a.add_argument("events", help=".db (collector) or .jsonl")
    a.add_argument("--obs", help="JSONL SDR observations")
    pu = s.add_parser("publish", help="validate vaccines from collected events and publish them to a collector")
    pu.add_argument("events")
    pu.add_argument("--benign", help="JSONL of known-benign sessions")
    pu.add_argument("--collector", required=True)
    pu.add_argument("--token", default=tok)
    pu.add_argument("--cafile")
    rp = s.add_parser("report", help="write a Markdown/HTML report")
    rp.add_argument("events")
    rp.add_argument("--obs")
    rp.add_argument("--benign")
    rp.add_argument("--format", choices=["md", "html"], default="md")
    rp.add_argument("--out", default="-")
    rl = s.add_parser("replay", help="resend a node's local JSONL log to a collector")
    rl.add_argument("events")
    rl.add_argument("--collector", required=True)
    rl.add_argument("--token", default=tok)
    rl.add_argument("--cafile")
    cp = s.add_parser("capture", help="capture IQ with rtl_sdr and append a CFO observation")
    cp.add_argument("--freq", type=float, default=433.92e6)
    cp.add_argument("--rate", type=int, default=250000)
    cp.add_argument("--samples", type=int, default=4096)
    cp.add_argument("--gain", type=float)
    cp.add_argument("--iq-out", default="capture.cu8")
    cp.add_argument("--obs", default="sdr_obs.jsonl")
    cp.add_argument("--every", type=float, help="repeat every N seconds")
    s.add_parser("demo", help="live end-to-end demo on loopback")
    b = s.add_parser("bench", help="seeded evaluation: detection vs baseline, attribution vs SNR")
    b.add_argument("--seed", type=int, default=0)
    b.add_argument("--json", action="store_true")
    for name, sp in s.choices.items():
        if name in cfg:
            sp.set_defaults(**{k.replace("-", "_"): v for k, v in cfg[name].items()})
    return p


def main(argv: list[str] | None = None) -> None:
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config", default=os.environ.get("NEXUS_CONFIG"))
    known, _ = pre.parse_known_args(argv)
    x = build_parser(load_config(known.config)).parse_args(argv)
    setup(x.log_level)

    if x.cmd == "run":
        asyncio.run(
            honeypot.serve(
                host=x.host,
                port=x.port,
                node=x.node,
                log=x.log,
                collector=x.collector,
                token=x.token,
                cafile=x.cafile,
                max_conn=x.max_conn,
            )
        )
    elif x.cmd == "collector":
        col = Collector(x.host, x.port, x.token, x.db, x.certfile, x.keyfile, x.node_tokens, x.rate, x.burst)
        if col.auth.open:
            log.warning("no tokens configured: collector is OPEN (lab use only)")
        print("collector on", col.url, flush=True)
        col.httpd.serve_forever()
    elif x.cmd == "analyze":
        evs = _events(x.events)
        if x.obs:
            obs = sdr.assign_emitters(sdr.load(x.obs))
            for em, v in sorted(sdr.actors(evs, sdr.correlate(evs, obs)).items()):
                print(em, {k: sorted(t) if isinstance(t, set) else t for k, t in v.items()})
        for g in analysis.cluster(evs):
            v, rep = vaccine.validate([evs[i] for i in g], [])
            print("cluster", g, json.dumps(v), json.dumps(rep))
    elif x.cmd == "publish":
        evs = _events(x.events)
        ben = telemetry.load(x.benign) if x.benign else []
        out = []
        for g in analysis.cluster(evs):
            v, rep = vaccine.validate([evs[i] for i in g], ben)
            print(v["id"], "deploy" if rep["safe_to_deploy"] else "SKIP", rep)
            if rep["safe_to_deploy"]:
                out.append(v)
        honeypot._http(x.collector + "/vaccine", x.token, out, x.cafile)
        print("published %d vaccine(s)" % len(out))
    elif x.cmd == "report":
        rep = report.build(
            _events(x.events), sdr.load(x.obs) if x.obs else None, telemetry.load(x.benign) if x.benign else ()
        )
        text = report.to_markdown(rep) if x.format == "md" else report.to_html(rep)
        if x.out == "-":
            sys.stdout.write(text)
        else:
            with open(x.out, "w") as f:
                f.write(text)
    elif x.cmd == "replay":
        sent = failed = 0
        for e in telemetry.load(x.events):
            try:
                honeypot._http(x.collector + "/events", x.token, e.__dict__, x.cafile)
                sent += 1
            except Exception as err:
                failed += 1
                log.warning("replay failed: %s", err)
        print("replayed %d, failed %d" % (sent, failed))
        sys.exit(1 if failed else 0)
    elif x.cmd == "capture":
        while True:
            o = capture.capture_once(x.freq, x.rate, x.samples, x.iq_out, x.obs, x.gain)
            print("cfo=%+.0f Hz power=%.1f dB" % (o.cfo_hz, o.power_db), flush=True)
            if not x.every:
                break
            time.sleep(x.every)
    elif x.cmd == "bench":
        from . import bench

        res = bench.run(lambda s: None if x.json else print(s), x.seed)
        if x.json:
            print(json.dumps(res))
    else:
        from .demo import run

        print(asyncio.run(run()))


if __name__ == "__main__":
    main()
