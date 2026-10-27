import argparse, asyncio, json, os, sys, time
from . import __version__, honeypot, telemetry, sdr, analysis, vaccine, report, capture
from .collector import Collector
from .store import Store

def _events(path):
    return Store(path).events() if path.endswith(".db") else telemetry.load(path)

def main(argv=None):
    tok = os.environ.get("NEXUS_TOKEN", "")
    p = argparse.ArgumentParser(prog="nexus-shield")
    p.add_argument("--version", action="version", version=__version__)
    s = p.add_subparsers(dest="cmd", required=True)
    r = s.add_parser("run", help="start a honeypot node")
    r.add_argument("--host", default="127.0.0.1"); r.add_argument("--port", type=int, default=2323)
    r.add_argument("--node", default="node-1"); r.add_argument("--log", default="events.jsonl")
    r.add_argument("--collector"); r.add_argument("--token", default=tok); r.add_argument("--cafile")
    r.add_argument("--max-conn", type=int, default=honeypot.MAX_CONN)
    c = s.add_parser("collector", help="start the central collector")
    c.add_argument("--host", default="127.0.0.1"); c.add_argument("--port", type=int, default=8080)
    c.add_argument("--token", default=tok); c.add_argument("--db", default="collected.db")
    c.add_argument("--certfile"); c.add_argument("--keyfile")
    a = s.add_parser("analyze", help="cluster sessions, attribute via SDR observations, build vaccines")
    a.add_argument("events", help=".db (collector) or .jsonl"); a.add_argument("--obs", help="JSONL SDR observations")
    pu = s.add_parser("publish", help="validate vaccines from collected events and publish them to a collector")
    pu.add_argument("events"); pu.add_argument("--benign", help="JSONL of known-benign sessions")
    pu.add_argument("--collector", required=True); pu.add_argument("--token", default=tok); pu.add_argument("--cafile")
    rp = s.add_parser("report", help="write a Markdown/HTML report")
    rp.add_argument("events"); rp.add_argument("--obs"); rp.add_argument("--benign")
    rp.add_argument("--format", choices=["md", "html"], default="md"); rp.add_argument("--out", default="-")
    cp = s.add_parser("capture", help="capture IQ with rtl_sdr and append a CFO observation")
    cp.add_argument("--freq", type=float, default=433.92e6); cp.add_argument("--rate", type=int, default=250000)
    cp.add_argument("--samples", type=int, default=4096); cp.add_argument("--gain", type=float)
    cp.add_argument("--iq-out", default="capture.cu8"); cp.add_argument("--obs", default="sdr_obs.jsonl")
    cp.add_argument("--every", type=float, help="repeat every N seconds")
    s.add_parser("demo", help="live end-to-end demo on loopback")
    x = p.parse_args(argv)

    if x.cmd == "run":
        asyncio.run(honeypot.serve(host=x.host, port=x.port, node=x.node, log=x.log, collector=x.collector,
                                   token=x.token, cafile=x.cafile, max_conn=x.max_conn))
    elif x.cmd == "collector":
        col = Collector(x.host, x.port, x.token, x.db, x.certfile, x.keyfile)
        print("collector on", col.url, flush=True); col.httpd.serve_forever()
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
        evs = _events(x.events); ben = telemetry.load(x.benign) if x.benign else []
        out = []
        for g in analysis.cluster(evs):
            v, rep = vaccine.validate([evs[i] for i in g], ben)
            print(v["id"], "deploy" if rep["safe_to_deploy"] else "SKIP", rep)
            if rep["safe_to_deploy"]: out.append(v)
        honeypot._http(x.collector + "/vaccine", x.token, out, x.cafile)
        print("published %d vaccine(s)" % len(out))
    elif x.cmd == "report":
        rep = report.build(_events(x.events), sdr.load(x.obs) if x.obs else None, telemetry.load(x.benign) if x.benign else ())
        text = report.to_markdown(rep) if x.format == "md" else report.to_html(rep)
        sys.stdout.write(text) if x.out == "-" else open(x.out, "w").write(text)
    elif x.cmd == "capture":
        while True:
            o = capture.capture_once(x.freq, x.rate, x.samples, x.iq_out, x.obs, x.gain)
            print("cfo=%+.0f Hz power=%.1f dB" % (o.cfo_hz, o.power_db), flush=True)
            if not x.every: break
            time.sleep(x.every)
    else:
        from .demo import run
        print(asyncio.run(run()))

if __name__ == "__main__": main()
