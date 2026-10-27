import argparse, asyncio, json
from . import honeypot, telemetry, sdr, analysis, vaccine
from .collector import Collector

def main(argv=None):
    p = argparse.ArgumentParser(prog="nexus-shield")
    s = p.add_subparsers(dest="cmd", required=True)
    r = s.add_parser("run", help="start a honeypot node")
    r.add_argument("--host", default="127.0.0.1"); r.add_argument("--port", type=int, default=2323)
    r.add_argument("--node", default="node-1"); r.add_argument("--log", default="events.jsonl")
    r.add_argument("--collector"); r.add_argument("--token", default="")
    c = s.add_parser("collector", help="start the central collector")
    c.add_argument("--host", default="127.0.0.1"); c.add_argument("--port", type=int, default=8080)
    c.add_argument("--token", default=""); c.add_argument("--log", default="collected.jsonl")
    a = s.add_parser("analyze", help="cluster events, attribute via SDR observations, build vaccines")
    a.add_argument("events"); a.add_argument("--obs", help="JSONL of SDR observations (ts,freq_hz,power_db,cfo_hz)")
    s.add_parser("demo", help="live end-to-end demo on loopback")
    x = p.parse_args(argv)
    if x.cmd == "run":
        asyncio.run(honeypot.serve(host=x.host, port=x.port, node=x.node, log=x.log, collector=x.collector, token=x.token))
    elif x.cmd == "collector":
        col = Collector(x.host, x.port, x.token, x.log); print("collector on", col.url); col.httpd.serve_forever()
    elif x.cmd == "analyze":
        evs = telemetry.load(x.events)
        if x.obs:
            obs = sdr.assign_emitters(sdr.load(x.obs))
            for em, v in sorted(sdr.actors(evs, sdr.correlate(evs, obs)).items()):
                print(em, {k: sorted(t) if isinstance(t, set) else t for k, t in v.items()})
        for g in analysis.cluster(evs):
            v, rep = vaccine.validate([evs[i] for i in g], [])
            print("cluster", g, json.dumps(v), json.dumps(rep))
    else:
        from .demo import run
        print(asyncio.run(run()))

if __name__ == "__main__": main()
