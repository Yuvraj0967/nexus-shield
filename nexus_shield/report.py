"""Summarize collected sessions into a Markdown or HTML report."""
import html
from collections import Counter
from . import analysis, sdr, vaccine

def build(events, obs=None, benign=()):
    corr = sdr.correlate(events, sdr.assign_emitters(obs)) if obs else {}
    clusters = []
    for g in analysis.cluster(events):
        evs = [events[i] for i in g]
        v, rep = vaccine.validate(evs, list(benign))
        clusters.append({"sessions": len(g), "tokens": v["tokens"], "automated": sum(analysis.features(e)["automated"] for e in evs),
                         "ips": sorted({e.ip for e in evs}), "nodes": sorted({e.node for e in evs}),
                         "vaccine_id": v["id"], "validation": rep})
    return {"sessions": len(events), "nodes": sorted({e.node for e in events}),
            "top_sources": Counter(e.ip for e in events).most_common(5),
            "vaccine_tagged": sum(any(t.startswith("vaccine:") for t in e.tags) for e in events),
            "clusters": sorted(clusters, key=lambda c: -c["sessions"]),
            "actors": {k: {**v, "ips": sorted(v["ips"]), "nodes": sorted(v["nodes"])} for k, v in sdr.actors(events, corr).items()}}

def to_markdown(r):
    L = ["# Nexus Shield report", "", "- Sessions: **%d** across nodes %s" % (r["sessions"], ", ".join(r["nodes"]) or "-"),
         "- Sessions tagged by a vaccine: **%d**" % r["vaccine_tagged"],
         "- Top sources: " + (", ".join("%s (%d)" % t for t in r["top_sources"]) or "-"), "", "## Behavioral clusters"]
    for i, c in enumerate(r["clusters"]):
        L += ["", "### Cluster %d: %d sessions (%d automated)" % (i, c["sessions"], c["automated"]),
              "- Tokens: `%s`" % " ".join(c["tokens"]), "- Sources: %s | Nodes: %s" % (", ".join(c["ips"]), ", ".join(c["nodes"])),
              "- Vaccine `%s`: %s" % (c["vaccine_id"], c["validation"])]
    if r["actors"]:
        L += ["", "## Attributed physical emitters"]
        L += ["- **%s** (CFO %+.0f Hz): %d sessions, IPs %s, nodes %s" % (k, a["cfo_hz"], a["sessions"], a["ips"], a["nodes"])
              for k, a in sorted(r["actors"].items())]
    return "\n".join(L) + "\n"

def to_html(r):
    return ("<!doctype html><meta charset=utf-8><title>Nexus Shield report</title>"
            "<body style='font:15px system-ui;max-width:48rem;margin:2rem auto;padding:0 1rem'><pre style='white-space:pre-wrap'>"
            + html.escape(to_markdown(r)) + "</pre></body>")
