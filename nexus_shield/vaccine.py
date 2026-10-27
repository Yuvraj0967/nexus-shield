"""Vaccines are PASSIVE: detection rules + blocklist suggestions, validated offline against a benign corpus.
Nothing here connects out or touches the attacker."""
import re
from .analysis import signature

def make(events, min_support=2):
    """Tokens seen across >= min_support sessions form a rule."""
    from collections import Counter
    c = Counter(t for e in events for t in set(signature(e)["tokens"]))
    toks = sorted(t for t, n in c.items() if n >= min_support)
    return {"tokens": toks, "min_hits": max(1, min(2, len(toks))), "block_srcs": sorted({e.src.split(":")[0] for e in events})}

def matches(vaccine, ev):
    if not vaccine["tokens"]: return False
    text = " ".join(ev.payloads).lower()
    return sum(1 for t in vaccine["tokens"] if re.search(re.escape(t), text)) >= vaccine["min_hits"]

def evaluate(vaccine, malicious, benign):
    tp = sum(matches(vaccine, e) for e in malicious)
    fp = sum(matches(vaccine, e) for e in benign)
    return {"recall": tp / len(malicious) if malicious else 0.0,
            "false_positives": fp, "benign": len(benign), "safe_to_deploy": fp == 0 and tp > 0}
