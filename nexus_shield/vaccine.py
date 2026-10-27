"""Vaccines are PASSIVE: detection rules + blocklist suggestions. They are trained on observed sessions, stripped of
anything seen in benign traffic, and validated on held-out sessions before being marked safe to deploy.
Nothing here connects out or acts on the remote host."""
import hashlib
from collections import Counter
from .analysis import tokens

def make(events, benign=(), min_support=0.6):
    n = len(events)
    c = Counter(t for e in events for t in tokens(e))
    ben = {t for e in benign for t in tokens(e)}
    toks = sorted(t for t, k in c.items() if k / n >= min_support and t not in ben)
    return {"id": hashlib.sha256(" ".join(toks).encode()).hexdigest()[:10], "tokens": toks,
            "min_hits": min(len(toks), max(2, -(-len(toks) // 3))) if toks else 1,
            "block_srcs": sorted({e.ip for e in events})}

def matches(v, ev):
    return bool(v["tokens"]) and len(set(v["tokens"]) & tokens(ev)) >= v["min_hits"]

def evaluate(v, malicious, benign):
    tp = sum(matches(v, e) for e in malicious); fp = sum(matches(v, e) for e in benign)
    r = tp / len(malicious) if malicious else 0.0
    return {"recall": round(r, 2), "false_positives": fp, "benign_tested": len(benign),
            "safe_to_deploy": bool(benign) and fp == 0 and r >= 0.8}

def validate(events, benign, min_train=2):
    """Train on ~60% of sessions, test on the rest (never seen in training); ship a vaccine trained on all."""
    k = max(min_train, round(len(events) * 0.6))
    if len(events) - k < 1:
        return make(events, benign), {"safe_to_deploy": False, "reason": "not enough sessions to hold out"}
    held = evaluate(make(events[:k], benign), events[k:], benign)
    held["heldout_sessions"] = len(events) - k
    return make(events, benign), held
