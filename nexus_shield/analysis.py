import math, re
from collections import Counter

def tokens(ev):
    """Command vocabulary of a session (lowercase words starting with a letter, 3+ chars)."""
    return {t for p in ev.payloads for t in re.findall(r"[a-z_][a-z0-9_]{2,}", p.lower())}

def entropy(s):
    c = Counter(s); n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values()) if n else 0.0

def features(ev):
    gaps = ev.gaps[1:] or [0]
    mg = sum(gaps) / len(gaps)
    return {"tokens": sorted(tokens(ev)), "lines": len(ev.payloads), "mean_gap": round(mg, 3),
            "automated": mg < 0.5 and len(ev.payloads) > 2,
            "max_entropy": round(max((entropy(p) for p in ev.payloads), default=0), 2)}

def jaccard(a, b):
    return len(a & b) / len(a | b) if a | b else 0.0

def cluster(events, threshold=0.5):
    """Greedy fuzzy clustering by token-set similarity. Returns lists of event indices."""
    groups = []   # (union token set, [indices])
    for i, e in enumerate(events):
        t = tokens(e)
        for g in groups:
            if jaccard(t, g[0]) >= threshold:
                g[0] |= t; g[1].append(i); break
        else:
            groups.append([set(t), [i]])
    return [g[1] for g in groups]
