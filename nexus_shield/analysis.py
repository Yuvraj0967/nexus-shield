import hashlib, math, re
from collections import Counter

def _entropy(s):
    if not s: return 0.0
    c = Counter(s); n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())

def tokens(ev):
    return sorted({t for p in ev.payloads for t in re.findall(r"[A-Za-z_./-]{3,}", p.lower())})

def signature(ev):
    toks = tokens(ev)
    gaps = ev.gaps[1:] or [0]
    mean_gap = sum(gaps) / len(gaps)
    f = {
        "tokens": toks,
        "lines": len(ev.payloads),
        "mean_gap": round(mean_gap, 3),
        "automated": mean_gap < 0.5 and len(ev.payloads) > 2,
        "max_entropy": round(max((_entropy(p) for p in ev.payloads), default=0), 2),
    }
    f["id"] = hashlib.sha256(" ".join(toks).encode()).hexdigest()[:12]
    return f

def cluster(events):
    groups = {}
    for i, e in enumerate(events): groups.setdefault(signature(e)["id"], []).append(i)
    return groups
