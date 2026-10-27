from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

from .telemetry import Event


def tokens(ev: Event) -> set[str]:
    """Command vocabulary of a session (lowercase words starting with a letter, 3+ chars)."""
    return {t for p in ev.payloads for t in re.findall(r"[a-z_][a-z0-9_]{2,}", p.lower())}


def entropy(s: str) -> float:
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values()) if n else 0.0


def features(ev: Event) -> dict[str, Any]:
    gaps = ev.gaps[1:] or [0.0]
    mg = sum(gaps) / len(gaps)
    return {
        "tokens": sorted(tokens(ev)),
        "lines": len(ev.payloads),
        "mean_gap": round(mg, 3),
        "automated": mg < 0.5 and len(ev.payloads) > 2,
        "max_entropy": round(max((entropy(p) for p in ev.payloads), default=0.0), 2),
    }


def jaccard(a: set[str], b: set[str]) -> float:
    return len(a & b) / len(a | b) if a | b else 0.0


def cluster(events: list[Event], threshold: float = 0.5) -> list[list[int]]:
    """Greedy fuzzy clustering by token-set similarity. Returns lists of event indices."""
    groups: list[tuple[set[str], list[int]]] = []
    for i, e in enumerate(events):
        t = tokens(e)
        for union, idx in groups:
            if jaccard(t, union) >= threshold:
                union |= t
                idx.append(i)
                break
        else:
            groups.append((set(t), [i]))
    return [idx for _, idx in groups]
