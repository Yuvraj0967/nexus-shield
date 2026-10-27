"""SDR attribution by replay. Reads observations (from any SDR capture tool exported as JSONL/CSV-like dicts)
and correlates them to honeypot events by time window. No hardware access here."""
import json, random
from dataclasses import dataclass

@dataclass
class Obs:
    ts: float
    freq_hz: float
    rssi_dbm: float
    emitter_id: str   # e.g. clustered RF fingerprint label

def load(path):
    with open(path) as f:
        return [Obs(**json.loads(l)) for l in f if l.strip()]

def correlate(events, observations, window=5.0):
    """Return {event index: emitter_id} for the strongest observation within +/-window seconds."""
    out = {}
    for i, e in enumerate(events):
        c = [o for o in observations if abs(o.ts - e.ts) <= window]
        if c: out[i] = max(c, key=lambda o: o.rssi_dbm).emitter_id
    return out

def synth(events, seed=0):
    rnd = random.Random(seed); obs = []
    for e in events:
        obs.append(Obs(e.ts + rnd.uniform(-2, 2), 433.92e6, rnd.uniform(-80, -50), "emitter-" + e.src.split(":")[0]))
    return obs
