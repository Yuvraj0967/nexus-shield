import json, time
from dataclasses import dataclass, asdict, field

@dataclass
class Event:
    ts: float
    node: str
    src: str
    payloads: list = field(default_factory=list)   # decoded text lines sent by the peer
    gaps: list = field(default_factory=list)       # seconds between lines

def append(path, ev):
    with open(path, "a") as f:
        f.write(json.dumps(asdict(ev)) + "\n")

def load(path):
    with open(path) as f:
        return [Event(**json.loads(l)) for l in f if l.strip()]
