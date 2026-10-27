from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field


@dataclass
class Event:
    ts: float
    node: str
    src: str
    payloads: list[str] = field(default_factory=list)  # lines sent by the peer
    gaps: list[float] = field(default_factory=list)  # seconds between lines
    tags: list[str] = field(default_factory=list)  # e.g. "vaccine:<id>"

    @property
    def ip(self) -> str:
        return self.src.rsplit(":", 1)[0]


def append(path: str, ev: Event) -> None:
    with open(path, "a") as f:
        f.write(json.dumps(asdict(ev)) + "\n")


def load(path: str) -> list[Event]:
    with open(path) as f:
        return [Event(**json.loads(line)) for line in f if line.strip()]
