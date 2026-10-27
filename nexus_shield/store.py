"""SQLite persistence for the collector (events + the current vaccine set)."""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any

from .telemetry import Event


class Store:
    def __init__(self, path: str = ":memory:") -> None:
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        self.db.executescript(
            "create table if not exists events(id integer primary key, ts real, node text, src text,"
            " payloads text, gaps text, tags text);"
            "create table if not exists vaccines(id integer primary key check(id=1), body text);"
        )

    def close(self) -> None:
        with self.lock:
            self.db.close()

    def add(self, ev: Event) -> None:
        with self.lock, self.db:
            self.db.execute(
                "insert into events(ts,node,src,payloads,gaps,tags) values(?,?,?,?,?,?)",
                (ev.ts, ev.node, ev.src, json.dumps(ev.payloads), json.dumps(ev.gaps), json.dumps(ev.tags)),
            )

    def events(self) -> list[Event]:
        with self.lock:
            rows = self.db.execute("select ts,node,src,payloads,gaps,tags from events order by id").fetchall()
        return [Event(r[0], r[1], r[2], json.loads(r[3]), json.loads(r[4]), json.loads(r[5])) for r in rows]

    def count(self) -> int:
        with self.lock:
            return int(self.db.execute("select count(*) from events").fetchone()[0])

    def set_vaccines(self, vs: list[dict[str, Any]]) -> None:
        with self.lock, self.db:
            self.db.execute("insert or replace into vaccines(id, body) values(1, ?)", (json.dumps(vs),))

    def vaccines(self) -> list[dict[str, Any]]:
        with self.lock:
            r = self.db.execute("select body from vaccines where id=1").fetchone()
        return list(json.loads(r[0])) if r else []
