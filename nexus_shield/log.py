"""Logging setup: one `key=value` line per record on stderr."""

from __future__ import annotations

import logging

log = logging.getLogger("nexus_shield")


def setup(level: str = "INFO") -> None:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("ts=%(asctime)s level=%(levelname)s logger=%(name)s msg=%(message)s"))
    root = logging.getLogger("nexus_shield")
    root.handlers[:] = [h]
    root.setLevel(level.upper())
    root.propagate = False
