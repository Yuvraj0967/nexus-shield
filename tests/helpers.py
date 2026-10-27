from nexus_shield.telemetry import Event


def ev(lines, gap=0.05, ip="1.1.1.1", ts=1.0, node="n"):
    return Event(ts, node, ip + ":1", list(lines), [gap] * len(lines))
