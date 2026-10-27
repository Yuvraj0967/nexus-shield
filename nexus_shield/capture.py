"""Capture helper around the rtl_sdr CLI (RTL-SDR dongles). Requires `rtl_sdr` on PATH and a device.
Writes cu8 IQ, estimates CFO/power, appends an Obs to a JSONL file. Untested against real hardware in CI."""

from __future__ import annotations

import shutil
import subprocess
import time
from collections.abc import Callable
from typing import Any

from . import sdr


def command(freq_hz: float, fs: float, n_samples: int, out: str, gain: float | None = None) -> list[str]:
    cmd = ["rtl_sdr", "-f", str(int(freq_hz)), "-s", str(int(fs)), "-n", str(int(n_samples))]
    if gain is not None:
        cmd += ["-g", str(gain)]
    return cmd + [out]


def capture_once(
    freq_hz: float,
    fs: float,
    n_samples: int,
    out: str,
    obs_path: str,
    gain: float | None = None,
    runner: Callable[..., Any] = subprocess.run,
) -> sdr.Obs:
    if runner is subprocess.run and not shutil.which("rtl_sdr"):
        raise RuntimeError("rtl_sdr not found on PATH (install rtl-sdr)")
    ts = time.time()
    runner(command(freq_hz, fs, n_samples, out, gain), check=True, timeout=60, capture_output=True)
    o = sdr.from_capture(out, ts, fs, freq_hz, fmt="cu8")
    sdr.save(obs_path, o)
    return o
