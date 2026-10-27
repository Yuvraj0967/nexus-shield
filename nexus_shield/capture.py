"""Capture helper around the rtl_sdr CLI (RTL-SDR dongles). Requires `rtl_sdr` on PATH and a device.
Writes cu8 IQ, estimates CFO/power, appends an Obs to a JSONL file. Untested against real hardware in CI."""
import shutil, subprocess, time
from . import sdr

def command(freq_hz, fs, n_samples, out, gain=None):
    cmd = ["rtl_sdr", "-f", str(int(freq_hz)), "-s", str(int(fs)), "-n", str(int(n_samples))]
    if gain is not None: cmd += ["-g", str(gain)]
    return cmd + [out]

def capture_once(freq_hz, fs, n_samples, out, obs_path, gain=None, runner=subprocess.run):
    if runner is subprocess.run and not shutil.which("rtl_sdr"):
        raise RuntimeError("rtl_sdr not found on PATH (install rtl-sdr)")
    ts = time.time()
    runner(command(freq_hz, fs, n_samples, out, gain), check=True, timeout=60, capture_output=True)
    o = sdr.from_capture(out, ts, fs, freq_hz, fmt="cu8")
    sdr.save(obs_path, o)
    return o
