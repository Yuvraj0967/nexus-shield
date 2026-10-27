"""SDR attribution from IQ samples.
Reads complex float32 (cf32) captures, as written by rtl_sdr/GNU Radio file sinks, and estimates the transmitter's
carrier-frequency offset (CFO) and power. CFO is a hardware-specific trait (oscillator error), so observations with
a consistent CFO are attributed to one physical emitter. Session<->capture linking is by nearest timestamp.
No live device driver is included: point it at captures from your own receiver."""
import cmath, json, math, random, struct
from dataclasses import dataclass

@dataclass
class Obs:
    ts: float
    freq_hz: float
    power_db: float
    cfo_hz: float
    emitter_id: str = ""

def read_iq(path, fmt="cf32"):
    """fmt: 'cf32' (GNU Radio file sink) or 'cu8' (rtl_sdr default, unsigned 8-bit I/Q)."""
    raw = open(path, "rb").read()
    if fmt == "cu8":
        return [complex((raw[i] - 127.5) / 127.5, (raw[i + 1] - 127.5) / 127.5) for i in range(0, len(raw) - 1, 2)]
    f = struct.unpack("<%df" % (len(raw) // 4), raw[: len(raw) // 4 * 4])
    return [complex(f[i], f[i + 1]) for i in range(0, len(f) - 1, 2)]

def write_iq(path, samples):
    flat = [v for s in samples for v in (s.real, s.imag)]
    open(path, "wb").write(struct.pack("<%df" % len(flat), *flat))

def estimate(samples, fs):
    """Lag-1 phase-difference CFO estimator; unambiguous within +/- fs/2."""
    z = sum(samples[i + 1] * samples[i].conjugate() for i in range(len(samples) - 1))
    cfo = cmath.phase(z) * fs / (2 * math.pi)
    p = sum(abs(s) ** 2 for s in samples) / len(samples)
    return cfo, 10 * math.log10(p) if p > 0 else -120.0

def from_capture(path, ts, fs=250_000, center_hz=433.92e6, fmt="cf32"):
    cfo, p = estimate(read_iq(path, fmt), fs)
    return Obs(ts, center_hz, p, cfo)

def synth_iq(cfo, fs=250_000, n=2048, snr_db=20, amp=0.5, seed=0):
    """Test signal generator (stand-in for a real capture)."""
    rnd = random.Random(seed)
    sg = amp / 10 ** (snr_db / 20) / math.sqrt(2)
    return [complex(amp * math.cos(2 * math.pi * cfo * i / fs) + rnd.gauss(0, sg),
                    amp * math.sin(2 * math.pi * cfo * i / fs) + rnd.gauss(0, sg)) for i in range(n)]

def assign_emitters(obs, tol_hz=250):
    """Greedy 1-D clustering on CFO; labels obs in place as emitter-N."""
    cents = []   # [sum, count]
    for o in obs:
        for i, (s, n) in enumerate(cents):
            if abs(o.cfo_hz - s / n) <= tol_hz:
                cents[i][0] += o.cfo_hz; cents[i][1] += 1; o.emitter_id = "emitter-%d" % i; break
        else:
            cents.append([o.cfo_hz, 1]); o.emitter_id = "emitter-%d" % (len(cents) - 1)
    return obs

def correlate(events, obs, window=0.4):
    """{event index: Obs} using the nearest-in-time observation within +/-window seconds."""
    out = {}
    for i, e in enumerate(events):
        c = [o for o in obs if abs(o.ts - e.ts) <= window]
        if c: out[i] = min(c, key=lambda o: abs(o.ts - e.ts))
    return out

def actors(events, corr):
    """Group sessions by physical emitter: shows one actor hopping across IPs and nodes."""
    out = {}
    for i, o in corr.items():
        a = out.setdefault(o.emitter_id, {"ips": set(), "nodes": set(), "sessions": 0, "cfo_hz": []})
        a["ips"].add(events[i].ip); a["nodes"].add(events[i].node); a["sessions"] += 1; a["cfo_hz"].append(o.cfo_hz)
    for a in out.values(): a["cfo_hz"] = round(sum(a["cfo_hz"]) / len(a["cfo_hz"]), 1)
    return out

def save(path, o):
    with open(path, "a") as f: f.write(json.dumps(o.__dict__) + "\n")

def load(path):
    return [Obs(**json.loads(l)) for l in open(path) if l.strip()]
