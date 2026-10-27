# SDR attribution
**Idea:** a transmitter's oscillator error produces a roughly stable carrier-frequency offset (CFO). Repeated captures
with the same CFO suggest the same physical emitter even when the network identity (IP) changes.

**Estimator:** lag-1 phase difference, `CFO = angle(Σ x[n+1]·conj(x[n])) · fs / 2π` (unambiguous within ±fs/2), plus mean power in dBFS.
Accuracy on synthetic 20 dB SNR signals is within ~100 Hz (see `tests/test_sdr.py`).

**Capture:** `nexus-shield capture --freq 433.92e6 --rate 250000 --every 5` wraps `rtl_sdr` (cu8) and appends observations to `sdr_obs.jsonl`.
GNU Radio users can write cf32 files and call `sdr.from_capture(..., fmt="cf32")`. Hardware path is not covered by automated tests.

**Linking:** `correlate` pairs each session to the nearest observation within ±0.4 s; run clocks under NTP/PTP. `assign_emitters` clusters CFOs with a 250 Hz tolerance.

**Caveats:** only works if the emitter is a radio within range of your receiver and its signal is captured at session time. CFO drifts
with temperature and supply voltage, and a demodulated/relayed signal shows the relay's CFO. Treat results as investigative leads.
