# Nexus Shield

Status: working prototype (stdlib-only Python, no hardware required).

A defensive honeypot pipeline: **collect → attribute → analyze → vaccinate**.

| Component | File | Role |
|---|---|---|
| Honeypot node | `honeypot.py` | Low-interaction fake login prompt; executes nothing, binds to 127.0.0.1 by default, caps input size/time |
| Telemetry | `telemetry.py` | JSONL event schema (`ts, node, src, payloads, gaps`) |
| SDR attribution | `sdr.py` | Correlates replayed SDR observations (JSONL) to events by time window; synthetic generator for demos. No live SDR driver yet |
| Analysis | `analysis.py` | Token/timing/entropy features, stable signature ID, clustering |
| Vaccines | `vaccine.py` | Passive detection rules + blocklist suggestions, evaluated for recall/false positives on a benign corpus before "safe_to_deploy" |

## Run
    python -m nexus_shield demo                 # end-to-end simulation
    python -m nexus_shield run --port 2323      # start a honeypot node (loopback)
    python tests/test_all.py-style: python -m pytest   # if pytest is installed

## Limitations
- SDR is replay/synthetic only; real hardware capture and RF fingerprinting are not implemented.
- Vaccines are detection rules only; they never act against remote hosts (deliberate).
- Signatures are token-based; no ML, no multi-node aggregation yet.
- Run only in authorized, isolated environments.
