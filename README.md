# Nexus Shield

Status: v0.2 working project (stdlib-only Python 3.10+). Runs end to end on loopback with simulated attackers and
synthetic radio captures. Not a production security product.

Distributed honeypot nodes feed a central collector. An SDR layer attributes sessions to physical emitters, an
analysis layer clusters behavior, and **passive vaccines** (detection rules) are validated on held-out sessions
and published back to the nodes, which then tag matching traffic.

```
attackers ──► honeypot nodes ──POST /events──► collector ──► analysis ──► vaccine (validated)
               (node-1, node-2)   ▲                 ▲  ▲                      │
                                  │ GET /vaccine ───┘  └── SDR attribution    │
                                  └────────────────────────── published ◄─────┘
```

## What each part really does
| Part | File | Behavior |
|---|---|---|
| Honeypot node | `honeypot.py` | Fake login/shell prompt (asyncio). Executes nothing; loopback by default; caps lines, line length, session time. Forwards sessions to the collector, tags sessions matching published vaccines |
| Collector | `collector.py`, `store.py` | HTTP service backed by SQLite: `POST /events`, `GET /events`, `GET/POST /vaccine`, `GET /healthz`. Token auth, 64 KiB body cap, input validation, optional TLS |
| SDR attribution | `sdr.py` | Reads cf32 IQ captures, estimates carrier-frequency offset + power, clusters emitters by CFO, links captures to sessions by nearest timestamp, groups sessions into actors across IPs/nodes |
| Analysis | `analysis.py` | Token/timing/entropy features; fuzzy (Jaccard) clustering, so tooling variants group together |
| Vaccines | `vaccine.py` | Rule = token set + hit threshold + source blocklist. Tokens seen in benign traffic are removed; trained on ~60% of a cluster, tested on the unseen rest; `safe_to_deploy` needs recall >= 0.8 and zero benign false positives |

## Install & run
```
pip install -e ".[dev]"            # Python 3.10+, no runtime dependencies
pytest -q                          # 15 tests, including a live end-to-end run
nexus-shield demo                  # collector + 2 nodes + attackers on loopback

export NEXUS_TOKEN=secret
nexus-shield collector --port 8080 --db collected.db            # add --certfile/--keyfile for TLS
nexus-shield run --port 2323 --node node-1 --collector http://127.0.0.1:8080
nexus-shield capture --every 5                                  # rtl_sdr -> sdr_obs.jsonl (needs hardware)
nexus-shield report collected.db --obs sdr_obs.jsonl --format html --out report.html
nexus-shield publish collected.db --benign benign.jsonl --collector http://127.0.0.1:8080
docker compose up --build          # hardened two-node lab
```
Docs: [architecture](docs/ARCHITECTURE.md) · [threat model](docs/THREAT_MODEL.md) · [schemas/API](docs/SCHEMAS.md) · [SDR](docs/SDR.md) · [deployment](docs/DEPLOYMENT.md)

## Demo output (abridged)
```
[2] emitter-0 cfo=+1201 Hz: 3 sessions, ips=['127.0.0.2','127.0.0.3'] nodes=['node-1','node-2']   <- one actor, two IPs
    attribution matches ground truth: True
[3] cluster of 3 sessions -> held-out {'recall': 1.0, 'false_positives': 0, 'safe_to_deploy': True}
[4] variant tagged: True ['vaccine:...'] | benign falsely tagged: 0     <- new actor, mutated tooling
```

## Limitations (honest)
- **SDR:** the demo uses synthetic IQ. Real captures need your own receiver (e.g. `rtl_sdr` writing cf32); there is no device driver, and real CFO drifts with temperature and distance, so tolerances need tuning. Timestamp linking assumes well-synchronized clocks and that the emitter is physically within radio range of a receiver.
- **Detection is lexical:** token-based; an attacker who avoids known vocabulary evades it. No ML, no protocol-level emulation beyond a fake prompt.
- **Vaccines never act on remote hosts.** They tag/alert; blocking is a human or firewall decision. Held-out sets in the demo are tiny; real use needs far more data.
- Single collector, shared-token auth only (no per-node identity or rate limiting).
- Docker/`rtl_sdr` paths are provided but not exercised in CI.
- Use only in authorized, isolated environments.
