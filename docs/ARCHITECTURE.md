# Architecture
```
attacker ─► node (asyncio, non-executing) ──POST /events──► collector (HTTP + SQLite) ◄── analyst CLI
                  ▲                                              │  analyze / report / publish
                  └──────────── GET /vaccine ◄───────────────────┘
SDR receiver ─► capture (rtl_sdr or GNU Radio) ─► Obs(ts, cfo, power) ─► correlate with sessions by timestamp
```
**Flow:** nodes record each session (lines + inter-line gaps). The collector stores them. `analyze`/`report` cluster
sessions by token-set Jaccard similarity, attribute sessions to emitters via SDR observations, and `publish` builds a
vaccine per cluster, validates it on sessions held out from training and against a benign corpus, and uploads only those
that pass. Nodes fetch the vaccine set at the end of each session and add a `vaccine:<id>` tag on matches.

**Modules:** `honeypot` (node), `collector` + `store` (service), `telemetry` (schema/JSONL), `sdr` + `capture` (RF),
`analysis` (features/clustering), `vaccine` (rules/validation), `report`, `demo`, `cli`.

**Design choices:** stdlib only; node never executes input; vaccines are data, not code; the collector is the only
shared state; every stage is usable offline from JSONL/SQLite files.

**Trust boundaries:** attacker↔node (hostile input, capped and non-executing); node↔collector (per-node token, optional TLS); analyst↔collector (admin token). See `docs/THREAT_MODEL.md` and `docs/adr/`.
