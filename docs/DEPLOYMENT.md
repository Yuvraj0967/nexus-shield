# Deployment
**Local lab (Docker):** `cp .env.example .env`, fill the three tokens (`openssl rand -hex 16`), then `docker compose up --build`. Nodes listen on 127.0.0.1:2323/2324.

**Config file:** `nexus-shield --config nexus.toml collector` (see `nexus.example.toml`); flags override it. Keep secrets in the environment: `NEXUS_TOKEN`, `NEXUS_NODE_TOKENS` (JSON).

**Operations:** scrape `/metrics` with the admin token; if a node cannot reach the collector it keeps sessions in its local log, resend with `nexus-shield replay events.jsonl --collector URL`.

**Bare metal:**
```
pip install .
nexus-shield collector --host 0.0.0.0 --port 8443 --certfile c.pem --keyfile k.pem --db /var/lib/nexus/collected.db
nexus-shield run --host 0.0.0.0 --port 2323 --node edge-1 --collector https://collector:8443 --cafile ca.pem   # NEXUS_TOKEN in env
```
**Workflow:** `nexus-shield report collected.db --obs sdr_obs.jsonl --format html --out report.html`, review, then
`nexus-shield publish collected.db --benign benign.jsonl --collector https://collector:8443 --cafile ca.pem`.

**Rules of thumb:** deploy only on networks you are authorized to monitor; keep nodes off production networks; never expose
the collector publicly without TLS and a strong token; collect a benign corpus from your own environment before publishing vaccines.
