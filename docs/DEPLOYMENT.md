# Deployment
**Local lab (Docker):** `export NEXUS_TOKEN=$(openssl rand -hex 16); docker compose up --build`. Nodes listen on 127.0.0.1:2323/2324.

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
