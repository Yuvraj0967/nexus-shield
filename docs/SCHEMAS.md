# Schemas
**Event** (JSONL line / `POST /events`): `{"ts": float unix, "node": str, "src": "ip:port", "payloads": [str], "gaps": [float s], "tags": [str]}`
Unknown fields are rejected (HTTP 400).

**Observation** (SDR JSONL): `{"ts": float, "freq_hz": float, "power_db": float (dBFS), "cfo_hz": float, "emitter_id": str (assigned at analysis)}`

**Vaccine** (`GET/POST /vaccine`, list): `{"id": str, "tokens": [str], "min_hits": int, "block_srcs": [ip]}`.
A session matches when at least `min_hits` of `tokens` appear in its token set (lowercase words, 3+ chars, starting with a letter).

**Validation report:** `{"recall", "false_positives", "benign_tested", "safe_to_deploy", "heldout_sessions"}`; deployable iff a benign corpus was supplied, recall ≥ 0.8 and false_positives = 0.

**Collector API:** `POST /events`, `GET /events`, `GET|POST /vaccine`, `GET /healthz`. Header `X-Token` when a token is configured.
