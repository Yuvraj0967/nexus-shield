# ADR 0003: Per-node credentials and roles
**Status:** accepted. **Decision:** the collector has an admin token plus one token per node. Nodes can post events only for
their own name and read vaccines; only admins read events, publish vaccines or read metrics. Requests are rate-limited per
principal. **Consequences:** a compromised node cannot forge other nodes' data or poison vaccines. Not covered: replay protection,
token rotation, mTLS (see `docs/THREAT_MODEL.md`).
