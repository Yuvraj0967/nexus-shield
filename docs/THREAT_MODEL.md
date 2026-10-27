# Threat model
| Asset | Threat | Mitigation | Residual risk |
|---|---|---|---|
| Node host | Exploit via attacker input | Non-executing fake prompt; caps on lines (50), line length (512 B), session time (30 s), concurrent connections (64); container is read-only, cap-drop ALL, non-root | Bugs in asyncio/Python itself; always isolate the host |
| Collector | Forged events / vaccine poisoning | Admin + per-node tokens (constant-time compare), nodes can only submit their own events, per-principal rate limits, 64 KiB body cap, strict field validation, TLS option | Per-node tokens and roles, rate limited; no replay protection, token rotation or mTLS |
| Vaccine set | Attacker shapes honeypot traffic to learn rules or trigger false positives | Benign-token stripping, held-out validation, zero-FP gate, human-reviewed `publish` | A determined attacker can evade lexical rules; poisoning needs benign corpus hygiene |
| Attribution | Spoofed or coincidental RF | Needs CFO consistency across sessions; timestamp window | CFO drifts with temperature/distance; clock skew; two emitters in range break nearest-timestamp linking. Treat as a lead, not proof |
| Privacy/legal | Logging third-party data | Stores only lines sent to the honeypot and source address | Check local law on RF monitoring and traffic logging before deploying |
**Out of scope:** active countermeasures, any code that connects out to an attacker, high-interaction honeypots.
