# ADR 0002: Vaccines are passive detection rules
**Status:** accepted. **Context:** "behavioral vaccines" could mean counter-attacks. **Decision:** a vaccine is data (token set,
threshold, suggested blocklist) that nodes use to tag sessions; nothing connects out to or executes against remote hosts.
Publishing requires validation on held-out sessions plus a benign corpus with zero false positives. **Consequences:** safe by
construction and auditable; response (blocking, alerting) is left to operators.
