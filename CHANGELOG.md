# Changelog
## 0.3.0
- Collector: per-node tokens with roles, per-principal rate limiting, Prometheus `/metrics`, store closes cleanly.
- Node: forwarding failures are logged and kept in the local log; connection and line caps; `replay` command to resend.
- TOML config file (`--config`), `NEXUS_NODE_TOKENS`, structured logging (`--log-level`).
- Reproducible benchmark (`nexus-shield bench`), fuzz tests, 36 tests at ~98% coverage, full type hints (`mypy --strict`), ruff.
- Makefile, pre-commit, CI (lint, types, 3 Python versions, docker build), issue/PR templates, dependabot, ADRs, benchmarks doc.
- Requires Python 3.11+ (tomllib).
## 0.2.0
- Collector service (SQLite, token auth, optional TLS); nodes forward sessions and tag traffic matching published vaccines.
- SDR attribution from IQ (cf32/cu8): CFO estimation, emitter clustering, actor grouping; `capture` command for rtl_sdr.
- Fuzzy behavioral clustering; vaccines validated on held-out sessions with benign-token stripping.
- CLI (`nexus-shield`), reports (Markdown/HTML), Docker/compose lab, CI, docs, tests.
## 0.1.0
- Initial single-process prototype.
