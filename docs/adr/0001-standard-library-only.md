# ADR 0001: Standard library only
**Status:** accepted. **Context:** the node ingests hostile input and runs on small, isolated hosts; every dependency is
supply-chain surface and install friction. **Decision:** the runtime package has zero dependencies (asyncio, http.server,
sqlite3, tomllib). Tooling (pytest, ruff, mypy) is dev-only. **Consequences:** pure-Python DSP is slow (fine for 2k-sample
captures; use NumPy-backed tooling upstream for heavy RF work) and `http.server` is not a high-throughput server (rate limits and body caps compensate).
