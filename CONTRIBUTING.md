# Contributing
- Setup: `make install`. Before a PR run `make check` (ruff, `mypy --strict`, pytest with an 85% coverage gate, demo, bench). `pre-commit install` is optional.
- Design decisions live in `docs/adr/`; add an ADR for anything that changes the trust model or dependencies.
- Standard library only for the core package. Keep honeypot code non-executing: never run, evaluate, or fetch anything an attacker sends.
- Vaccines stay passive (detect/tag). Active countermeasures against remote hosts are out of scope.
- Add a test with every behavior change; document schema changes in `docs/SCHEMAS.md`.
