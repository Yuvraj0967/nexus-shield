# Contributing
- `pip install -e ".[dev]" && pytest -q` must pass; `python -m nexus_shield demo` must report all-true results.
- Standard library only for the core package. Keep honeypot code non-executing: never run, evaluate, or fetch anything an attacker sends.
- Vaccines stay passive (detect/tag). Active countermeasures against remote hosts are out of scope.
- Add a test with every behavior change; document schema changes in `docs/SCHEMAS.md`.
