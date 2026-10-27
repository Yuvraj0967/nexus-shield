.PHONY: install lint format type test cov bench demo check docker
install: ; pip install -e ".[dev]"
lint: ; ruff check .
format: ; ruff format .
type: ; mypy
test: ; pytest -q
cov: ; pytest -q --cov --cov-report=term-missing
bench: ; nexus-shield bench
demo: ; nexus-shield demo
check: lint type cov bench demo   ## everything CI runs
docker: ; docker compose up --build
