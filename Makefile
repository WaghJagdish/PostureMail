.PHONY: install lint typecheck test test-cov up down clean

PYTHON ?= .venv/bin/python
RUFF ?= .venv/bin/ruff
MYPY ?= .venv/bin/mypy
PYTEST ?= .venv/bin/pytest

install:
	uv venv --python 3.12 .venv
	uv pip install -e ".[dev]" --python .venv

lint:
	$(RUFF) check src tests
	$(RUFF) format --check src tests

format:
	$(RUFF) format src tests
	$(RUFF) check --fix src tests

typecheck:
	$(MYPY) src tests

test:
	$(PYTEST) -v tests

test-cov:
	$(PYTEST) -v --cov=pecff --cov-report=term-missing --cov-report=xml tests

up:
	docker compose up -d

down:
	docker compose down

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage coverage.xml dist build *.egg-info
