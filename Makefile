.PHONY: install dev test lint clean generate report demo

PY ?= python
LOG ?= examples/sample.log

install:
	$(PY) -m pip install -e .

dev:
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest -v

clean:
	rm -rf build dist *.egg-info .pytest_cache .coverage htmlcov
	find . -type d -name __pycache__ -exec rm -rf {} +

generate:
	log-analyzer generate --out $(LOG) --lines 1000 --days 3

report:
	log-analyzer report $(LOG) --format rich

demo: generate
	@echo "--- top-ips ---"
	@log-analyzer top-ips $(LOG) --limit 5
	@echo "--- status-codes ---"
	@log-analyzer status-codes $(LOG)
	@echo "--- suspicious ---"
	@log-analyzer suspicious $(LOG)
