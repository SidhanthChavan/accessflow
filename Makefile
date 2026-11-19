ARGS = --hr data/hr_feed.csv --policy config/policy.yaml --today 2026-11-19

.PHONY: install test lint demo plan apply verify clean

install:
	pip install -e ".[dev]"

test:
	pytest --cov=accessflow --cov-report=term-missing

lint:
	ruff check src tests scripts

demo: clean
	python scripts/seed_demo.py
	accessflow plan $(ARGS)
	accessflow apply $(ARGS) --actor demo
	accessflow plan $(ARGS)
	accessflow verify-audit audit/audit.jsonl

plan:
	accessflow plan $(ARGS)

apply:
	accessflow apply $(ARGS)

verify:
	accessflow verify-audit audit/audit.jsonl

clean:
	rm -rf reports audit .pytest_cache .coverage
