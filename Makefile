.PHONY: install test lint format run all

install:
	pip install -e .

test:
	python -m pytest

lint:
	python -m ruff check .

format:
	python -m ruff format --check .

run:
	python -m cloud_hardening_lab --help

all: lint format test
