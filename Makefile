.PHONY: install test lint format run run-fixed sarif docker-build docker-run clean

install:
	uv sync --python 3.12

test:
	uv run pytest -q

lint:
	uv run ruff check .
	uv run ruff format --check .

format:
	uv run ruff format .
	uv run ruff check . --fix

run:  ## lint the deliberately bad example (exits 1)
	-uv run kubeready examples/bad

run-fixed:
	uv run kubeready examples/fixed

sarif:
	uv run kubeready examples/bad --format sarif --output kubeready.sarif --fail-on none

docker-build:
	docker build -t kubeready .

docker-run:
	docker run --rm -v "$(PWD)/examples:/work:ro" kubeready fixed

clean:
	rm -rf .pytest_cache .ruff_cache kubeready.sarif
