.PHONY: help install install-dev test test-verbose coverage lint format clean build publish

# Default target
help:
	@echo "axioms-core-py - Makefile commands"
	@echo ""
	@echo "Available commands:"
	@echo "  make install       - Install package in editable mode"
	@echo "  make install-dev   - Install package with dev dependencies"
	@echo "  make test          - Run tests"
	@echo "  make test-verbose  - Run tests with verbose output"
	@echo "  make coverage      - Run tests with coverage report"
	@echo "  make lint          - Run linter (ruff)"
	@echo "  make format        - Format code with black and ruff"
	@echo "  make clean         - Remove build artifacts and cache files"
	@echo "  make build         - Build distribution packages"
	@echo "  make publish       - Publish to PyPI (requires credentials)"
	@echo "  make publish-test  - Publish to TestPyPI"

# Install package in editable mode
install:
	pip install -e .

# Install with dev dependencies
install-dev:
	pip install -e ".[dev]"

# Run tests
test:
	pytest tests/

# Run tests with verbose output
test-verbose:
	pytest tests/ -v

# Run tests with coverage
coverage:
	pytest tests/ --cov=axioms_core --cov-report=term-missing --cov-report=html

# Run linter
lint:
	ruff check src tests

# Format code
format:
	black src tests
	ruff check src tests --fix

# Clean build artifacts and cache
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .eggs/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.egg" -delete
	rm -f src/axioms_core/_version.py

# Build distribution packages
build: clean
	python -m build

# Publish to PyPI
publish: build
	twine upload dist/*

# Publish to TestPyPI
publish-test: build
	twine upload --repository testpypi dist/*

# Check package before publishing
check: build
	twine check dist/*

# Run all checks (lint, test, coverage)
check-all: lint test coverage
	@echo "All checks passed!"

# Create a new release (tag and push)
release:
	@echo "Current version: $$(git describe --tags --abbrev=0 2>/dev/null || echo 'No tags yet')"
	@read -p "Enter new version (e.g., v0.1.0): " version; \
	git tag -a $$version -m "Release $$version"; \
	git push origin $$version

# Show current version
version:
	@python -c "try:\n  from axioms_core import __version__\n  print(__version__)\nexcept:\n  print('Not installed or version not available')"
