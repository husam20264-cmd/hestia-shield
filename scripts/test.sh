#!/bin/bash
set -e

echo "🧪 Running all tests for Hestia Shield v1.0.0"

pip install -e .[dev]

pytest tests/ -v --cov=hestia --cov-report=html --cov-report=term

echo "✅ Tests complete! Coverage report in ./htmlcov/"