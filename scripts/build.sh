#!/bin/bash
set -e

echo "🚀 Building Hestia Shield v1.0.0"

pip install -e .[dev]

echo "🧪 Running unit tests..."
pytest tests/ -m "not performance and not benchmark" -v

echo "⚡ Running performance tests..."
pytest tests/ -m performance -v

echo "📊 Running benchmark tests..."
pytest tests/ -m benchmark -v

echo "📦 Building package..."
python -m build

echo "✅ Build complete! Package is in ./dist/"