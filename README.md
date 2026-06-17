# Hestia Shield

Runtime Security for AI Agents - v1.0.0

## Features

- Low-latency decision engine (<50ms p95)
- Fast path for low-risk requests
- Rules engine with custom conditions
- Attack pattern detection
- Agent monitoring
- Redis caching (optional)
- Webhooks for security events
- Multi-tenant support

## Installation

```bash
pip install hestia-shield
```

## Usage

```python
from hestia import DecisionEngine, RulesEngine, TextClassifier

engine = DecisionEngine()
decision = await engine.evaluate_prompt(
    prompt="Summarize this document",
    user_id="usr_1"
)
```

## API

```bash
# Start server
hestia-api

# Or
uvicorn hestia.api:app --host 0.0.0.0 --port 8000
```

## Tests

```bash
# All tests
pytest tests/ -v

# Performance tests
pytest tests/ -m performance

# Benchmark
pytest tests/ -m benchmark
```

## License

Apache-2.0