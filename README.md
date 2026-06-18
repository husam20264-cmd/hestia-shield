# 🛡️ Hestia Shield v1.2.0

**Runtime security layer for autonomous AI agents.**

[![License](https://img.shields.io/github/license/husam20264-cmd/hestia-shield)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-91%2F91-success)](https://github.com/husam20264-cmd/hestia-shield)

> **Security must be fast enough to stay in the execution path.**

---

## 🚀 What's New in v1.2.0

### 🧠 ML-based Threat Detection
- Lightweight RandomForest classifier (20+ features)
- Real-time inference with <1ms overhead
- Auto-extracts features from prompts, tools, and behavior

### 🧬 Self-Learning Attack Memory
- SQLite-backed attack memory with pattern analysis
- Learns from every attack attempt
- Dynamically adapts strategy based on success/failure

### 📜 Adaptive Policy Generation
- Generates new security rules automatically
- Creates block keywords, tool restrictions, and risk thresholds
- Three modes: `dry_run`, `pending_approval`, `auto_apply`

### ⚡ Performance
- Fast Path: < 1ms (with ML)
- Full Pipeline: p95 < 8ms
- Throughput: 400+ req/s
- 100 concurrent requests: 250ms total

---

## 📦 Installation

```bash
pip install hestia-shield
```

For Redis support:

```bash
pip install hestia-shield[redis]
```

---

## 🚀 Quick Start

```python
from hestia import HestiaCore

hestia = HestiaCore(tenant_id="ten_123")

decision = hestia.evaluate_prompt(
    prompt="Summarize this document",
    user_id="user_123",
    model_id="model_456"
)

if decision.allowed:
    response = llm.chat(prompt)
else:
    response = decision.safe_message
```

---

## 🔧 Configuration

| Variable | Default | Description |
| :--- | :--- | :--- |
| `HESTIA_ML_MODEL_PATH` | `""` | Path to ML model (optional) |
| `HESTIA_POLICY_AUTO_APPLY` | `false` | Auto-apply generated policies |
| `HESTIA_POLICY_GEN_INTERVAL` | `10` | Decisions between policy generation |

---

## 📊 Performance

| Metric | v1.1.0 | v1.2.0 | Improvement |
| :--- | ---: | ---: | ---: |
| Fast Path | < 20ms | < 1ms | ⬇️ 95% |
| Full Path (p95) | < 50ms | < 8ms | ⬇️ 84% |
| Throughput | 500 req/s | 400+ req/s | — |
| ML Overhead | — | < 1ms | ✅ New |

---

## 🧪 Test Coverage

| Suite | Count |
| :--- | ---: |
| Core + Policy | 87 |
| Performance | 4 |
| **Total** | **91/91** |

---

## 🏛️ Architecture

```
Request -> Fast Path (< 1ms)
              |
         Low Risk? -- Yes -> Allow
              | No
         Parallel Full Evaluation
              |- Rules Engine
              |- ML Classifier
              |- Attack Memory
              |- Agent Monitor
              |- Policy Engine
              |
         Decision Aggregator
              |
         allow / sandbox / human_review / block
```

---

## 📄 License

Apache 2.0
