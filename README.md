# 🛡️ Hestia Shield v3.0.0

**Runtime security layer for autonomous AI agents with ML threat detection, attack memory, and adaptive policies.**

[![License](https://img.shields.io/github/license/husam20264-cmd/hestia-shield)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-346%2F346-success)](https://github.com/husam20264-cmd/hestia-shield)

> **Security must be fast enough to stay in the execution path.**

---

## ❓ What's the Problem?

AI agents execute code, call APIs, and manipulate data based on LLM prompts. Without runtime protection, a single malicious prompt can trigger data exfiltration, code injection, or resource exhaustion. Traditional security tools are too slow for the LLM execution path.

---

## 🎯 What Does Hestia Do?

Hestia Shield is a **runtime security layer** that evaluates every prompt and tool call before execution, blocking malicious requests while allowing safe ones to proceed with minimal latency.

---

## ⚡ Try It in 2 Minutes

```bash
pip install hestia-shield
```

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

## ✨ What Makes It Unique

| Feature | Benefit |
|---------|---------|
| **Fast Path** | < 1ms for low-risk requests — stays in the execution path |
| **ML Threat Detection** | RandomForest classifier catches sophisticated attacks |
| **Attack Memory** | Learns from every attack, adapts defenses automatically |
| **Adaptive Policies** | Generates and applies new rules without downtime |
| **4 Decisions** | `allow` / `sandbox` / `human_review` / `block` — flexible response |

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

## 🔧 Configuration

| Variable | Default | Description |
| :--- | :--- | :--- |
| `HESTIA_ML_MODEL_PATH` | `""` | Path to ML model (optional) |
| `HESTIA_POLICY_AUTO_APPLY` | `false` | Auto-apply generated policies |
| `HESTIA_POLICY_GEN_INTERVAL` | `10` | Decisions between policy generation |

---

## 📊 Performance

| Metric | v1.1.0 | v3.0.0 | Improvement |
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
| Integrations | 100+ |
| **Total** | **346/346** |

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
