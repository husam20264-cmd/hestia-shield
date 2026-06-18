"""
Example: Protecting a LangChain agent with Hestia Shield.

Prerequisites:
    pip install langchain langchain-community langchain-openai

Run:
    # Start Hestia Shield API first
    uvicorn hestia.api:app --port 8000

    # Get an API key
    curl -X POST http://localhost:8000/v1/api-keys \
      -H "Content-Type: application/json" \
      -d '{"tenant_id": "ten_demo", "role": "admin"}'

    # Run this example
    python examples/langchain_integration.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hestia.integrations.langchain import HestiaShieldCallback

# ─── Example 1: Basic protection ─────────────────────────────────────

def example_basic_protection():
    """Protect a LangChain agent with minimal configuration."""

    callback = HestiaShieldCallback(
        api_key=os.environ.get("HESTIA_API_KEY", "hst_demo_key"),
        base_url=os.environ.get("HESTIA_API_URL", "http://localhost:8000"),
        strict=True,
    )

    print(f"✅ HestiaShieldCallback ready")
    print(f"   Base URL: {callback.client.base_url}")
    print(f"   Strict mode: {callback.strict}")
    print()

    health = callback.client.health_check()
    if health:
        print("✅ Hestia Shield API is reachable")
    else:
        print("⚠️  Hestia Shield API is not reachable — start the API server first")

    print(f"\nCallback stats: {callback.get_stats()}")


# ─── Example 2: Custom configuration ─────────────────────────────────

def example_custom_config():
    """Callback with custom configuration."""

    callback = HestiaShieldCallback(
        api_key=os.environ.get("HESTIA_API_KEY", "hst_demo_key"),
        strict=True,
        block_on_error=False,
        evaluate_prompts=True,
        evaluate_tools=True,
        excluded_tools={"math", "search"},
        user_id="user_123",
        agent_id="my_agent",
    )

    print(f"✅ Custom callback configured")
    print(f"   Excluded tools: {callback.excluded_tools}")
    print(f"   Block on error: {callback.block_on_error}")


# ─── Example 3: Log-only mode ────────────────────────────────────────

def example_log_only():
    """Log-only mode — never blocks, only logs decisions."""

    callback = HestiaShieldCallback(
        api_key=os.environ.get("HESTIA_API_KEY", "hst_demo_key"),
        strict=False,
    )

    print(f"✅ Log-only mode — actions are logged but never blocked")
    print(f"   Use strict=False for monitoring before enforcing")


# ─── Main ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("Hestia Shield — LangChain Integration Examples")
    print("=" * 60)
    print()

    example_basic_protection()
    print()
    example_custom_config()
    print()
    example_log_only()
    print()
    print("=" * 60)
    print("Done.")
