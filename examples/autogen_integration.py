"""
AutoGen Integration Example — Hestia Shield

Prerequisites:
    pip install autogen-agentchat autogen-ext[openai]

Run:
    export HESTIA_API_KEY="hst_xxx"
    python examples/autogen_integration.py
"""

import logging
import os
from pathlib import Path

logging.basicConfig(level=logging.INFO)

hestia_api_key = os.getenv("HESTIA_API_KEY", "hst_dev_key")
hestia_base_url = os.getenv("HESTIA_BASE_URL", "http://localhost:8000")

# ── 1. Decorate individual tools ──────────────────────────────────────

from hestia.integrations.autogen import hestia_tool


@hestia_tool(api_key=hestia_api_key, base_url=hestia_base_url, strict=True)
def read_file(path: str) -> str:
    """Read a file from disk."""
    return Path(path).read_text()


@hestia_tool(api_key=hestia_api_key, base_url=hestia_base_url, strict=True)
def write_file(path: str, content: str) -> str:
    """Write content to a file."""
    Path(path).write_text(content)
    return f"Written {len(content)} bytes to {path}"


@hestia_tool(api_key=hestia_api_key, base_url=hestia_base_url, strict=True)
def delete_file(path: str) -> str:
    """Delete a file from disk."""
    Path(path).unlink()
    return f"Deleted {path}"


# ── 2. Use ToolGuard for dynamic tools ────────────────────────────────

from hestia.integrations.autogen import ToolGuard

tool_guard = ToolGuard(
    api_key=hestia_api_key,
    base_url=hestia_base_url,
    strict=True,
)

def search_docs(query: str) -> str:
    return f"Results for: {query}"

def execute_shell(command: str) -> str:
    return f"Executed: {command}"

safe_search = tool_guard.protect(search_docs)
safe_shell = tool_guard.protect(execute_shell)

# ── 3. Create a protected AutoGen Agent ─────────────────────────────

# Protected agent example — requires a model client like OpenAI
# from autogen_ext.models.openai import OpenAIChatCompletionClient
#
# model_client = OpenAIChatCompletionClient(model="gpt-4")
#
# from hestia.integrations.autogen import create_protected_agent
#
# agent = create_protected_agent(
#     name="safe_assistant",
#     api_key=hestia_api_key,
#     base_url=hestia_base_url,
#     model_client=model_client,
#     tools=[safe_search, safe_shell],
#     strict=True,
#     evaluate_messages=True,
#     block_on_error=False,
# )


if __name__ == "__main__":
    print("Hestia Shield ❖ AutoGen Integration")
    print("=" * 40)

    # Test a few tool calls
    print("\n--- Safe tool calls (should pass) ---")
    try:
        result = safe_search(query="How to use AutoGen?")
        print(f"  search_docs: {result}")
        stats = tool_guard.get_stats()
        print(f"  Stats: {stats}")
    except Exception as e:
        print(f"  Error: {e}")

    print("\nDone. See examples/autogen_integration.py for the full example.")
