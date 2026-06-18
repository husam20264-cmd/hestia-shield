"""
Hestia Shield - AutoGen Integration

Protect Microsoft AutoGen agents with Hestia Shield.

Usage:
    from hestia.integrations.autogen import hestia_tool, create_protected_agent

    # Protect individual tools
    @hestia_tool(api_key="hst_xxx")
    def read_file(path: str) -> str:
        ...

    # Or create a fully protected agent
    agent = create_protected_agent(
        name="assistant",
        api_key="hst_xxx",
        model_client=model_client,
        tools=[read_file],
    )
"""

from .tool_guard import hestia_tool, ToolGuard
from .agent import create_protected_agent

__all__ = ["hestia_tool", "ToolGuard", "create_protected_agent"]
