"""
Hestia Shield - CrewAI Integration

Protect CrewAI agents with Hestia Shield guardrails and tool protection.

Usage:
    from hestia.integrations.crewai import (
        create_hestia_guardrail,
        hestia_tool,
        protect_tool,
    )

    # Guardrail for agent output
    agent = Agent(
        role="assistant",
        goal="Help users",
        backstory="You are helpful",
        guardrail=create_hestia_guardrail(api_key="hst_xxx"),
    )

    # Protected tools via decorator
    @hestia_tool(api_key="hst_xxx")
    def read_file(path: str) -> str:
        \"\"\"Read a file from disk.\"\"\"
        ...
"""

from .guardrail import create_hestia_guardrail
from .tool_guard import hestia_tool, protect_tool

__all__ = [
    "create_hestia_guardrail",
    "hestia_tool",
    "protect_tool",
]
