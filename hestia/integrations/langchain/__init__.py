"""
Hestia Shield - LangChain Integration

Protect LangChain agents with one line of code.

Usage:
    from hestia.integrations.langchain import HestiaShieldCallback

    agent = AgentExecutor(
        tools=tools,
        llm=llm,
        callbacks=[HestiaShieldCallback(api_key="hst_xxx")]
    )
"""

from .callback import HestiaShieldCallback

__all__ = ["HestiaShieldCallback"]
