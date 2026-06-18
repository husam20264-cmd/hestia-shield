"""
Hestia Tool Guard — CrewAI tool protection.

Wraps CrewAI tools with Hestia Shield evaluation before execution.
"""

import logging
import functools
from typing import Any, Callable, Optional

from ..langchain.client import HestiaAPIClient, HestiaDecision, HestiaSecurityError

try:
    from crewai.tools import tool as crewai_tool
    from crewai.tools.base_tool import Tool
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False
    Tool = object
    crewai_tool = None

logger = logging.getLogger(__name__)


def hestia_tool(
    api_key: str,
    base_url: str = "",
    strict: bool = True,
    block_on_error: bool = False,
    user_id: str = "crewai",
    agent_id: str = "crewai",
    result_as_answer: bool = False,
    max_usage_count: Optional[int] = None,
):
    """
    Decorator that creates a CrewAI tool protected by Hestia Shield.

    Usage:
        @hestia_tool(api_key="hst_xxx")
        def read_file(path: str) -> str:
            \"\"\"Read a file from disk.\"\"\"
            with open(path) as f:
                return f.read()

    The decorated function is evaluated before each execution.
    """
    if not CREWAI_AVAILABLE:
        raise ImportError(
            "crewai is required. Install with: pip install crewai"
        )

    client = HestiaAPIClient(api_key=api_key, base_url=base_url)

    def decorator(func: Callable) -> Tool:
        tool_name = func.__name__

        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            arguments = {"args": args, **kwargs} if args else dict(kwargs)

            try:
                decision = client.evaluate_tool_call(
                    tool_name=tool_name,
                    tool_args=arguments,
                    user_id=user_id,
                    agent_id=agent_id,
                )

                if not decision.allowed:
                    if strict:
                        raise HestiaSecurityError({
                            "decision": decision.decision,
                            "risk_score": decision.risk_score,
                            "reason": decision.reason,
                            "type": "tool",
                            "tool_name": tool_name,
                        })
                    else:
                        logger.warning(
                            "Hestia Shield would block '%s': %s",
                            tool_name, decision.reason,
                        )

            except HestiaSecurityError:
                raise
            except Exception as e:
                logger.error("Hestia Shield evaluation failed for '%s': %s", tool_name, e)
                if block_on_error:
                    raise HestiaSecurityError({
                        "decision": "block",
                        "risk_score": 1.0,
                        "reason": f"Hestia Shield unavailable: {e}",
                        "type": "tool",
                        "tool_name": tool_name,
                    })

            return func(*args, **kwargs)

        return crewai_tool(
            tool_name,
            result_as_answer=result_as_answer,
            max_usage_count=max_usage_count,
        )(wrapper)

    return decorator


def protect_tool(
    tool,
    api_key: str,
    base_url: str = "",
    strict: bool = True,
    block_on_error: bool = False,
    user_id: str = "crewai",
    agent_id: str = "crewai",
):
    """
    Wrap an existing CrewAI Tool with Hestia Shield protection.

    Creates a new Tool instance with the same name/description but
    with Hestia evaluation added before execution.

    Usage:
        from crewai.tools import tool

        @tool("read_file")
        def read_file(path: str) -> str:
            \"\"\"Read a file from disk.\"\"\"
            ...

        safe_read = protect_tool(read_file, api_key="hst_xxx")
    """
    if not CREWAI_AVAILABLE:
        raise ImportError(
            "crewai is required. Install with: pip install crewai"
        )

    client = HestiaAPIClient(api_key=api_key, base_url=base_url)
    original_run = tool.run

    def protected_run(*args, **kwargs) -> Any:
        tool_name = tool.name
        arguments = {"args": args, **kwargs} if args else dict(kwargs)

        try:
            decision = client.evaluate_tool_call(
                tool_name=tool_name,
                tool_args=arguments,
                user_id=user_id,
                agent_id=agent_id,
            )

            if not decision.allowed:
                if strict:
                    raise HestiaSecurityError({
                        "decision": decision.decision,
                        "risk_score": decision.risk_score,
                        "reason": decision.reason,
                        "type": "tool",
                        "tool_name": tool_name,
                    })
                else:
                    logger.warning(
                        "Hestia Shield would block '%s': %s",
                        tool_name, decision.reason,
                    )

        except HestiaSecurityError:
            raise
        except Exception as e:
            logger.error("Hestia Shield evaluation failed for '%s': %s", tool_name, e)
            if block_on_error:
                raise HestiaSecurityError({
                    "decision": "block",
                    "risk_score": 1.0,
                    "reason": f"Hestia Shield unavailable: {e}",
                    "type": "tool",
                    "tool_name": tool_name,
                })

        return original_run(*args, **kwargs)

    protected_run.__doc__ = getattr(original_run, "__doc__", None) or tool.name

    return crewai_tool(
        tool.name,
        result_as_answer=getattr(tool, "result_as_answer", False),
    )(protected_run)
