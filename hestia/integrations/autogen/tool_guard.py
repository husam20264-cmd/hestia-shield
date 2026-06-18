"""
Tool Guard for AutoGen — wraps tool functions with Hestia Shield evaluation.
"""

import logging
import functools
from typing import Any, Callable, Dict, Optional

from ..langchain.client import HestiaAPIClient, HestiaDecision, HestiaSecurityError

logger = logging.getLogger(__name__)


def hestia_tool(
    api_key: str,
    base_url: str = "",
    strict: bool = True,
    block_on_error: bool = False,
    user_id: str = "autogen",
    agent_id: str = "autogen",
):
    """
    Decorator that wraps a tool function with Hestia Shield evaluation.

    The decorated function is evaluated before execution. If blocked,
    raises HestiaSecurityError (strict=True) or logs a warning.

    Usage:
        @hestia_tool(api_key="hst_xxx")
        def read_file(path: str) -> str:
            with open(path) as f:
                return f.read()
    """
    client = HestiaAPIClient(api_key=api_key, base_url=base_url)

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            tool_name = func.__name__
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

        return wrapper

    return decorator


class ToolGuard:
    """
    Programmatic tool guard — wraps callables with Hestia Shield evaluation.
    Useful when tools are created dynamically or passed as FunctionTool instances.

    Usage:
        guard = ToolGuard(api_key="hst_xxx")

        def read_file(path: str) -> str:
            ...

        safe_read = guard.protect(read_file)

        # Use with AutoGen
        from autogen_core.tools import FunctionTool
        tool = FunctionTool(safe_read, description="Read a file")
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "",
        strict: bool = True,
        block_on_error: bool = False,
        user_id: str = "autogen",
        agent_id: str = "autogen",
    ):
        self.client = HestiaAPIClient(api_key=api_key, base_url=base_url)
        self.strict = strict
        self.block_on_error = block_on_error
        self.user_id = user_id
        self.agent_id = agent_id
        self.stats = {"evaluated": 0, "blocked": 0, "errors": 0}

    def protect(self, func: Callable) -> Callable:
        """Wrap a callable with Hestia Shield evaluation."""

        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            tool_name = func.__name__
            arguments = {"args": args, **kwargs} if args else dict(kwargs)

            try:
                decision = self.client.evaluate_tool_call(
                    tool_name=tool_name,
                    tool_args=arguments,
                    user_id=self.user_id,
                    agent_id=self.agent_id,
                )
                self.stats["evaluated"] += 1

                if not decision.allowed:
                    self.stats["blocked"] += 1
                    if self.strict:
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
                self.stats["errors"] += 1
                logger.error("Hestia Shield failed for '%s': %s", tool_name, e)
                if self.block_on_error:
                    raise HestiaSecurityError({
                        "decision": "block",
                        "risk_score": 1.0,
                        "reason": f"Hestia Shield unavailable: {e}",
                        "type": "tool",
                        "tool_name": tool_name,
                    })

            return func(*args, **kwargs)

        return wrapper

    def get_stats(self) -> Dict[str, int]:
        return dict(self.stats)
