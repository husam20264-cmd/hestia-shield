"""
HestiaShieldCallback — LangChain integration for Hestia Shield.

Evaluates prompts and tool calls before they execute in LangChain agents.
"""

import logging
import time
from typing import Any, Dict, List, Optional, Set

from .client import HestiaAPIClient, HestiaSecurityError

logger = logging.getLogger(__name__)

try:
    from langchain_core.callbacks import BaseCallbackHandler
    LANGCHAIN_AVAILABLE = True
except ImportError:
    BaseCallbackHandler = object
    LANGCHAIN_AVAILABLE = False


class HestiaShieldCallback(BaseCallbackHandler):
    """
    LangChain callback that evaluates every agent action through Hestia Shield.

    Usage:
        from hestia.integrations.langchain import HestiaShieldCallback

        agent = AgentExecutor(
            tools=tools,
            llm=llm,
            callbacks=[HestiaShieldCallback(api_key="hst_xxx")]
        )

    Parameters:
        api_key: Hestia Shield API key
        base_url: Hestia Shield API URL (default: http://localhost:8000)
        strict: If True, raises HestiaSecurityError on block decisions
        block_on_error: If True, blocks when Hestia Shield is unreachable
        evaluate_prompts: If True, evaluates LLM prompts before execution
        evaluate_tools: If True, evaluates tool calls before execution
        excluded_tools: Set of tool names to skip evaluation for
        user_id: Default user ID for evaluations
        agent_id: Default agent ID for evaluations
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "",
        strict: bool = True,
        block_on_error: bool = False,
        evaluate_prompts: bool = True,
        evaluate_tools: bool = True,
        excluded_tools: Optional[Set[str]] = None,
        user_id: str = "langchain",
        agent_id: str = "langchain",
    ):
        if not LANGCHAIN_AVAILABLE:
            raise ImportError(
                "langchain-core is required. Install with: pip install langchain-core"
            )

        super().__init__()
        self.client = HestiaAPIClient(api_key=api_key, base_url=base_url)
        self.strict = strict
        self.block_on_error = block_on_error
        self.evaluate_prompts = evaluate_prompts
        self.evaluate_tools = evaluate_tools
        self.excluded_tools = excluded_tools or set()
        self.user_id = user_id
        self.agent_id = agent_id

        self.stats = {
            "prompts_evaluated": 0,
            "tools_evaluated": 0,
            "prompts_blocked": 0,
            "tools_blocked": 0,
            "errors": 0,
        }

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        **kwargs: Any,
    ) -> None:
        if not self.evaluate_prompts or not prompts:
            return

        for prompt in prompts:
            try:
                decision = self.client.evaluate_prompt(
                    prompt=prompt,
                    user_id=self.user_id,
                    model_id=serialized.get("id", "langchain"),
                )
                self.stats["prompts_evaluated"] += 1

                if not decision.allowed:
                    self.stats["prompts_blocked"] += 1
                    msg = f"Hestia Shield blocked prompt: {decision.reason}"
                    logger.warning(msg)

                    if self.strict:
                        raise HestiaSecurityError({
                            "decision": decision.decision,
                            "risk_score": decision.risk_score,
                            "reason": decision.reason,
                            "type": "prompt",
                        })

            except HestiaSecurityError:
                raise
            except Exception as e:
                self.stats["errors"] += 1
                logger.error("Hestia Shield prompt evaluation failed: %s", e)
                if self.block_on_error:
                    raise HestiaSecurityError({
                        "decision": "block",
                        "risk_score": 1.0,
                        "reason": f"Hestia Shield unavailable: {e}",
                        "type": "prompt",
                    })

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        tool_name = serialized.get("name", kwargs.get("name", "unknown"))
        if tool_name in self.excluded_tools:
            return

        if not self.evaluate_tools:
            return

        try:
            decision = self.client.evaluate_tool_call(
                tool_name=tool_name,
                tool_args={"input": input_str},
                user_id=self.user_id,
                agent_id=self.agent_id,
            )
            self.stats["tools_evaluated"] += 1

            if not decision.allowed:
                self.stats["tools_blocked"] += 1
                msg = (
                    f"Hestia Shield blocked tool '{tool_name}': "
                    f"{decision.reason}"
                )
                logger.warning(msg)

                if self.strict:
                    raise HestiaSecurityError({
                        "decision": decision.decision,
                        "risk_score": decision.risk_score,
                        "reason": decision.reason,
                        "type": "tool",
                        "tool_name": tool_name,
                    })

        except HestiaSecurityError:
            raise
        except Exception as e:
            self.stats["errors"] += 1
            logger.error(
                "Hestia Shield tool evaluation failed for '%s': %s",
                tool_name, e,
            )
            if self.block_on_error:
                raise HestiaSecurityError({
                    "decision": "block",
                    "risk_score": 1.0,
                    "reason": f"Hestia Shield unavailable: {e}",
                    "type": "tool",
                    "tool_name": tool_name,
                })

    def on_llm_end(self, response, **kwargs: Any) -> None:
        pass

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        pass

    def on_chain_start(
        self, serialized: Dict[str, Any], inputs: Dict[str, Any], **kwargs: Any
    ) -> None:
        pass

    def on_chain_end(self, outputs: Dict[str, Any], **kwargs: Any) -> None:
        pass

    def get_stats(self) -> Dict[str, int]:
        return dict(self.stats)
