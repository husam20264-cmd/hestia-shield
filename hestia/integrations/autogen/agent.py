"""
HestiaAutoGenAgent — AutoGen agent protected by Hestia Shield.

Evaluates every message and tool call before execution.
"""

import logging
from typing import Any, Dict, List, Optional, Sequence

from ..langchain.client import HestiaAPIClient, HestiaDecision, HestiaSecurityError

try:
    from autogen_agentchat.agents import AssistantAgent
    from autogen_agentchat.base import Response
    from autogen_agentchat.messages import BaseChatMessage, TextMessage
    from autogen_core import CancellationToken

    AUTOGEN_AVAILABLE = True
except ImportError:
    AUTOGEN_AVAILABLE = False
    AssistantAgent = object

logger = logging.getLogger(__name__)


def create_protected_agent(
    name: str,
    api_key: str,
    model_client,
    *,
    base_url: str = "",
    strict: bool = True,
    block_on_error: bool = False,
    evaluate_messages: bool = True,
    user_id: str = "autogen",
    agent_id: str = "autogen",
    **kwargs,
):
    """
    Create an AutoGen AssistantAgent protected by Hestia Shield.

    Usage:
        from autogen_ext.models.openai import OpenAIChatCompletionClient

        model = OpenAIChatCompletionClient(model="gpt-4")
        agent = create_protected_agent(
            name="assistant",
            api_key="hst_xxx",
            model_client=model,
            tools=[read_file, write_file],
        )
    """
    if not AUTOGEN_AVAILABLE:
        raise ImportError(
            "autogen-agentchat is required. Install with: pip install autogen-agentchat"
        )

    return _ProtectedAgent(
        name=name,
        api_key=api_key,
        base_url=base_url,
        strict=strict,
        block_on_error=block_on_error,
        evaluate_messages=evaluate_messages,
        user_id=user_id,
        agent_id=agent_id,
        model_client=model_client,
        **kwargs,
    )


class _ProtectedAgent(AssistantAgent):
    """
    Internal subclass of AssistantAgent with Hestia Shield protection.
    Use create_protected_agent() instead of instantiating directly.
    """

    def __init__(
        self,
        name: str,
        api_key: str,
        base_url: str,
        strict: bool,
        block_on_error: bool,
        evaluate_messages: bool,
        user_id: str,
        agent_id: str,
        model_client,
        **kwargs,
    ):
        self._hestia_client = HestiaAPIClient(api_key=api_key, base_url=base_url)
        self._hestia_strict = strict
        self._hestia_block_on_error = block_on_error
        self._hestia_evaluate_messages = evaluate_messages
        self._hestia_user_id = user_id
        self._hestia_agent_id = agent_id
        self._hestia_stats = {
            "messages_evaluated": 0,
            "messages_blocked": 0,
            "errors": 0,
        }

        super().__init__(name=name, model_client=model_client, **kwargs)

    async def on_messages(
        self,
        messages: Sequence[BaseChatMessage],
        cancellation_token: CancellationToken,
    ) -> Response:
        if self._hestia_evaluate_messages:
            for msg in messages:
                content = getattr(msg, "content", None)
                if content and isinstance(content, str):
                    try:
                        decision = self._hestia_client.evaluate_prompt(
                            prompt=content,
                            user_id=self._hestia_user_id,
                            model_id=self._hestia_agent_id,
                        )
                        self._hestia_stats["messages_evaluated"] += 1

                        if not decision.allowed:
                            self._hestia_stats["messages_blocked"] += 1
                            msg_text = (
                                f"Hestia Shield blocked message: {decision.reason}"
                            )
                            logger.warning(msg_text)

                            if self._hestia_strict:
                                raise HestiaSecurityError({
                                    "decision": decision.decision,
                                    "risk_score": decision.risk_score,
                                    "reason": decision.reason,
                                    "type": "message",
                                })

                    except HestiaSecurityError:
                        raise
                    except Exception as e:
                        self._hestia_stats["errors"] += 1
                        logger.error(
                            "Hestia Shield message evaluation failed: %s", e
                        )
                        if self._hestia_block_on_error:
                            raise HestiaSecurityError({
                                "decision": "block",
                                "risk_score": 1.0,
                                "reason": f"Hestia Shield unavailable: {e}",
                                "type": "message",
                            })

        return await super().on_messages(messages, cancellation_token)

    def get_hestia_stats(self) -> Dict[str, int]:
        return dict(self._hestia_stats)
