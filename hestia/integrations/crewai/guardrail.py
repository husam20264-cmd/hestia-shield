"""
Hestia Guardrail — CrewAI guardrail integration.

Provides a factory that returns a guardrail callable compatible with
CrewAI Agent.guardrail and Task.guardrail.

The guardrail evaluates the agent's output before it's returned,
blocking or logging based on configuration.
"""

import logging
from typing import Any, Tuple

from ..langchain.client import HestiaAPIClient, HestiaDecision, HestiaSecurityError

logger = logging.getLogger(__name__)


def create_hestia_guardrail(
    api_key: str,
    base_url: str = "",
    strict: bool = True,
    block_on_error: bool = False,
    user_id: str = "crewai",
    agent_id: str = "crewai",
):
    """
    Create a guardrail callable for CrewAI Agent/Task.

    The guardrail evaluates the agent's raw output through Hestia Shield.
    Returns (True, None) if allowed, (False, error_message) if blocked.

    Usage:
        from hestia.integrations.crewai import create_hestia_guardrail

        agent = Agent(
            role="assistant",
            goal="Help users",
            backstory="You are helpful",
            guardrail=create_hestia_guardrail(api_key="hst_xxx"),
        )
    """
    client = HestiaAPIClient(api_key=api_key, base_url=base_url)

    def guardrail(output, **kwargs) -> Tuple[bool, Any]:
        raw = getattr(output, "raw", None) or getattr(output, "content", str(output))
        if not raw or not isinstance(raw, str):
            return True, None

        try:
            decision = client.evaluate_prompt(
                prompt=raw,
                user_id=user_id,
                model_id=agent_id,
            )

            if not decision.allowed:
                msg = f"Hestia Shield blocked output: {decision.reason}"
                logger.warning(msg)
                if strict:
                    return False, msg

        except HestiaSecurityError:
            raise
        except Exception as e:
            logger.error("Hestia Shield guardrail failed: %s", e)
            if block_on_error:
                return False, f"Hestia Shield unavailable: {e}"

        return True, None

    return guardrail
