"""
Tests for Hestia Shield — AutoGen Integration
"""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from hestia.integrations.langchain.client import (
    HestiaDecision,
    HestiaSecurityError,
)
from hestia.integrations.autogen import hestia_tool, ToolGuard, create_protected_agent


class TestHestiaToolDecorator:
    """Tests for the @hestia_tool decorator."""

    def test_allowed_tool(self):
        @hestia_tool(api_key="test_key", strict=True)
        def read_file(path: str) -> str:
            return "file content"

        with patch(
            "hestia.integrations.autogen.tool_guard.HestiaAPIClient.evaluate_tool_call"
        ) as mock_eval:
            mock_eval.return_value = HestiaDecision(
                allowed=True, decision="allow", risk_score=0.1, reason="Safe", details={},
            )
            result = read_file(path="config.yaml")
            assert result == "file content"
            mock_eval.assert_called_once_with(
                tool_name="read_file",
                tool_args={"path": "config.yaml"},
                user_id="autogen",
                agent_id="autogen",
            )

    def test_blocked_tool_strict(self):
        @hestia_tool(api_key="test_key", strict=True)
        def dangerous_tool() -> str:
            return "never reached"

        with patch(
            "hestia.integrations.autogen.tool_guard.HestiaAPIClient.evaluate_tool_call"
        ) as mock_eval:
            mock_eval.return_value = HestiaDecision(
                allowed=False, decision="block", risk_score=0.95,
                reason="Dangerous operation", details={},
            )
            with pytest.raises(HestiaSecurityError) as exc:
                dangerous_tool()
            assert exc.value.decision["tool_name"] == "dangerous_tool"

    def test_blocked_tool_log_only(self):
        @hestia_tool(api_key="test_key", strict=False)
        def risky_tool() -> str:
            return "executed anyway"

        with patch(
            "hestia.integrations.autogen.tool_guard.HestiaAPIClient.evaluate_tool_call"
        ) as mock_eval:
            mock_eval.return_value = HestiaDecision(
                allowed=False, decision="block", risk_score=0.9,
                reason="Risky", details={},
            )
            result = risky_tool()
            assert result == "executed anyway"

    def test_block_on_error(self):
        @hestia_tool(api_key="test_key", strict=True, block_on_error=True)
        def my_tool() -> str:
            return "data"

        with patch(
            "hestia.integrations.autogen.tool_guard.HestiaAPIClient.evaluate_tool_call"
        ) as mock_eval:
            mock_eval.side_effect = ConnectionError("API unreachable")
            with pytest.raises(HestiaSecurityError) as exc:
                my_tool()
            assert "Hestia Shield unavailable" in exc.value.decision["reason"]

    def test_block_on_error_disabled(self):
        @hestia_tool(api_key="test_key", strict=True, block_on_error=False)
        def my_tool() -> str:
            return "data"

        with patch(
            "hestia.integrations.autogen.tool_guard.HestiaAPIClient.evaluate_tool_call"
        ) as mock_eval:
            mock_eval.side_effect = ConnectionError("API unreachable")
            result = my_tool()
            assert result == "data"

    def test_tool_with_args(self):
        @hestia_tool(api_key="test_key", strict=True)
        def add(a: int, b: int) -> int:
            return a + b

        with patch(
            "hestia.integrations.autogen.tool_guard.HestiaAPIClient.evaluate_tool_call"
        ) as mock_eval:
            mock_eval.return_value = HestiaDecision(
                allowed=True, decision="allow", risk_score=0.0, reason="Safe", details={},
            )
            result = add(2, 3)
            assert result == 5

    def test_tool_no_args(self):
        @hestia_tool(api_key="test_key")
        def ping() -> str:
            return "pong"

        with patch(
            "hestia.integrations.autogen.tool_guard.HestiaAPIClient.evaluate_tool_call"
        ) as mock_eval:
            mock_eval.return_value = HestiaDecision(
                allowed=True, decision="allow", risk_score=0.0, reason="Safe", details={},
            )
            result = ping()
            assert result == "pong"
            call_kwargs = mock_eval.call_args[1]
            assert call_kwargs["tool_args"] == {}


class TestToolGuard:
    """Tests for the ToolGuard class."""

    def test_protect_function(self):
        guard = ToolGuard(api_key="test_key", strict=True)

        def read_file(path: str) -> str:
            return "content"

        safe = guard.protect(read_file)

        with patch.object(guard.client, "evaluate_tool_call") as mock_eval:
            mock_eval.return_value = HestiaDecision(
                allowed=True, decision="allow", risk_score=0.0, reason="Safe", details={},
            )
            result = safe(path="config.yaml")
            assert result == "content"
            assert guard.get_stats()["evaluated"] == 1

    def test_protect_blocked(self):
        guard = ToolGuard(api_key="test_key", strict=True)

        def dangerous() -> str:
            return "boom"

        safe = guard.protect(dangerous)

        with patch.object(guard.client, "evaluate_tool_call") as mock_eval:
            mock_eval.return_value = HestiaDecision(
                allowed=False, decision="block", risk_score=0.9,
                reason="Blocked", details={},
            )
            with pytest.raises(HestiaSecurityError):
                safe()
            stats = guard.get_stats()
            assert stats["evaluated"] == 1
            assert stats["blocked"] == 1

    def test_get_stats(self):
        guard = ToolGuard(api_key="test_key")
        stats = guard.get_stats()
        assert stats["evaluated"] == 0
        assert stats["blocked"] == 0
        assert stats["errors"] == 0

    def test_custom_user_agent_ids(self):
        guard = ToolGuard(
            api_key="test_key", strict=True,
            user_id="admin", agent_id="research-agent",
        )

        def search() -> str:
            return "results"

        safe = guard.protect(search)

        with patch.object(guard.client, "evaluate_tool_call") as mock_eval:
            mock_eval.return_value = HestiaDecision(
                allowed=True, decision="allow", risk_score=0.0, reason="Safe", details={},
            )
            safe()
            call_kwargs = mock_eval.call_args[1]
            assert call_kwargs["user_id"] == "admin"
            assert call_kwargs["agent_id"] == "research-agent"


class TestCreateProtectedAgent:
    """Tests for create_protected_agent."""

    def test_create_agent_smoke(self):
        mock_model = MagicMock()
        guard = create_protected_agent(
            name="test_agent", api_key="test_key", model_client=mock_model,
        )
        assert guard.name == "test_agent"
        assert guard._hestia_client is not None

    @pytest.mark.asyncio
    async def test_message_evaluation_allowed(self):
        mock_model = MagicMock()
        from autogen_core import CancellationToken
        from autogen_agentchat.messages import TextMessage

        agent = create_protected_agent(
            name="agent", api_key="test_key", model_client=mock_model, strict=True,
        )

        with patch.object(agent._hestia_client, "evaluate_prompt") as mock_eval:
            mock_eval.return_value = HestiaDecision(
                allowed=True, decision="allow", risk_score=0.0, reason="Safe", details={},
            )
            with patch.object(
                agent.__class__.__bases__[0], "on_messages", new=AsyncMock()
            ) as mock_parent:
                mock_parent.return_value = "fake response"
                msg = TextMessage(content="hello", source="user")
                result = await agent.on_messages([msg], CancellationToken())
                assert result == "fake response"
                mock_eval.assert_called_once()

    @pytest.mark.asyncio
    async def test_message_evaluation_blocked(self):
        mock_model = MagicMock()
        from autogen_core import CancellationToken
        from autogen_agentchat.messages import TextMessage

        agent = create_protected_agent(
            name="agent", api_key="test_key", model_client=mock_model, strict=True,
        )

        with patch.object(agent._hestia_client, "evaluate_prompt") as mock_eval:
            mock_eval.return_value = HestiaDecision(
                allowed=False, decision="block", risk_score=0.95,
                reason="Malicious prompt", details={},
            )
            msg = TextMessage(content="delete everything", source="user")
            with pytest.raises(HestiaSecurityError) as exc:
                await agent.on_messages([msg], CancellationToken())
            assert exc.value.decision["type"] == "message"

    @pytest.mark.asyncio
    async def test_message_evaluation_skipped_when_disabled(self):
        mock_model = MagicMock()
        from autogen_core import CancellationToken

        agent = create_protected_agent(
            name="agent", api_key="test_key", model_client=mock_model,
            evaluate_messages=False,
        )

        with patch.object(agent._hestia_client, "evaluate_prompt") as mock_eval:
            with patch.object(
                agent.__class__.__bases__[0], "on_messages", new=AsyncMock()
            ) as mock_parent:
                mock_parent.return_value = "ok"
                msg = MagicMock()
                msg.content = "hello"
                await agent.on_messages([msg], CancellationToken())
                mock_eval.assert_not_called()

    @pytest.mark.asyncio
    async def test_block_on_error_enabled(self):
        mock_model = MagicMock()
        from autogen_core import CancellationToken

        agent = create_protected_agent(
            name="agent", api_key="test_key", model_client=mock_model,
            block_on_error=True,
        )

        with patch.object(agent._hestia_client, "evaluate_prompt") as mock_eval:
            mock_eval.side_effect = ConnectionError("no server")
            msg = MagicMock()
            msg.content = "test"
            with pytest.raises(HestiaSecurityError):
                await agent.on_messages([msg], CancellationToken())

    def test_get_hestia_stats(self):
        mock_model = MagicMock()
        agent = create_protected_agent(
            name="agent", api_key="test_key", model_client=mock_model,
        )
        stats = agent.get_hestia_stats()
        assert "messages_evaluated" in stats
        assert "messages_blocked" in stats
        assert "errors" in stats

    def test_create_protected_agent_no_autogen(self):
        from hestia.integrations.autogen.agent import AUTOGEN_AVAILABLE
        assert AUTOGEN_AVAILABLE is True  # autogen is installed in this env
