"""
Tests for Hestia Shield — CrewAI Integration
"""

import pytest
from unittest.mock import patch, MagicMock

from hestia.integrations.langchain.client import (
    HestiaDecision,
    HestiaSecurityError,
)
from hestia.integrations.crewai import create_hestia_guardrail, hestia_tool, protect_tool


class TestHestiaGuardrail:
    """Tests for create_hestia_guardrail."""

    def test_guardrail_allows_safe_output(self):
        guardrail = create_hestia_guardrail(api_key="test_key")

        mock_output = MagicMock()
        mock_output.raw = "safe response"

        with patch(
            "hestia.integrations.crewai.guardrail.HestiaAPIClient.evaluate_prompt"
        ) as mock_eval:
            mock_eval.return_value = HestiaDecision(
                allowed=True, decision="allow", risk_score=0.1, reason="Safe", details={},
            )
            success, error = guardrail(mock_output)
            assert success is True
            assert error is None

    def test_guardrail_blocks_dangerous_output_strict(self):
        guardrail = create_hestia_guardrail(api_key="test_key", strict=True)

        mock_output = MagicMock()
        mock_output.raw = "delete all files"

        with patch(
            "hestia.integrations.crewai.guardrail.HestiaAPIClient.evaluate_prompt"
        ) as mock_eval:
            mock_eval.return_value = HestiaDecision(
                allowed=False, decision="block", risk_score=0.95,
                reason="Dangerous instructions", details={},
            )
            success, error = guardrail(mock_output)
            assert success is False
            assert "blocked" in error.lower()

    def test_guardrail_logs_only_when_not_strict(self):
        guardrail = create_hestia_guardrail(api_key="test_key", strict=False)

        mock_output = MagicMock()
        mock_output.raw = "risky content"

        with patch(
            "hestia.integrations.crewai.guardrail.HestiaAPIClient.evaluate_prompt"
        ) as mock_eval:
            mock_eval.return_value = HestiaDecision(
                allowed=False, decision="block", risk_score=0.8,
                reason="Risky", details={},
            )
            success, error = guardrail(mock_output)
            assert success is True
            assert error is None

    def test_guardrail_handles_empty_output(self):
        guardrail = create_hestia_guardrail(api_key="test_key")

        mock_output = MagicMock()
        mock_output.raw = None

        with patch(
            "hestia.integrations.crewai.guardrail.HestiaAPIClient.evaluate_prompt"
        ) as mock_eval:
            success, error = guardrail(mock_output)
            assert success is True
            mock_eval.assert_not_called()

    def test_guardrail_handles_non_string_output(self):
        guardrail = create_hestia_guardrail(api_key="test_key")

        mock_output = MagicMock()
        mock_output.raw = 12345

        with patch(
            "hestia.integrations.crewai.guardrail.HestiaAPIClient.evaluate_prompt"
        ) as mock_eval:
            success, error = guardrail(mock_output)
            assert success is True
            mock_eval.assert_not_called()

    def test_guardrail_block_on_error(self):
        guardrail = create_hestia_guardrail(
            api_key="test_key", strict=True, block_on_error=True
        )

        mock_output = MagicMock()
        mock_output.raw = "test"

        with patch(
            "hestia.integrations.crewai.guardrail.HestiaAPIClient.evaluate_prompt"
        ) as mock_eval:
            mock_eval.side_effect = ConnectionError("API down")
            success, error = guardrail(mock_output)
            assert success is False
            assert "unavailable" in error.lower()

    def test_guardrail_block_on_error_disabled(self):
        guardrail = create_hestia_guardrail(
            api_key="test_key", strict=True, block_on_error=False
        )

        mock_output = MagicMock()
        mock_output.raw = "test"

        with patch(
            "hestia.integrations.crewai.guardrail.HestiaAPIClient.evaluate_prompt"
        ) as mock_eval:
            mock_eval.side_effect = ConnectionError("API down")
            success, error = guardrail(mock_output)
            assert success is True

    def test_guardrail_with_kwargs(self):
        guardrail = create_hestia_guardrail(
            api_key="test_key", user_id="admin", agent_id="research-agent"
        )

        mock_output = MagicMock()
        mock_output.raw = "safe"

        with patch(
            "hestia.integrations.crewai.guardrail.HestiaAPIClient.evaluate_prompt"
        ) as mock_eval:
            mock_eval.return_value = HestiaDecision(
                allowed=True, decision="allow", risk_score=0.0, reason="Safe", details={},
            )
            guardrail(mock_output)
            call_kwargs = mock_eval.call_args[1]
            assert call_kwargs["user_id"] == "admin"
            assert call_kwargs["model_id"] == "research-agent"


class TestHestiaCrewToolDecorator:
    """Tests for the @hestia_tool decorator."""

    def test_tool_allows_safe_call(self):
        @hestia_tool(api_key="test_key", strict=True)
        def read_file(path: str) -> str:
            """Read a file from disk."""
            return "file content"

        assert read_file.name == "read_file"

        with patch(
            "hestia.integrations.crewai.tool_guard.HestiaAPIClient.evaluate_tool_call"
        ) as mock_eval:
            mock_eval.return_value = HestiaDecision(
                allowed=True, decision="allow", risk_score=0.1, reason="Safe", details={},
            )
            result = read_file.run(path="config.yaml")
            assert result == "file content"

    def test_tool_blocks_dangerous_call(self):
        @hestia_tool(api_key="test_key", strict=True)
        def dangerous_tool() -> str:
            """A dangerous tool."""
            return "boom"

        with patch(
            "hestia.integrations.crewai.tool_guard.HestiaAPIClient.evaluate_tool_call"
        ) as mock_eval:
            mock_eval.return_value = HestiaDecision(
                allowed=False, decision="block", risk_score=0.95,
                reason="Dangerous operation", details={},
            )
            with pytest.raises(HestiaSecurityError) as exc:
                dangerous_tool.run()
            assert exc.value.decision["tool_name"] == "dangerous_tool"

    def test_tool_log_only(self):
        @hestia_tool(api_key="test_key", strict=False)
        def risky_tool() -> str:
            """A risky tool."""
            return "executed"

        with patch(
            "hestia.integrations.crewai.tool_guard.HestiaAPIClient.evaluate_tool_call"
        ) as mock_eval:
            mock_eval.return_value = HestiaDecision(
                allowed=False, decision="block", risk_score=0.8,
                reason="Risky", details={},
            )
            result = risky_tool.run()
            assert result == "executed"

    def test_tool_block_on_error(self):
        @hestia_tool(api_key="test_key", strict=True, block_on_error=True)
        def my_tool() -> str:
            """My tool."""
            return "data"

        with patch(
            "hestia.integrations.crewai.tool_guard.HestiaAPIClient.evaluate_tool_call"
        ) as mock_eval:
            mock_eval.side_effect = ConnectionError("API unreachable")
            with pytest.raises(HestiaSecurityError) as exc:
                my_tool.run()
            assert "Hestia Shield unavailable" in exc.value.decision["reason"]

    def test_tool_block_on_error_disabled(self):
        @hestia_tool(api_key="test_key", strict=True, block_on_error=False)
        def my_tool() -> str:
            """My tool."""
            return "data"

        with patch(
            "hestia.integrations.crewai.tool_guard.HestiaAPIClient.evaluate_tool_call"
        ) as mock_eval:
            mock_eval.side_effect = ConnectionError("API unreachable")
            result = my_tool.run()
            assert result == "data"

    def test_tool_with_args(self):
        @hestia_tool(api_key="test_key", strict=True)
        def add(a: int, b: int) -> int:
            """Add two numbers."""
            return a + b

        with patch(
            "hestia.integrations.crewai.tool_guard.HestiaAPIClient.evaluate_tool_call"
        ) as mock_eval:
            mock_eval.return_value = HestiaDecision(
                allowed=True, decision="allow", risk_score=0.0, reason="Safe", details={},
            )
            result = add.run(a=2, b=3)
            assert result == 5

    def test_tool_no_args(self):
        @hestia_tool(api_key="test_key")
        def ping() -> str:
            """Return pong."""
            return "pong"

        with patch(
            "hestia.integrations.crewai.tool_guard.HestiaAPIClient.evaluate_tool_call"
        ) as mock_eval:
            mock_eval.return_value = HestiaDecision(
                allowed=True, decision="allow", risk_score=0.0, reason="Safe", details={},
            )
            result = ping.run()
            assert result == "pong"
            call_kwargs = mock_eval.call_args[1]
            assert call_kwargs["tool_args"] == {}


class TestProtectTool:
    """Tests for protect_tool."""

    def test_protect_existing_tool(self):
        from crewai.tools import tool

        @tool("read_file")
        def read_file(path: str) -> str:
            """Read a file from disk."""
            return "file content"

        safe_tool = protect_tool(read_file, api_key="test_key", strict=True)

        with patch(
            "hestia.integrations.crewai.tool_guard.HestiaAPIClient.evaluate_tool_call"
        ) as mock_eval:
            mock_eval.return_value = HestiaDecision(
                allowed=True, decision="allow", risk_score=0.1, reason="Safe", details={},
            )
            result = safe_tool.run(path="config.yaml")
            assert result == "file content"

    def test_protect_tool_blocks_dangerous(self):
        from crewai.tools import tool

        @tool("dangerous_tool")
        def dangerous() -> str:
            """A dangerous tool."""
            return "boom"

        safe_tool = protect_tool(dangerous, api_key="test_key", strict=True)

        with patch(
            "hestia.integrations.crewai.tool_guard.HestiaAPIClient.evaluate_tool_call"
        ) as mock_eval:
            mock_eval.return_value = HestiaDecision(
                allowed=False, decision="block", risk_score=0.95,
                reason="Dangerous operation", details={},
            )
            with pytest.raises(HestiaSecurityError) as exc:
                safe_tool.run()
            assert exc.value.decision["tool_name"] == "dangerous_tool"
