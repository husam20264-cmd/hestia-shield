"""
Tests for Hestia Shield — LangChain Integration
"""

import pytest
import json
from unittest.mock import patch, MagicMock
from urllib.error import URLError

from hestia.integrations.langchain.callback import HestiaShieldCallback
from hestia.integrations.langchain.client import (
    HestiaAPIClient,
    HestiaDecision,
    HestiaSecurityError,
)


class TestHestiaDecision:
    def test_from_dict_allowed(self):
        d = HestiaDecision.from_dict({
            "decision": "allow",
            "risk_score": 0.1,
            "reason": "Safe",
            "details": {},
        })
        assert d.allowed is True
        assert d.decision == "allow"
        assert d.risk_score == 0.1

    def test_from_dict_blocked(self):
        d = HestiaDecision.from_dict({
            "decision": "block",
            "risk_score": 0.95,
            "reason": "Malicious content detected",
            "details": {"triggered_keywords": ["delete"]},
        })
        assert d.allowed is False
        assert d.decision == "block"
        assert d.risk_score == 0.95


class TestHestiaAPIClient:
    def test_init_defaults(self):
        client = HestiaAPIClient(api_key="test_key")
        assert client.api_key == "test_key"
        assert client.base_url == "http://localhost:8000"

    def test_init_custom_url(self):
        client = HestiaAPIClient(api_key="test_key", base_url="http://hestia:9000")
        assert client.base_url == "http://hestia:9000"

    def test_infer_category_execute(self):
        client = HestiaAPIClient(api_key="test_key")
        assert client._infer_category("shell") == "execute"
        assert client._infer_category("run_command") == "execute"

    def test_infer_category_read(self):
        client = HestiaAPIClient(api_key="test_key")
        assert client._infer_category("read_file") == "read"
        assert client._infer_category("search_docs") == "read"

    def test_infer_category_write(self):
        client = HestiaAPIClient(api_key="test_key")
        assert client._infer_category("write_file") == "write"
        assert client._infer_category("create_doc") == "write"

    def test_infer_category_delete(self):
        client = HestiaAPIClient(api_key="test_key")
        assert client._infer_category("delete_file") == "delete"
        assert client._infer_category("remove_item") == "delete"

    def test_infer_category_network(self):
        client = HestiaAPIClient(api_key="test_key")
        assert client._infer_category("send_email") == "network"
        assert client._infer_category("http_post") == "network"

    def test_health_check_success(self):
        client = HestiaAPIClient(api_key="test_key", base_url="http://localhost:8000")
        with patch("hestia.integrations.langchain.client.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_urlopen.return_value.__enter__.return_value = mock_resp
            assert client.health_check() is True

    def test_health_check_failure(self):
        client = HestiaAPIClient(api_key="test_key", base_url="http://localhost:8000")
        with patch("hestia.integrations.langchain.client.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = URLError("Connection refused")
            assert client.health_check() is False


class TestHestiaSecurityError:
    def test_error_message(self):
        error = HestiaSecurityError({
            "decision": "block",
            "risk_score": 0.95,
            "reason": "High-risk content detected",
        })
        assert str(error) == "High-risk content detected"
        assert error.decision["decision"] == "block"


class TestHestiaShieldCallback:
    def test_init(self):
        cb = HestiaShieldCallback(
            api_key="test_key",
            base_url="http://localhost:8000",
            strict=True,
        )
        assert cb.client.api_key == "test_key"
        assert cb.client.base_url == "http://localhost:8000"
        assert cb.strict is True
        assert cb.evaluate_prompts is True
        assert cb.evaluate_tools is True
        assert cb.stats["prompts_evaluated"] == 0

    def test_init_custom(self):
        cb = HestiaShieldCallback(
            api_key="test_key",
            strict=False,
            block_on_error=True,
            evaluate_prompts=False,
            evaluate_tools=True,
            excluded_tools={"math"},
            user_id="custom_user",
            agent_id="custom_agent",
        )
        assert cb.strict is False
        assert cb.block_on_error is True
        assert cb.evaluate_prompts is False
        assert cb.evaluate_tools is True
        assert "math" in cb.excluded_tools
        assert cb.user_id == "custom_user"
        assert cb.agent_id == "custom_agent"

    def test_on_llm_start_evaluates_prompt(self):
        cb = HestiaShieldCallback(api_key="test_key", strict=False)
        with patch.object(cb.client, "evaluate_prompt") as mock_eval:
            mock_eval.return_value = HestiaDecision(
                allowed=True,
                decision="allow",
                risk_score=0.1,
                reason="Safe",
                details={},
            )
            cb.on_llm_start(
                serialized={"id": "gpt-4"},
                prompts=["Summarize this document"],
            )
            assert cb.stats["prompts_evaluated"] == 1
            assert cb.stats["prompts_blocked"] == 0

    def test_on_llm_start_blocked_strict(self):
        cb = HestiaShieldCallback(api_key="test_key", strict=True)
        with patch.object(cb.client, "evaluate_prompt") as mock_eval:
            mock_eval.return_value = HestiaDecision(
                allowed=False,
                decision="block",
                risk_score=0.95,
                reason="Malicious content",
                details={},
            )
            with pytest.raises(HestiaSecurityError) as exc:
                cb.on_llm_start(
                    serialized={"id": "gpt-4"},
                    prompts=["Delete all files"],
                )
            assert exc.value.decision["reason"] == "Malicious content"
            assert cb.stats["prompts_blocked"] == 1

    def test_on_llm_start_blocked_not_strict(self):
        cb = HestiaShieldCallback(api_key="test_key", strict=False)
        with patch.object(cb.client, "evaluate_prompt") as mock_eval:
            mock_eval.return_value = HestiaDecision(
                allowed=False,
                decision="block",
                risk_score=0.95,
                reason="Malicious content",
                details={},
            )
            cb.on_llm_start(
                serialized={"id": "gpt-4"},
                prompts=["Delete all files"],
            )
            assert cb.stats["prompts_evaluated"] == 1
            assert cb.stats["prompts_blocked"] == 1

    def test_on_llm_start_skipped_when_disabled(self):
        cb = HestiaShieldCallback(
            api_key="test_key", strict=False, evaluate_prompts=False
        )
        with patch.object(cb.client, "evaluate_prompt") as mock_eval:
            cb.on_llm_start(
                serialized={"id": "gpt-4"},
                prompts=["Test prompt"],
            )
            mock_eval.assert_not_called()
            assert cb.stats["prompts_evaluated"] == 0

    def test_on_tool_start_evaluates_tool(self):
        cb = HestiaShieldCallback(api_key="test_key", strict=False)
        with patch.object(cb.client, "evaluate_tool_call") as mock_eval:
            mock_eval.return_value = HestiaDecision(
                allowed=True,
                decision="allow",
                risk_score=0.1,
                reason="Safe",
                details={},
            )
            cb.on_tool_start(
                serialized={"name": "read_file"},
                input_str="config.yaml",
            )
            assert cb.stats["tools_evaluated"] == 1
            assert cb.stats["tools_blocked"] == 0

    def test_on_tool_start_blocked_strict(self):
        cb = HestiaShieldCallback(api_key="test_key", strict=True)
        with patch.object(cb.client, "evaluate_tool_call") as mock_eval:
            mock_eval.return_value = HestiaDecision(
                allowed=False,
                decision="block",
                risk_score=0.9,
                reason="Tool blocked",
                details={},
            )
            with pytest.raises(HestiaSecurityError) as exc:
                cb.on_tool_start(
                    serialized={"name": "dangerous_tool"},
                    input_str="do_something",
                )
            assert exc.value.decision["tool_name"] == "dangerous_tool"
            assert cb.stats["tools_blocked"] == 1

    def test_on_tool_start_excluded_tool(self):
        cb = HestiaShieldCallback(
            api_key="test_key",
            strict=False,
            excluded_tools={"safe_tool"},
        )
        with patch.object(cb.client, "evaluate_tool_call") as mock_eval:
            cb.on_tool_start(
                serialized={"name": "safe_tool"},
                input_str="test",
            )
            mock_eval.assert_not_called()
            assert cb.stats["tools_evaluated"] == 0

    def test_on_tool_start_skipped_when_disabled(self):
        cb = HestiaShieldCallback(
            api_key="test_key", strict=False, evaluate_tools=False
        )
        with patch.object(cb.client, "evaluate_tool_call") as mock_eval:
            cb.on_tool_start(
                serialized={"name": "some_tool"},
                input_str="test",
            )
            mock_eval.assert_not_called()

    def test_block_on_error_enabled(self):
        cb = HestiaShieldCallback(
            api_key="test_key", strict=True, block_on_error=True
        )
        with patch.object(cb.client, "evaluate_prompt") as mock_eval:
            mock_eval.side_effect = ConnectionError("API unreachable")
            with pytest.raises(HestiaSecurityError) as exc:
                cb.on_llm_start(
                    serialized={"id": "gpt-4"},
                    prompts=["Test"],
                )
            assert "Hestia Shield unavailable" in exc.value.decision["reason"]

    def test_block_on_error_disabled(self):
        cb = HestiaShieldCallback(
            api_key="test_key", strict=True, block_on_error=False
        )
        with patch.object(cb.client, "evaluate_prompt") as mock_eval:
            mock_eval.side_effect = ConnectionError("API unreachable")
            cb.on_llm_start(
                serialized={"id": "gpt-4"},
                prompts=["Test"],
            )
            assert cb.stats["errors"] == 1

    def test_get_stats(self):
        cb = HestiaShieldCallback(api_key="test_key")
        stats = cb.get_stats()
        assert "prompts_evaluated" in stats
        assert "tools_evaluated" in stats
        assert "prompts_blocked" in stats
        assert "tools_blocked" in stats
        assert "errors" in stats

    def test_on_chain_start_end_noop(self):
        cb = HestiaShieldCallback(api_key="test_key")
        cb.on_chain_start({"id": "test"}, {"input": "test"})
        cb.on_chain_end({"output": "test"})
        cb.on_llm_end(MagicMock())
        cb.on_tool_end("output")
