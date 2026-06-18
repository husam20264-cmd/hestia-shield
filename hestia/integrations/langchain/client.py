"""
Lightweight HTTP client for Hestia Shield API.

Used by framework integrations to evaluate prompts and tool calls.
"""

import os
import json
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass
from urllib.request import Request, urlopen
from urllib.error import URLError

logger = logging.getLogger(__name__)


class HestiaSecurityError(Exception):
    def __init__(self, decision: Dict[str, Any]):
        self.decision = decision
        super().__init__(decision.get("reason", "Blocked by Hestia Shield"))


@dataclass
class HestiaDecision:
    allowed: bool
    decision: str
    risk_score: float
    reason: str
    details: Dict[str, Any]

    @classmethod
    def from_dict(cls, data: Dict) -> "HestiaDecision":
        return cls(
            allowed=data.get("decision") == "allow",
            decision=data.get("decision", "allow"),
            risk_score=data.get("risk_score", 0.0),
            reason=data.get("reason", ""),
            details=data.get("details", {}),
        )


class HestiaAPIClient:
    def __init__(
        self,
        api_key: str,
        base_url: str = "",
        timeout: int = 5,
    ):
        self.api_key = api_key
        self.base_url = base_url or os.getenv(
            "HESTIA_API_URL", "http://localhost:8000"
        )
        self.timeout = timeout
        self._token: Optional[str] = None

    def _get_token(self) -> str:
        if self._token:
            return self._token
        try:
            req = Request(
                url=f"{self.base_url}/v1/token",
                data=json.dumps({"api_key": self.api_key}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode())
                self._token = data["token"]
                return self._token
        except URLError as e:
            raise ConnectionError(
                f"Cannot connect to Hestia Shield at {self.base_url}: {e}"
            )

    def evaluate_prompt(
        self,
        prompt: str,
        user_id: str = "langchain",
        model_id: Optional[str] = None,
    ) -> HestiaDecision:
        token = self._get_token()
        payload = {
            "prompt": prompt,
            "user_id": user_id,
            "model_id": model_id or "langchain",
        }
        try:
            req = Request(
                url=f"{self.base_url}/v1/decision/evaluate",
                data=json.dumps(payload).encode(),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {token}",
                },
                method="POST",
            )
            with urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode())
                return HestiaDecision.from_dict(data)
        except URLError as e:
            logger.warning("Hestia Shield evaluation failed: %s", e)
            return HestiaDecision(
                allowed=True,
                decision="allow",
                risk_score=0.0,
                reason="Hestia Shield unreachable — allowing by default",
                details={"error": str(e)},
            )

    def evaluate_tool_call(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        user_id: str = "langchain",
        agent_id: Optional[str] = None,
    ) -> HestiaDecision:
        token = self._get_token()
        payload = {
            "tool_call": {
                "name": tool_name,
                "arguments": tool_args,
                "category": self._infer_category(tool_name),
            },
            "user_id": user_id,
            "agent_id": agent_id or "langchain",
        }
        try:
            req = Request(
                url=f"{self.base_url}/v1/agent/tool-call/evaluate",
                data=json.dumps(payload).encode(),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {token}",
                },
                method="POST",
            )
            with urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode())
                return HestiaDecision.from_dict(data)
        except URLError as e:
            logger.warning("Hestia Shield tool evaluation failed: %s", e)
            return HestiaDecision(
                allowed=True,
                decision="allow",
                risk_score=0.0,
                reason="Hestia Shield unreachable — allowing by default",
                details={"error": str(e)},
            )

    def _infer_category(self, tool_name: str) -> str:
        name_lower = tool_name.lower()
        if any(kw in name_lower for kw in ["write", "create", "edit", "upload"]):
            return "write"
        if any(kw in name_lower for kw in ["read", "list", "get", "search", "view"]):
            return "read"
        if any(kw in name_lower for kw in ["exec", "shell", "run", "command"]):
            return "execute"
        if any(kw in name_lower for kw in ["delete", "remove", "rm"]):
            return "delete"
        if any(kw in name_lower for kw in ["send", "email", "http", "post"]):
            return "network"
        return "general"

    def health_check(self) -> bool:
        try:
            req = Request(url=f"{self.base_url}/health", method="GET")
            with urlopen(req, timeout=self.timeout) as resp:
                return resp.status == 200
        except URLError:
            return False
