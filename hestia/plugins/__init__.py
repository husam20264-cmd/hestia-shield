"""
Hestia Shield — Plugin System

Extend Hestia Shield with custom security rules, detectors, policy generators,
and alert channels via a standard plugin API.

Usage:
    from hestia.plugins import Plugin, hook, PluginRegistry

    class MyPlugin(Plugin):
        name = "My Plugin"
        version = "1.0.0"

        @hook("pre_decision")
        def block_forbidden(self, prompt: str, context: dict) -> dict:
            if "forbidden" in prompt.lower():
                return {"decision": "block", "reason": "Blocked by plugin"}
            return {}

    registry = PluginRegistry()
    registry.register(MyPlugin())
    results = registry.execute_hooks("pre_decision", prompt="test", context={})
"""

from .api import Plugin
from .hooks import hook
from .registry import PluginRegistry
from .loader import PluginLoader

__all__ = [
    "Plugin",
    "hook",
    "PluginRegistry",
    "PluginLoader",
]
