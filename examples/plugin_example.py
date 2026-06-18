"""
Example Hestia Shield Plugin — Custom Block Keyword Detector

Demonstrates the Plugin API by implementing a plugin that blocks prompts
containing forbidden keywords.

Usage:
    from hestia.plugins import PluginRegistry

    registry = PluginRegistry()
    registry.register(CustomBlockPlugin())

    # Test a prompt
    results = registry.execute_hooks("pre_decision", prompt="run forbidden command", context={})
    print(results)  # -> [{'plugin': 'Custom Block', 'hook': 'pre_decision', ...}]
"""

from hestia.plugins import Plugin, hook


class CustomBlockPlugin(Plugin):
    name = "Custom Block"
    version = "1.0.0"
    description = "Blocks prompts containing forbidden keywords"

    def __init__(self, config=None):
        super().__init__(config)
        self.forbidden_keywords = config.get("forbidden_keywords", [
            "forbidden",
            "malicious",
            "exploit",
            "bypass",
        ])

    @hook("pre_decision")
    def block_forbidden_keywords(self, prompt: str, context: dict) -> dict:
        for kw in self.forbidden_keywords:
            if kw in prompt.lower():
                return {
                    "decision": "block",
                    "reason": f"Custom plugin blocked: prompt contains forbidden keyword '{kw}'",
                    "details": {"keyword": kw},
                }
        return {}

    @hook("post_decision")
    def log_blocked(self, decision: dict, prompt: str) -> None:
        if decision.get("decision") == "block":
            pass

    @hook("on_load")
    def on_load(self) -> None:
        pass

    @hook("on_shutdown")
    def on_shutdown(self) -> None:
        pass
