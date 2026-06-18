"""
Hook definitions for the Hestia Shield Plugin System.

Defines available hook points and the `hook` decorator for marking
plugin methods as hook handlers.
"""

from typing import Callable, Dict, Any

HOOK_PRE_DECISION = "pre_decision"
HOOK_POST_DECISION = "post_decision"
HOOK_ALERT = "alert"
HOOK_POLICY_GENERATION = "policy_generation"
HOOK_ON_LOAD = "on_load"
HOOK_ON_SHUTDOWN = "on_shutdown"

HOOK_DESCRIPTIONS: Dict[str, str] = {
    HOOK_PRE_DECISION: "Called before a security decision is made. Return a dict to override the decision.",
    HOOK_POST_DECISION: "Called after a decision is made. Can log or augment the decision.",
    HOOK_ALERT: "Called when an alert is fired. Receives alert data.",
    HOOK_POLICY_GENERATION: "Called when adaptive policy is generated. Can modify policy rules.",
    HOOK_ON_LOAD: "Called when the plugin is loaded (registered).",
    HOOK_ON_SHUTDOWN: "Called when the plugin is unloaded (unregistered).",
}

_AVAILABLE_HOOKS = frozenset([
    HOOK_PRE_DECISION,
    HOOK_POST_DECISION,
    HOOK_ALERT,
    HOOK_POLICY_GENERATION,
    HOOK_ON_LOAD,
    HOOK_ON_SHUTDOWN,
])


def hook(hook_name: str) -> Callable:
    """
    Decorator that marks a Plugin method as a handler for the given hook.

    Args:
        hook_name: One of the HOOK_* constants from this module.

    Usage:
        class MyPlugin(Plugin):
            @hook("pre_decision")
            def my_handler(self, prompt: str, context: dict) -> dict:
                ...
    """
    if hook_name not in _AVAILABLE_HOOKS:
        raise ValueError(
            f"Unknown hook '{hook_name}'. "
            f"Available hooks: {', '.join(sorted(_AVAILABLE_HOOKS))}"
        )

    def decorator(func: Callable) -> Callable:
        func._hestia_hook = hook_name
        return func

    return decorator
