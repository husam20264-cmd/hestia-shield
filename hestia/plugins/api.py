"""
Plugin base class for Hestia Shield.

All plugins must subclass `Plugin` and set `name` and `version`.
Hook handlers are registered via the `@hook` decorator.
"""

import logging
from typing import Any, Dict, List, Optional, Callable

from .hooks import HOOK_ON_LOAD, HOOK_ON_SHUTDOWN

logger = logging.getLogger(__name__)


class Plugin:
    """
    Base class for all Hestia Shield plugins.

    Subclasses must set `name` and `version`. Optionally set `description`.
    Decorate methods with `@hook("hook_name")` to register handlers.

    Usage:
        from hestia.plugins import Plugin, hook

        class MyPlugin(Plugin):
            name = "MyPlugin"
            version = "1.0.0"

            @hook("pre_decision")
            def on_pre_decision(self, prompt: str, context: dict) -> dict:
                ...
    """

    name: str = ""
    version: str = ""
    description: str = ""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._hook_map: Dict[str, List[Callable]] = {}
        self._enabled = True
        self._register_hooks()

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = value

    def _register_hooks(self) -> None:
        for attr_name in dir(self):
            method = getattr(self, attr_name, None)
            if method is None:
                continue
            hook_name = getattr(method, "_hestia_hook", None)
            if hook_name:
                if hook_name not in self._hook_map:
                    self._hook_map[hook_name] = []
                self._hook_map[hook_name].append(method)

    def get_hooks(self, hook_name: str) -> List[Callable]:
        return self._hook_map.get(hook_name, [])

    def get_registered_hooks(self) -> Dict[str, List[str]]:
        return {
            hook_name: [fn.__name__ for fn in fns]
            for hook_name, fns in self._hook_map.items()
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "enabled": self._enabled,
            "hooks": self.get_registered_hooks(),
        }
