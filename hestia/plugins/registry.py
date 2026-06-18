"""
Plugin registry for Hestia Shield.

Central registry that holds all loaded plugins and executes hooks.
"""

import logging
from typing import Any, Dict, List, Optional

from .api import Plugin
from .hooks import HOOK_ON_LOAD, HOOK_ON_SHUTDOWN

logger = logging.getLogger(__name__)


class PluginRegistry:
    """
    Central registry for Hestia Shield plugins.

    Manages plugin lifecycle (register/unregister) and executes hooks
    across all registered plugins.

    Usage:
        registry = PluginRegistry()
        registry.register(MyPlugin())
        results = registry.execute_hooks("pre_decision", prompt="test", context={})
    """

    def __init__(self):
        self._plugins: Dict[str, Plugin] = {}

    def register(self, plugin: Plugin) -> None:
        if not plugin.name:
            raise ValueError("Plugin must have a non-empty name")
        if plugin.name in self._plugins:
            logger.warning("Overwriting existing plugin: %s", plugin.name)
        self._plugins[plugin.name] = plugin
        self._call_hooks(plugin, HOOK_ON_LOAD)
        logger.info("Plugin registered: %s v%s", plugin.name, plugin.version)

    def unregister(self, name: str) -> Optional[Plugin]:
        plugin = self._plugins.pop(name, None)
        if plugin:
            self._call_hooks(plugin, HOOK_ON_SHUTDOWN)
            logger.info("Plugin unregistered: %s", name)
        return plugin

    def get_plugin(self, name: str) -> Optional[Plugin]:
        return self._plugins.get(name)

    def list_plugins(self) -> List[Dict[str, Any]]:
        return [p.to_dict() for p in self._plugins.values()]

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_plugins": len(self._plugins),
            "plugins": [{"name": p.name, "version": p.version, "enabled": p.enabled} for p in self._plugins.values()],
        }

    def execute_hooks(
        self, hook_name: str, **context: Any
    ) -> List[Dict[str, Any]]:
        """
        Execute all registered handlers for a given hook across all plugins.

        Each handler receives the context as keyword arguments.
        Returns a list of result dicts (non-None return values).

        If a handler raises, the error is logged and other handlers continue.
        """
        results: List[Dict[str, Any]] = []
        for plugin_name, plugin in self._plugins.items():
            if not plugin.enabled:
                continue
            for hook_fn in plugin.get_hooks(hook_name):
                try:
                    result = hook_fn(**context)
                    if result:
                        results.append({
                            "plugin": plugin_name,
                            "hook": hook_name,
                            "handler": hook_fn.__name__,
                            "result": result,
                        })
                except Exception as e:
                    logger.error(
                        "Plugin '%s' hook '%s' handler '%s' failed: %s",
                        plugin_name, hook_name, hook_fn.__name__, e,
                    )
        return results

    def _call_hooks(self, plugin: Plugin, hook_name: str) -> None:
        if not plugin.enabled:
            return
        for hook_fn in plugin.get_hooks(hook_name):
            try:
                hook_fn()
            except Exception as e:
                logger.error(
                    "Plugin '%s' lifecycle hook '%s' failed: %s",
                    plugin.name, hook_name, e,
                )
