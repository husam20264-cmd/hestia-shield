"""
Plugin loader for Hestia Shield.

Discovers and loads plugins from a configurable directory.
"""

import importlib.util
import logging
import os
from pathlib import Path
from typing import List, Optional

from .api import Plugin
from .registry import PluginRegistry

logger = logging.getLogger(__name__)


class PluginLoader:
    """
    Discovers and loads Hestia Shield plugins from a directory.

    Usage:
        loader = PluginLoader("/path/to/plugins")
        registry = PluginRegistry()
        loaded = loader.load_all(registry)
    """

    def __init__(self, plugin_dir: Optional[str] = None):
        self.plugin_dir = plugin_dir or os.getenv(
            "HESTIA_PLUGIN_DIR", "/etc/hestia/plugins"
        )

    def discover(self) -> List[Path]:
        plugin_path = Path(self.plugin_dir)
        if not plugin_path.exists() or not plugin_path.is_dir():
            logger.debug("Plugin directory does not exist: %s", self.plugin_dir)
            return []
        return [
            f for f in sorted(plugin_path.glob("*.py"))
            if not f.name.startswith("_")
        ]

    def load_plugin(self, plugin_file: Path) -> Optional[Plugin]:
        try:
            spec = importlib.util.spec_from_file_location(
                f"hestia_plugin_{plugin_file.stem}", plugin_file
            )
            if spec is None or spec.loader is None:
                logger.warning("Cannot load spec for %s", plugin_file)
                return None

            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

            for attr_name in dir(mod):
                obj = getattr(mod, attr_name)
                if (
                    isinstance(obj, type)
                    and issubclass(obj, Plugin)
                    and obj is not Plugin
                ):
                    plugin = obj()
                    logger.info(
                        "Loaded plugin: %s v%s from %s",
                        plugin.name, plugin.version, plugin_file,
                    )
                    return plugin

            logger.warning("No Plugin subclass found in %s", plugin_file)
            return None

        except Exception as e:
            logger.error("Failed to load plugin from %s: %s", plugin_file, e)
            return None

    def load_all(self, registry: PluginRegistry) -> List[Plugin]:
        loaded: List[Plugin] = []
        for plugin_file in self.discover():
            plugin = self.load_plugin(plugin_file)
            if plugin is not None:
                try:
                    registry.register(plugin)
                    loaded.append(plugin)
                except Exception as e:
                    logger.error(
                        "Failed to register plugin from %s: %s", plugin_file, e
                    )
        return loaded
