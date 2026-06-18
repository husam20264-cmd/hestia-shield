"""
Tests for Hestia Shield — Plugin System (v1.7.0)
"""

import pytest
import tempfile
import os
from pathlib import Path

from hestia.plugins import Plugin, hook, PluginRegistry, PluginLoader
from hestia.plugins.hooks import (
    HOOK_PRE_DECISION,
    HOOK_POST_DECISION,
    HOOK_ALERT,
    HOOK_POLICY_GENERATION,
    HOOK_ON_LOAD,
    HOOK_ON_SHUTDOWN,
    _AVAILABLE_HOOKS,
)


# ---------------------------------------------------------------------------
# Test plugin implementations
# ---------------------------------------------------------------------------

class PreDecisionPlugin(Plugin):
    name = "PreDecision"
    version = "1.0.0"

    @hook(HOOK_PRE_DECISION)
    def block_forbidden(self, prompt: str, context: dict) -> dict:
        if "forbidden" in prompt.lower():
            return {"decision": "block", "reason": "Blocked by test plugin"}
        return {}


class PostDecisionPlugin(Plugin):
    name = "PostDecision"
    version = "1.0.0"

    def __init__(self, config=None):
        super().__init__(config)
        self.logged_decisions = []

    @hook(HOOK_POST_DECISION)
    def log_decision(self, decision: dict, prompt: str) -> dict:
        self.logged_decisions.append({"decision": decision, "prompt": prompt})
        return {"logged": True}


class AlertPlugin(Plugin):
    name = "AlertHandler"
    version = "1.0.0"

    def __init__(self, config=None):
        super().__init__(config)
        self.alerts_received = []

    @hook(HOOK_ALERT)
    def on_alert(self, alert: dict) -> dict:
        self.alerts_received.append(alert)
        return {"handled": True}


class PolicyPlugin(Plugin):
    name = "PolicyGen"
    version = "1.0.0"

    @hook(HOOK_POLICY_GENERATION)
    def modify_policy(self, policy: dict) -> dict:
        return {"modified": True, "original": policy}


class LifecyclePlugin(Plugin):
    name = "Lifecycle"
    version = "1.0.0"

    def __init__(self, config=None):
        super().__init__(config)
        self.loaded = False
        self.shutdown = False

    @hook(HOOK_ON_LOAD)
    def on_load(self) -> None:
        self.loaded = True

    @hook(HOOK_ON_SHUTDOWN)
    def on_shutdown(self) -> None:
        self.shutdown = True


class MultiHookPlugin(Plugin):
    name = "MultiHook"
    version = "1.0.0"

    def __init__(self, config=None):
        super().__init__(config)
        self.calls = []

    @hook(HOOK_PRE_DECISION)
    def hook1(self, prompt: str, context: dict) -> dict:
        self.calls.append(("pre_decision", prompt))
        return {"hook1": True}

    @hook(HOOK_POST_DECISION)
    def hook2(self, decision: dict, prompt: str) -> dict:
        self.calls.append(("post_decision", prompt))
        return {"hook2": True}

    @hook(HOOK_ALERT)
    def hook3(self, alert: dict) -> dict:
        self.calls.append(("alert", alert.get("rule", "")))
        return {"hook3": True}


class ErrorPlugin(Plugin):
    name = "ErrorPlugin"
    version = "1.0.0"

    @hook(HOOK_PRE_DECISION)
    def failing_hook(self, prompt: str, context: dict) -> dict:
        raise RuntimeError("Something went wrong")


class NoHookPlugin(Plugin):
    name = "NoHook"
    version = "1.0.0"
    description = "No hooks registered"

    def utility_method(self) -> str:
        return "not a hook"


class DisabledPlugin(Plugin):
    name = "Disabled"
    version = "1.0.0"

    def __init__(self, config=None):
        super().__init__(config)
        self.enabled = False

    @hook(HOOK_PRE_DECISION)
    def never_called(self, prompt: str, context: dict) -> dict:
        return {"should_not_happen": True}


# ---------------------------------------------------------------------------
# Tests: Hook decorator
# ---------------------------------------------------------------------------

class TestHookDecorator:

    def test_valid_hook_name(self):
        @hook(HOOK_PRE_DECISION)
        def dummy():
            pass
        assert dummy._hestia_hook == HOOK_PRE_DECISION

    def test_invalid_hook_name_raises(self):
        with pytest.raises(ValueError, match="Unknown hook"):
            @hook("nonexistent_hook")
            def dummy():
                pass

    def test_all_hook_constants_available(self):
        assert HOOK_PRE_DECISION == "pre_decision"
        assert HOOK_POST_DECISION == "post_decision"
        assert HOOK_ALERT == "alert"
        assert HOOK_POLICY_GENERATION == "policy_generation"
        assert HOOK_ON_LOAD == "on_load"
        assert HOOK_ON_SHUTDOWN == "on_shutdown"


# ---------------------------------------------------------------------------
# Tests: Plugin base class
# ---------------------------------------------------------------------------

class TestPluginAPI:

    def test_plugin_base_requires_name(self):
        with pytest.raises(ValueError, match="non-empty name"):
            registry = PluginRegistry()
            plugin = Plugin()
            registry.register(plugin)

    def test_plugin_registers_hooks(self):
        plugin = PreDecisionPlugin()
        hooks = plugin.get_hooks(HOOK_PRE_DECISION)
        assert len(hooks) == 1
        assert hooks[0].__name__ == "block_forbidden"

    def test_plugin_no_hooks(self):
        plugin = NoHookPlugin()
        assert plugin.get_registered_hooks() == {}

    def test_plugin_to_dict(self):
        plugin = PreDecisionPlugin()
        d = plugin.to_dict()
        assert d["name"] == "PreDecision"
        assert d["version"] == "1.0.0"
        assert HOOK_PRE_DECISION in d["hooks"]

    def test_plugin_enabled_property(self):
        plugin = PreDecisionPlugin()
        assert plugin.enabled is True
        plugin.enabled = False
        assert plugin.enabled is False

    def test_plugin_with_config(self):
        plugin = PreDecisionPlugin(config={"threshold": 5})
        assert plugin.config["threshold"] == 5

    def test_plugin_get_registered_hooks(self):
        plugin = MultiHookPlugin()
        hooks = plugin.get_registered_hooks()
        assert HOOK_PRE_DECISION in hooks
        assert HOOK_POST_DECISION in hooks
        assert HOOK_ALERT in hooks
        assert len(hooks) == 3

    def test_multiple_hooks_same_type(self):
        class TwoHooksPlugin(Plugin):
            name = "TwoHooks"
            version = "1.0.0"

            @hook(HOOK_PRE_DECISION)
            def first(self, prompt: str, context: dict) -> dict:
                return {"first": True}

            @hook(HOOK_PRE_DECISION)
            def second(self, prompt: str, context: dict) -> dict:
                return {"second": True}

        plugin = TwoHooksPlugin()
        hooks = plugin.get_hooks(HOOK_PRE_DECISION)
        assert len(hooks) == 2


# ---------------------------------------------------------------------------
# Tests: PluginRegistry
# ---------------------------------------------------------------------------

class TestPluginRegistry:

    def test_register_and_list(self):
        registry = PluginRegistry()
        registry.register(PreDecisionPlugin())
        plugins = registry.list_plugins()
        assert len(plugins) == 1
        assert plugins[0]["name"] == "PreDecision"

    def test_unregister(self):
        registry = PluginRegistry()
        registry.register(PreDecisionPlugin())
        assert len(registry.list_plugins()) == 1
        plugin = registry.unregister("PreDecision")
        assert plugin is not None
        assert len(registry.list_plugins()) == 0

    def test_unregister_nonexistent(self):
        registry = PluginRegistry()
        result = registry.unregister("nonexistent")
        assert result is None

    def test_get_plugin(self):
        registry = PluginRegistry()
        plugin = PreDecisionPlugin()
        registry.register(plugin)
        assert registry.get_plugin("PreDecision") is plugin
        assert registry.get_plugin("nonexistent") is None

    def test_get_stats(self):
        registry = PluginRegistry()
        registry.register(PreDecisionPlugin())
        stats = registry.get_stats()
        assert stats["total_plugins"] == 1
        assert stats["plugins"][0]["name"] == "PreDecision"

    def test_execute_pre_decision_hook_blocked(self):
        registry = PluginRegistry()
        registry.register(PreDecisionPlugin())
        results = registry.execute_hooks(
            HOOK_PRE_DECISION,
            prompt="this is forbidden content",
            context={"user": "test"},
        )
        assert len(results) == 1
        assert results[0]["plugin"] == "PreDecision"
        assert results[0]["result"]["decision"] == "block"

    def test_execute_pre_decision_hook_allowed(self):
        registry = PluginRegistry()
        registry.register(PreDecisionPlugin())
        results = registry.execute_hooks(
            HOOK_PRE_DECISION,
            prompt="safe content",
            context={},
        )
        assert len(results) == 0

    def test_execute_post_decision_hook(self):
        registry = PluginRegistry()
        plugin = PostDecisionPlugin()
        registry.register(plugin)
        results = registry.execute_hooks(
            HOOK_POST_DECISION,
            decision={"decision": "block", "risk_score": 0.9},
            prompt="test",
        )
        assert len(results) == 1
        assert results[0]["result"]["logged"] is True

    def test_execute_alert_hook(self):
        registry = PluginRegistry()
        plugin = AlertPlugin()
        registry.register(plugin)
        results = registry.execute_hooks(
            HOOK_ALERT,
            alert={"rule": "high_blocks", "severity": "critical"},
        )
        assert len(results) == 1
        assert results[0]["result"]["handled"] is True

    def test_execute_policy_generation_hook(self):
        registry = PluginRegistry()
        registry.register(PolicyPlugin())
        results = registry.execute_hooks(
            HOOK_POLICY_GENERATION,
            policy={"rules": []},
        )
        assert len(results) == 1
        assert results[0]["result"]["modified"] is True

    def test_lifecycle_hooks_called_on_register(self):
        registry = PluginRegistry()
        plugin = LifecyclePlugin()
        assert plugin.loaded is False
        registry.register(plugin)
        assert plugin.loaded is True

    def test_lifecycle_hooks_called_on_unregister(self):
        registry = PluginRegistry()
        plugin = LifecyclePlugin()
        registry.register(plugin)
        registry.unregister("Lifecycle")
        assert plugin.shutdown is True

    def test_disabled_plugin_not_executed(self):
        registry = PluginRegistry()
        registry.register(DisabledPlugin())
        results = registry.execute_hooks(
            HOOK_PRE_DECISION,
            prompt="test",
            context={},
        )
        assert len(results) == 0

    def test_multiple_plugins_same_hook(self):
        registry = PluginRegistry()
        registry.register(PreDecisionPlugin())

        class AnotherBlockPlugin(Plugin):
            name = "Another"
            version = "1.0.0"

            @hook(HOOK_PRE_DECISION)
            def also_block(self, prompt: str, context: dict) -> dict:
                if "bad" in prompt.lower():
                    return {"decision": "block", "reason": "Also blocked"}
                return {}

        registry.register(AnotherBlockPlugin())
        results = registry.execute_hooks(
            HOOK_PRE_DECISION,
            prompt="bad content",
            context={},
        )
        assert len(results) == 1

    def test_plugin_error_isolation(self):
        registry = PluginRegistry()
        registry.register(ErrorPlugin())
        registry.register(PreDecisionPlugin())
        results = registry.execute_hooks(
            HOOK_PRE_DECISION,
            prompt="forbidden content",
            context={},
        )
        assert len(results) == 1
        assert results[0]["plugin"] == "PreDecision"

    def test_register_overwrite_warning(self):
        registry = PluginRegistry()
        registry.register(PreDecisionPlugin())
        registry.register(PreDecisionPlugin())
        assert len(registry.list_plugins()) == 1

    def test_multi_hook_plugin(self):
        registry = PluginRegistry()
        plugin = MultiHookPlugin()
        registry.register(plugin)

        registry.execute_hooks(HOOK_PRE_DECISION, prompt="hello", context={})
        registry.execute_hooks(HOOK_POST_DECISION, decision={}, prompt="hello")
        registry.execute_hooks(HOOK_ALERT, alert={"rule": "test"})

        assert len(plugin.calls) == 3

    def test_empty_registry(self):
        registry = PluginRegistry()
        assert registry.list_plugins() == []
        assert registry.get_stats()["total_plugins"] == 0
        assert registry.execute_hooks(HOOK_PRE_DECISION, prompt="test", context={}) == []


# ---------------------------------------------------------------------------
# Tests: PluginLoader
# ---------------------------------------------------------------------------

SAMPLE_PLUGIN_CODE = '''
from hestia.plugins import Plugin, hook

class SamplePlugin(Plugin):
    name = "Sample"
    version = "1.0.0"
    description = "A test plugin loaded from file"

    @hook("pre_decision")
    def check(self, prompt: str, context: dict) -> dict:
        if "evil" in prompt:
            return {"decision": "block", "reason": "Evil detected"}
        return {}
'''

INVALID_PLUGIN_CODE = '''
# No Plugin subclass here
x = 42
'''

IMPORT_ERROR_PLUGIN = '''
from nonexistent_module import foo
'''


class TestPluginLoader:

    def test_discover_empty_directory(self, tmp_path: Path):
        loader = PluginLoader(str(tmp_path))
        discovered = loader.discover()
        assert discovered == []

    def test_discover_nonexistent_directory(self):
        loader = PluginLoader("/tmp/hestia_nonexistent_plugins_xyz")
        discovered = loader.discover()
        assert discovered == []

    def test_discover_finds_py_files(self, tmp_path: Path):
        (tmp_path / "my_plugin.py").write_text("x = 1")
        (tmp_path / "other.py").write_text("y = 2")
        (tmp_path / "__init__.py").write_text("")
        loader = PluginLoader(str(tmp_path))
        discovered = loader.discover()
        names = [f.name for f in discovered]
        assert "my_plugin.py" in names
        assert "other.py" in names
        assert "__init__.py" not in names

    def test_load_valid_plugin(self, tmp_path: Path):
        plugin_file = tmp_path / "sample.py"
        plugin_file.write_text(SAMPLE_PLUGIN_CODE)
        loader = PluginLoader(str(tmp_path))
        plugin = loader.load_plugin(plugin_file)
        assert plugin is not None
        assert plugin.name == "Sample"
        assert plugin.version == "1.0.0"

    def test_load_invalid_plugin_no_subclass(self, tmp_path: Path):
        plugin_file = tmp_path / "invalid.py"
        plugin_file.write_text(INVALID_PLUGIN_CODE)
        loader = PluginLoader(str(tmp_path))
        plugin = loader.load_plugin(plugin_file)
        assert plugin is None

    def test_load_plugin_with_import_error(self, tmp_path: Path):
        plugin_file = tmp_path / "broken.py"
        plugin_file.write_text(IMPORT_ERROR_PLUGIN)
        loader = PluginLoader(str(tmp_path))
        plugin = loader.load_plugin(plugin_file)
        assert plugin is None

    def test_load_all_registers_plugins(self, tmp_path: Path):
        (tmp_path / "sample.py").write_text(SAMPLE_PLUGIN_CODE)
        registry = PluginRegistry()
        loader = PluginLoader(str(tmp_path))
        loaded = loader.load_all(registry)
        assert len(loaded) == 1
        assert loaded[0].name == "Sample"
        assert len(registry.list_plugins()) == 1

    def test_loaded_plugin_hooks_work(self, tmp_path: Path):
        (tmp_path / "sample.py").write_text(SAMPLE_PLUGIN_CODE)
        registry = PluginRegistry()
        loader = PluginLoader(str(tmp_path))
        loader.load_all(registry)

        results = registry.execute_hooks(
            HOOK_PRE_DECISION,
            prompt="evil command",
            context={},
        )
        assert len(results) == 1
        assert results[0]["result"]["decision"] == "block"

        safe_results = registry.execute_hooks(
            HOOK_PRE_DECISION,
            prompt="safe command",
            context={},
        )
        assert safe_results == []

    def test_loader_default_dir_from_env(self, monkeypatch):
        monkeypatch.setenv("HESTIA_PLUGIN_DIR", "/tmp/custom_plugins")
        loader = PluginLoader()
        assert loader.plugin_dir == "/tmp/custom_plugins"

    def test_loader_default_dir_fallback(self):
        loader = PluginLoader()
        assert loader.plugin_dir == "/etc/hestia/plugins"
