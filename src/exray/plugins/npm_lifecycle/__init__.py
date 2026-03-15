"""NPM lifecycle script scanner plugin."""

from .scanner import NpmLifecyclePlugin

# Plugin class exposed for orchestrator discovery
PLUGIN_CLASS = NpmLifecyclePlugin

__all__ = ["NpmLifecyclePlugin", "PLUGIN_CLASS"]
