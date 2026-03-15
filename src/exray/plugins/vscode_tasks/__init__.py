"""VS Code tasks scanner plugin."""

from .scanner import VsCodeTasksPlugin

# Plugin class exposed for orchestrator discovery
PLUGIN_CLASS = VsCodeTasksPlugin

__all__ = ["VsCodeTasksPlugin", "PLUGIN_CLASS"]
