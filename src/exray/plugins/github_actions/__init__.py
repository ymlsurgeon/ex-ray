"""GitHub Actions workflow scanner plugin."""

from .scanner import GitHubActionsPlugin

PLUGIN_CLASS = GitHubActionsPlugin

__all__ = ["GitHubActionsPlugin", "PLUGIN_CLASS"]
