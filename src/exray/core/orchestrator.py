"""Orchestrator for coordinating plugin execution and aggregating results."""

import importlib
import logging
import time
from pathlib import Path

from .models import ScanResult

logger = logging.getLogger(__name__)


class Orchestrator:
    """Coordinates plugin execution and aggregates scan results."""

    # Plugin registry (hardcoded for MVP)
    PLUGIN_REGISTRY = {
        "npm-lifecycle": "exray.plugins.npm_lifecycle",
        "vscode-tasks": "exray.plugins.vscode_tasks",
        "github-actions": "exray.plugins.github_actions",
    }

    def __init__(self):
        """Initialize orchestrator and load plugins."""
        self.plugins = {}
        self._load_plugins()

    def _load_plugins(self) -> None:
        """
        Load all registered plugins.

        Plugins are discovered via the PLUGIN_REGISTRY. Each plugin module
        must expose a PLUGIN_CLASS variable pointing to the scanner class.
        """
        for name, module_path in self.PLUGIN_REGISTRY.items():
            try:
                module = importlib.import_module(module_path)
                plugin_class = getattr(module, "PLUGIN_CLASS")
                self.plugins[name] = plugin_class()
                logger.info(f"Loaded plugin: {name}")
            except Exception as e:
                logger.error(f"Failed to load plugin {name}: {e}")
                # Continue loading other plugins

    def scan(
        self, target_path: Path, plugin_filter: list[str] | None = None
    ) -> ScanResult:
        """
        Run scan with all (or filtered) plugins.

        Args:
            target_path: Directory to scan
            plugin_filter: Optional list of plugin names to run (None = all)

        Returns:
            Aggregated ScanResult with findings from all plugins
        """
        start_time = time.time()
        all_findings = []
        plugins_run = []
        all_scanned: list[str] = []

        # Determine which plugins to run
        if plugin_filter:
            plugins_to_run = {
                name: plugin
                for name, plugin in self.plugins.items()
                if name in plugin_filter
            }
            # Warn about unknown plugins
            for name in plugin_filter:
                if name not in self.plugins:
                    logger.warning(f"Plugin '{name}' not found, skipping")
        else:
            plugins_to_run = self.plugins

        # Run each plugin
        for name, plugin in plugins_to_run.items():
            try:
                logger.info(f"Running plugin: {name}")
                findings = plugin.scan(target_path)
                all_findings.extend(findings)
                plugins_run.append(name)
                logger.info(f"Plugin {name} found {len(findings)} issue(s)")
                for path in getattr(plugin, "scanned_files", []):
                    try:
                        all_scanned.append(str(path.relative_to(target_path)))
                    except ValueError:
                        all_scanned.append(str(path))
            except Exception as e:
                logger.error(f"Plugin {name} failed: {e}")
                # Continue with other plugins (per DEC-009)

        # Calculate summary
        summary = self._calculate_summary(all_findings)

        # Calculate duration
        duration = time.time() - start_time

        return ScanResult(
            target_path=target_path,
            findings=all_findings,
            plugins_run=plugins_run,
            scanned_files=sorted(set(all_scanned)),
            scan_duration_seconds=round(duration, 2),
            summary=summary,
        )

    def _calculate_summary(self, findings: list) -> dict[str, int]:
        """
        Calculate severity summary from findings.

        Args:
            findings: List of Finding objects

        Returns:
            Dictionary with counts per severity level plus total
        """
        summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "total": len(findings),
        }

        for finding in findings:
            summary[finding.severity.value] += 1

        return summary

    def list_plugins(self) -> list[dict]:
        """
        Get metadata for all loaded plugins.

        Returns:
            List of plugin metadata dictionaries
        """
        return [plugin.get_metadata() for plugin in self.plugins.values()]
