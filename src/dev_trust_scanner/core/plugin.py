"""Base plugin interface for scanner plugins."""

from abc import ABC, abstractmethod
from pathlib import Path

from .models import Finding


class BasePlugin(ABC):
    """
    Abstract base class for all scanner plugins.

    Plugins must implement three methods to define their scanning behavior,
    metadata, and supported file patterns.
    """

    def __init__(self):
        """Initialize base plugin state."""
        self.scanned_files: list[Path] = []

    @abstractmethod
    def scan(self, target_path: Path) -> list[Finding]:
        """
        Run detection logic against target directory.

        This method should:
        1. Find relevant files in target_path
        2. Parse/analyze file contents
        3. Apply detection rules
        4. Return list of findings

        Important: This method should catch all exceptions and return
        partial results rather than crashing. Log errors appropriately.

        Args:
            target_path: Root directory to scan

        Returns:
            List of Finding objects (may be empty if no issues found)

        Example:
            ```python
            def scan(self, target_path: Path) -> list[Finding]:
                findings = []
                try:
                    for file in target_path.rglob("package.json"):
                        findings.extend(self._scan_file(file))
                except Exception as e:
                    logger.error(f"Scan error: {e}")
                return findings
            ```
        """
        ...

    @abstractmethod
    def get_metadata(self) -> dict:
        """
        Return plugin metadata.

        Returns:
            Dictionary with keys:
            - name (str): Plugin name (e.g., "npm-lifecycle")
            - version (str): Plugin version (e.g., "0.1.0")
            - author (str): Plugin author
            - description (str): Brief description of what plugin detects

        Example:
            ```python
            def get_metadata(self) -> dict:
                return {
                    "name": "npm-lifecycle",
                    "version": "0.1.0",
                    "author": "Dev Trust Scanner",
                    "description": "Detects malicious npm lifecycle scripts"
                }
            ```
        """
        ...

    @abstractmethod
    def get_supported_files(self) -> list[str]:
        """
        Return glob patterns for files this plugin inspects.

        Used by orchestrator to determine which plugins to run based on
        files present in the target directory.

        Returns:
            List of glob patterns (e.g., ['package.json'], ['.vscode/tasks.json'])

        Example:
            ```python
            def get_supported_files(self) -> list[str]:
                return ["package.json"]
            ```
        """
        ...
