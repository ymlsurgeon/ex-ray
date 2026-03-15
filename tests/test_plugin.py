"""Tests for plugin base class."""

from pathlib import Path

import pytest

from exray.core.models import Finding, Severity
from exray.core.plugin import BasePlugin


class TestBasePlugin:
    """Tests for BasePlugin abstract base class."""

    def test_cannot_instantiate_base_plugin_directly(self):
        """Test that BasePlugin cannot be instantiated directly."""
        with pytest.raises(TypeError) as exc_info:
            BasePlugin()

        assert "abstract" in str(exc_info.value).lower()

    def test_subclass_must_implement_scan(self):
        """Test that subclass must implement scan() method."""

        class IncompletePlugin(BasePlugin):
            def get_metadata(self) -> dict:
                return {}

            def get_supported_files(self) -> list[str]:
                return []

        with pytest.raises(TypeError) as exc_info:
            IncompletePlugin()

        assert "abstract" in str(exc_info.value).lower()

    def test_subclass_must_implement_get_metadata(self):
        """Test that subclass must implement get_metadata() method."""

        class IncompletePlugin(BasePlugin):
            def scan(self, target_path: Path) -> list[Finding]:
                return []

            def get_supported_files(self) -> list[str]:
                return []

        with pytest.raises(TypeError) as exc_info:
            IncompletePlugin()

        assert "abstract" in str(exc_info.value).lower()

    def test_subclass_must_implement_get_supported_files(self):
        """Test that subclass must implement get_supported_files() method."""

        class IncompletePlugin(BasePlugin):
            def scan(self, target_path: Path) -> list[Finding]:
                return []

            def get_metadata(self) -> dict:
                return {}

        with pytest.raises(TypeError) as exc_info:
            IncompletePlugin()

        assert "abstract" in str(exc_info.value).lower()

    def test_fully_implemented_plugin_works(self):
        """Test that a fully implemented plugin can be instantiated."""

        class CompletePlugin(BasePlugin):
            def scan(self, target_path: Path) -> list[Finding]:
                return []

            def get_metadata(self) -> dict:
                return {
                    "name": "test-plugin",
                    "version": "1.0.0",
                    "author": "Test Author",
                    "description": "Test plugin",
                }

            def get_supported_files(self) -> list[str]:
                return ["*.test"]

        # Should not raise any errors
        plugin = CompletePlugin()

        assert plugin is not None
        assert isinstance(plugin, BasePlugin)

    def test_plugin_scan_method_signature(self):
        """Test that scan() has correct signature."""

        class TestPlugin(BasePlugin):
            def scan(self, target_path: Path) -> list[Finding]:
                return []

            def get_metadata(self) -> dict:
                return {}

            def get_supported_files(self) -> list[str]:
                return []

        plugin = TestPlugin()
        result = plugin.scan(Path("."))

        assert isinstance(result, list)

    def test_plugin_get_metadata_returns_dict(self):
        """Test that get_metadata() returns a dict."""

        class TestPlugin(BasePlugin):
            def scan(self, target_path: Path) -> list[Finding]:
                return []

            def get_metadata(self) -> dict:
                return {
                    "name": "test",
                    "version": "1.0",
                    "author": "author",
                    "description": "desc",
                }

            def get_supported_files(self) -> list[str]:
                return []

        plugin = TestPlugin()
        metadata = plugin.get_metadata()

        assert isinstance(metadata, dict)
        assert "name" in metadata
        assert "version" in metadata
        assert "author" in metadata
        assert "description" in metadata

    def test_plugin_get_supported_files_returns_list(self):
        """Test that get_supported_files() returns a list."""

        class TestPlugin(BasePlugin):
            def scan(self, target_path: Path) -> list[Finding]:
                return []

            def get_metadata(self) -> dict:
                return {}

            def get_supported_files(self) -> list[str]:
                return ["package.json", "*.js"]

        plugin = TestPlugin()
        files = plugin.get_supported_files()

        assert isinstance(files, list)
        assert len(files) == 2
        assert all(isinstance(f, str) for f in files)

    def test_plugin_with_findings(self):
        """Test plugin that returns actual findings."""

        class TestPlugin(BasePlugin):
            def scan(self, target_path: Path) -> list[Finding]:
                return [
                    Finding(
                        rule_id="TEST-001",
                        rule_name="Test Finding",
                        severity=Severity.HIGH,
                        file_path=Path("test.txt"),
                        matched_content="suspicious",
                        description="Test description",
                        recommendation="Test recommendation",
                        plugin_name="test-plugin",
                    )
                ]

            def get_metadata(self) -> dict:
                return {"name": "test", "version": "1.0", "author": "a", "description": "d"}

            def get_supported_files(self) -> list[str]:
                return ["*.txt"]

        plugin = TestPlugin()
        findings = plugin.scan(Path("."))

        assert len(findings) == 1
        assert isinstance(findings[0], Finding)
        assert findings[0].rule_id == "TEST-001"
