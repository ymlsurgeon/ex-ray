"""Tests for orchestrator."""

from dev_trust_scanner.core.orchestrator import Orchestrator


class TestOrchestrator:
    """Tests for scan orchestration."""

    def test_orchestrator_loads_plugins(self):
        """Test that orchestrator loads all registered plugins."""
        orchestrator = Orchestrator()

        assert len(orchestrator.plugins) == 3  # npm-lifecycle, vscode-tasks, and github-actions
        assert "npm-lifecycle" in orchestrator.plugins
        assert "vscode-tasks" in orchestrator.plugins
        assert "github-actions" in orchestrator.plugins

    def test_list_plugins(self):
        """Test listing plugin metadata."""
        orchestrator = Orchestrator()
        plugins = orchestrator.list_plugins()

        assert len(plugins) == 3
        assert all("name" in p for p in plugins)
        assert all("version" in p for p in plugins)

    def test_scan_with_all_plugins(self, clean_npm_package):
        """Test scanning with all plugins."""
        orchestrator = Orchestrator()
        result = orchestrator.scan(clean_npm_package)

        assert result.target_path == clean_npm_package
        assert len(result.plugins_run) == 3  # All plugins ran
        assert "npm-lifecycle" in result.plugins_run
        assert "vscode-tasks" in result.plugins_run
        assert "github-actions" in result.plugins_run
        assert result.scan_duration_seconds >= 0
        assert result.summary["total"] == 0  # Clean package

    def test_scan_with_plugin_filter(self, clean_npm_package):
        """Test scanning with specific plugin only."""
        orchestrator = Orchestrator()
        result = orchestrator.scan(clean_npm_package, plugin_filter=["npm-lifecycle"])

        assert len(result.plugins_run) == 1
        assert result.plugins_run[0] == "npm-lifecycle"

    def test_scan_with_malicious_content(self, malicious_npm_eval):
        """Test scanning malicious content produces findings."""
        orchestrator = Orchestrator()
        result = orchestrator.scan(malicious_npm_eval)

        assert result.summary["total"] > 0
        assert len(result.findings) > 0

    def test_scan_with_monorepo(self, npm_monorepo):
        """Test scanning monorepo."""
        orchestrator = Orchestrator()
        result = orchestrator.scan(npm_monorepo)

        # Should find issues in malicious package
        assert result.summary["total"] > 0

    def test_scan_with_contagious_interview(self, contagious_interview_task):
        """Test scanning Contagious Interview attack."""
        orchestrator = Orchestrator()
        result = orchestrator.scan(contagious_interview_task)

        assert result.summary["total"] > 0
        assert result.summary["critical"] > 0  # VSC-001

    def test_summary_calculation(self, malicious_npm_eval, contagious_interview_task):
        """Test that summary counts are correct."""
        # Create a project with both npm and vscode issues
        (malicious_npm_eval / ".vscode").mkdir(exist_ok=True)
        (malicious_npm_eval / ".vscode" / "tasks.json").write_text(
            (contagious_interview_task / ".vscode" / "tasks.json").read_text()
        )

        orchestrator = Orchestrator()
        result = orchestrator.scan(malicious_npm_eval)

        # Verify summary counts match actual findings
        assert result.summary["total"] == len(result.findings)

        # Count findings by severity manually
        manual_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in result.findings:
            manual_count[finding.severity.value] += 1

        assert result.summary["critical"] == manual_count["critical"]
        assert result.summary["high"] == manual_count["high"]
        assert result.summary["medium"] == manual_count["medium"]
        assert result.summary["low"] == manual_count["low"]

    def test_scan_empty_directory(self, tmp_path):
        """Test scanning empty directory."""
        orchestrator = Orchestrator()
        result = orchestrator.scan(tmp_path)

        assert result.summary["total"] == 0
        assert len(result.findings) == 0
        assert len(result.plugins_run) == 3  # All plugins still ran

    def test_unknown_plugin_filter(self, clean_npm_package):
        """Test filtering with unknown plugin name."""
        orchestrator = Orchestrator()
        result = orchestrator.scan(
            clean_npm_package, plugin_filter=["unknown-plugin"]
        )

        assert len(result.plugins_run) == 0  # No plugins ran

    def test_mixed_plugin_filter(self, clean_npm_package):
        """Test filter with mix of known and unknown plugins."""
        orchestrator = Orchestrator()
        result = orchestrator.scan(
            clean_npm_package, plugin_filter=["npm-lifecycle", "unknown-plugin"]
        )

        assert len(result.plugins_run) == 1
        assert result.plugins_run[0] == "npm-lifecycle"
