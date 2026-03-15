"""Tests for output formatters."""

import json
from pathlib import Path

from rich.console import Console

from exray.core.models import Finding, ScanResult, Severity
from exray.core.reporting import JsonReporter, SarifReporter, TextReporter


class TestTextReporter:
    """Tests for text output formatter."""

    def test_text_report_no_findings(self, tmp_path):
        """Test text output with no findings."""
        result = ScanResult(
            target_path=tmp_path,
            scan_duration_seconds=1.5,
            summary={"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
        )

        console = Console(file=open("/dev/null", "w"))
        reporter = TextReporter(console=console)
        reporter.report(result)  # Should not crash

    def test_text_report_with_findings(self, tmp_path):
        """Test text output with findings."""
        findings = [
            Finding(
                rule_id="TEST-001",
                rule_name="Test Finding",
                severity=Severity.HIGH,
                file_path=Path("test.txt"),
                matched_content="malicious code",
                description="Test description",
                recommendation="Fix it",
                plugin_name="test-plugin",
            )
        ]

        result = ScanResult(
            target_path=tmp_path,
            findings=findings,
            plugins_run=["test-plugin"],
            scan_duration_seconds=2.0,
            summary={"critical": 0, "high": 1, "medium": 0, "low": 0, "total": 1},
        )

        console = Console(file=open("/dev/null", "w"))
        reporter = TextReporter(console=console)
        reporter.report(result)  # Should not crash


class TestJsonReporter:
    """Tests for JSON output formatter."""

    def test_json_report_valid(self, tmp_path):
        """Test JSON output is valid."""
        result = ScanResult(
            target_path=tmp_path,
            scan_duration_seconds=1.0,
            summary={"total": 0},
        )

        reporter = JsonReporter()
        output = reporter.report(result)

        # Should be valid JSON
        data = json.loads(output)
        assert "target_path" in data
        assert "findings" in data

    def test_json_report_with_findings(self, tmp_path):
        """Test JSON output with findings."""
        findings = [
            Finding(
                rule_id="TEST-001",
                rule_name="Test",
                severity=Severity.MEDIUM,
                file_path=Path("file.txt"),
                matched_content="content",
                description="desc",
                recommendation="rec",
                plugin_name="plugin",
            )
        ]

        result = ScanResult(
            target_path=tmp_path,
            findings=findings,
            plugins_run=["plugin"],
            scan_duration_seconds=1.5,
            summary={"total": 1},
        )

        reporter = JsonReporter()
        output = reporter.report(result)

        data = json.loads(output)
        assert len(data["findings"]) == 1
        assert data["findings"][0]["rule_id"] == "TEST-001"


class TestSarifReporter:
    """Tests for SARIF output formatter."""

    def test_sarif_structure(self, tmp_path):
        """Test SARIF output has correct structure."""
        result = ScanResult(
            target_path=tmp_path,
            scan_duration_seconds=1.0,
            summary={"total": 0},
        )

        reporter = SarifReporter()
        output = reporter.report(result)

        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert "$schema" in data
        assert "runs" in data
        assert len(data["runs"]) == 1

    def test_sarif_with_findings(self, tmp_path):
        """Test SARIF output with findings."""
        findings = [
            Finding(
                rule_id="TEST-001",
                rule_name="Test",
                severity=Severity.HIGH,
                file_path=Path("file.txt"),
                line_number=42,
                matched_content="content",
                description="Test description",
                recommendation="rec",
                plugin_name="plugin",
            )
        ]

        result = ScanResult(
            target_path=tmp_path,
            findings=findings,
            plugins_run=["plugin"],
            scan_duration_seconds=1.0,
            summary={"total": 1},
        )

        reporter = SarifReporter()
        output = reporter.report(result)

        data = json.loads(output)
        results = data["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "TEST-001"
        assert results[0]["level"] == "error"  # HIGH = error
        assert results[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 42

    def test_sarif_severity_mapping(self, tmp_path):
        """Test SARIF severity mapping."""
        findings = [
            Finding(
                rule_id="CRIT",
                rule_name="Critical",
                severity=Severity.CRITICAL,
                file_path=Path("f"),
                matched_content="c",
                description="d",
                recommendation="r",
                plugin_name="p",
            ),
            Finding(
                rule_id="MED",
                rule_name="Medium",
                severity=Severity.MEDIUM,
                file_path=Path("f"),
                matched_content="c",
                description="d",
                recommendation="r",
                plugin_name="p",
            ),
        ]

        result = ScanResult(
            target_path=tmp_path,
            findings=findings,
            plugins_run=["p"],
            scan_duration_seconds=1.0,
            summary={"total": 2},
        )

        reporter = SarifReporter()
        output = reporter.report(result)

        data = json.loads(output)
        results = data["runs"][0]["results"]
        assert results[0]["level"] == "error"  # CRITICAL
        assert results[1]["level"] == "warning"  # MEDIUM
