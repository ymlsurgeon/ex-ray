"""Tests for tenant-ID tagging in SARIF output and CLI integration."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from dev_trust_scanner.cli import main
from dev_trust_scanner.core.models import ScanResult, Severity
from dev_trust_scanner.core.reporting import SarifReporter


def _make_scan_result(tmp_path: Path) -> ScanResult:
    """Build a minimal ScanResult for testing."""
    return ScanResult(
        target_path=tmp_path,
        findings=[],
        plugins_run=["npm-lifecycle"],
        scan_duration_seconds=0.1,
        summary={"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
    )


class TestSarifTenantInjection:
    """Tests for tenant_id injection into SARIF run.properties."""

    def test_tenant_id_injected_when_provided(self, tmp_path):
        """run.properties contains tenantId when tenant_id is set."""
        result = _make_scan_result(tmp_path)
        reporter = SarifReporter()
        sarif_str = reporter.report(result, tenant_id="acme-corp")

        data = json.loads(sarif_str)
        props = data["runs"][0]["properties"]
        assert props["tenantId"] == "acme-corp"

    def test_tenant_id_absent_when_not_provided(self, tmp_path):
        """run.properties does NOT contain tenantId when tenant_id is None."""
        result = _make_scan_result(tmp_path)
        reporter = SarifReporter()
        sarif_str = reporter.report(result, tenant_id=None)

        data = json.loads(sarif_str)
        props = data["runs"][0]["properties"]
        assert "tenantId" not in props

    def test_scan_timestamp_always_present(self, tmp_path):
        """run.properties always contains scanTimestamp."""
        result = _make_scan_result(tmp_path)
        reporter = SarifReporter()
        sarif_str = reporter.report(result)

        data = json.loads(sarif_str)
        props = data["runs"][0]["properties"]
        assert "scanTimestamp" in props
        # Should be a valid ISO 8601 timestamp
        assert "T" in props["scanTimestamp"]

    def test_scanner_version_always_present(self, tmp_path):
        """run.properties always contains scannerVersion."""
        result = _make_scan_result(tmp_path)
        reporter = SarifReporter()
        sarif_str = reporter.report(result)

        data = json.loads(sarif_str)
        props = data["runs"][0]["properties"]
        assert "scannerVersion" in props
        assert props["scannerVersion"] != ""

    def test_sarif_structure_valid_without_tenant(self, tmp_path):
        """SARIF remains structurally valid when tenant_id is omitted."""
        result = _make_scan_result(tmp_path)
        reporter = SarifReporter()
        sarif_str = reporter.report(result)

        data = json.loads(sarif_str)
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        assert "tool" in data["runs"][0]
        assert "results" in data["runs"][0]

    def test_sarif_structure_valid_with_tenant(self, tmp_path):
        """SARIF remains structurally valid when tenant_id is provided."""
        result = _make_scan_result(tmp_path)
        reporter = SarifReporter()
        sarif_str = reporter.report(result, tenant_id="test-tenant")

        data = json.loads(sarif_str)
        assert data["version"] == "2.1.0"
        assert data["runs"][0]["properties"]["tenantId"] == "test-tenant"


class TestCLITenantAndWebhook:
    """Integration tests for --tenant-id and --webhook-url CLI flags."""

    def test_cli_tenant_id_in_sarif_output(self, clean_npm_package):
        """--tenant-id injects tenantId into SARIF stdout output."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [str(clean_npm_package), "--format", "sarif", "--tenant-id", "my-tenant"],
        )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["runs"][0]["properties"]["tenantId"] == "my-tenant"

    def test_cli_no_tenant_id_by_default(self, clean_npm_package):
        """SARIF output omits tenantId when --tenant-id is not passed."""
        runner = CliRunner()
        result = runner.invoke(
            main, [str(clean_npm_package), "--format", "sarif"]
        )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "tenantId" not in data["runs"][0]["properties"]

    def test_cli_webhook_called_on_sarif(self, clean_npm_package):
        """--webhook-url triggers post_sarif() when format is sarif."""
        runner = CliRunner()

        with patch("dev_trust_scanner.cli.post_sarif", return_value=True) as mock_post:
            result = runner.invoke(
                main,
                [
                    str(clean_npm_package),
                    "--format", "sarif",
                    "--webhook-url", "https://example.com/hook",
                ],
            )

        assert result.exit_code == 0
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert call_kwargs.kwargs["url"] == "https://example.com/hook"

    def test_cli_webhook_passes_tenant_id(self, clean_npm_package):
        """--tenant-id is forwarded to post_sarif()."""
        runner = CliRunner()

        with patch("dev_trust_scanner.cli.post_sarif", return_value=True) as mock_post:
            result = runner.invoke(
                main,
                [
                    str(clean_npm_package),
                    "--format", "sarif",
                    "--webhook-url", "https://example.com/hook",
                    "--tenant-id", "acme",
                ],
            )

        assert result.exit_code == 0
        mock_post.assert_called_once()
        assert mock_post.call_args.kwargs["tenant_id"] == "acme"

    def test_cli_webhook_failure_does_not_block_output(self, clean_npm_package):
        """Webhook failure does not prevent SARIF from being written to stdout."""
        runner = CliRunner()

        with patch("dev_trust_scanner.cli.post_sarif", return_value=False):
            result = runner.invoke(
                main,
                [
                    str(clean_npm_package),
                    "--format", "sarif",
                    "--webhook-url", "https://example.com/hook",
                ],
            )

        # Output should still be valid SARIF
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["version"] == "2.1.0"

    def test_cli_webhook_not_called_for_json_format(self, clean_npm_package):
        """Webhook is not triggered when --format is json (sarif only)."""
        runner = CliRunner()

        with patch("dev_trust_scanner.cli.post_sarif", return_value=True) as mock_post:
            result = runner.invoke(
                main,
                [
                    str(clean_npm_package),
                    "--format", "json",
                    "--webhook-url", "https://example.com/hook",
                ],
            )

        assert result.exit_code == 0
        mock_post.assert_not_called()

    def test_cli_output_file_sarif(self, clean_npm_package, tmp_path):
        """--output writes SARIF to file instead of stdout."""
        outfile = tmp_path / "results.sarif"
        runner = CliRunner()

        result = runner.invoke(
            main,
            [str(clean_npm_package), "--format", "sarif", "--output", str(outfile)],
        )

        assert result.exit_code == 0
        assert outfile.exists()
        data = json.loads(outfile.read_text())
        assert data["version"] == "2.1.0"
        # stdout should be empty when writing to file
        assert result.output.strip() == ""

    def test_cli_output_file_json(self, clean_npm_package, tmp_path):
        """--output writes JSON to file instead of stdout."""
        outfile = tmp_path / "results.json"
        runner = CliRunner()

        result = runner.invoke(
            main,
            [str(clean_npm_package), "--format", "json", "--output", str(outfile)],
        )

        assert result.exit_code == 0
        assert outfile.exists()
        data = json.loads(outfile.read_text())
        assert "findings" in data

    def test_cli_webhook_and_output_file_together(self, clean_npm_package, tmp_path):
        """--webhook-url and --output can be used together."""
        outfile = tmp_path / "results.sarif"
        runner = CliRunner()

        with patch("dev_trust_scanner.cli.post_sarif", return_value=True) as mock_post:
            result = runner.invoke(
                main,
                [
                    str(clean_npm_package),
                    "--format", "sarif",
                    "--output", str(outfile),
                    "--webhook-url", "https://example.com/hook",
                    "--tenant-id", "test-tenant",
                ],
            )

        assert result.exit_code == 0
        # File should be written
        assert outfile.exists()
        file_data = json.loads(outfile.read_text())
        assert file_data["runs"][0]["properties"]["tenantId"] == "test-tenant"
        # Webhook should also be called
        mock_post.assert_called_once()
