"""Output formatters for scan results."""

import json
from datetime import datetime, timezone

from rich.console import Console
from rich.rule import Rule

from .models import ScanResult, Severity

_VERSION = "0.1.0"


class TextReporter:
    """Human-readable output using rich library."""

    def __init__(self, console: Console | None = None):
        """Initialize text reporter with optional console."""
        self.console = console or Console()

    def report(self, result: ScanResult) -> None:
        """
        Generate and print text report.

        Args:
            result: Scan result to report
        """
        # Header
        self.console.print("🔍 Dev Trust Scanner v0.1.0", style="bold")
        self.console.print(f"Scanning: {result.target_path}")
        self.console.print(f"Plugins: {', '.join(result.plugins_run)}\n")

        # Findings
        if not result.findings:
            self.console.print("✅ No issues found", style="green bold")
        else:
            self.console.print(Rule())

            # Sort by severity (critical first)
            severity_order = {
                Severity.CRITICAL: 0,
                Severity.HIGH: 1,
                Severity.MEDIUM: 2,
                Severity.LOW: 3,
            }
            sorted_findings = sorted(
                result.findings, key=lambda f: severity_order[f.severity]
            )

            for finding in sorted_findings:
                self._print_finding(finding)

            self.console.print(Rule())

        # Summary
        summary = result.summary
        summary_parts = []

        if summary["critical"] > 0:
            summary_parts.append(f"{summary['critical']} critical")
        if summary["high"] > 0:
            summary_parts.append(f"{summary['high']} high")
        if summary["medium"] > 0:
            summary_parts.append(f"{summary['medium']} medium")
        if summary["low"] > 0:
            summary_parts.append(f"{summary['low']} low")

        if summary_parts:
            summary_text = f"Summary: {', '.join(summary_parts)} | {summary['total']} findings in {result.scan_duration_seconds}s"
        else:
            summary_text = f"Summary: 0 findings in {result.scan_duration_seconds}s"

        self.console.print(summary_text)

    def _print_finding(self, finding) -> None:
        """Print single finding with color coding."""
        # Color and icon by severity
        severity_config = {
            Severity.CRITICAL: ("red", "🔴"),
            Severity.HIGH: ("red", "🔴"),
            Severity.MEDIUM: ("yellow", "🟡"),
            Severity.LOW: ("blue", "🔵"),
        }

        color, icon = severity_config[finding.severity]

        # Title line
        self.console.print(
            f"{icon} {finding.severity.value.upper()}: {finding.rule_name} [{finding.rule_id}]",
            style=f"bold {color}",
        )

        # Details
        self.console.print(f"   File: {finding.file_path}", style=color)
        if finding.line_number:
            self.console.print(f"   Line: {finding.line_number}", style=color)

        # Truncate long content
        content = finding.matched_content
        if len(content) > 100:
            content = content[:100] + "..."
        self.console.print(f'   Match: "{content}"', style=color)

        self.console.print(f"   → {finding.recommendation}\n")


class JsonReporter:
    """JSON output for programmatic consumption."""

    def report(self, result: ScanResult) -> str:
        """
        Generate JSON report.

        Args:
            result: Scan result to report

        Returns:
            JSON string
        """
        return result.model_dump_json(indent=2)


class SarifReporter:
    """SARIF 2.1.0 format for CI/CD integration."""

    def report(self, result: ScanResult, tenant_id: str | None = None) -> str:
        """
        Generate SARIF 2.1.0 format report.

        Args:
            result: Scan result to report
            tenant_id: Optional tenant identifier injected into run.properties

        Returns:
            SARIF JSON string compatible with GitHub code scanning
        """
        run: dict = {
            "tool": {
                "driver": {
                    "name": "Dev Trust Scanner",
                    "version": _VERSION,
                    "informationUri": "https://github.com/ymlsurgeon/dev-trust-scanner",
                    "rules": self._build_rules_array(result),
                }
            },
            "properties": {
                "scanTimestamp": datetime.now(timezone.utc).isoformat(),
                "scannerVersion": _VERSION,
            },
            "results": [self._finding_to_sarif(f) for f in result.findings],
        }

        if tenant_id:
            run["properties"]["tenantId"] = tenant_id

        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [run],
        }

        return json.dumps(sarif, indent=2)

    def _build_rules_array(self, result: ScanResult) -> list[dict]:
        """
        Build the tool.driver.rules array from scan findings.

        GitHub code scanning uses this to display rule names and descriptions
        as inline annotations on PRs. Without it, findings show as 'unknown rule'.

        Args:
            result: Scan result containing findings

        Returns:
            Deduplicated list of SARIF rule descriptor objects
        """
        seen: set[str] = set()
        rules = []

        for finding in result.findings:
            if finding.rule_id in seen:
                continue
            seen.add(finding.rule_id)

            rules.append({
                "id": finding.rule_id,
                "name": finding.rule_name,
                "shortDescription": {"text": finding.rule_name},
                "fullDescription": {"text": finding.description},
                "help": {"text": finding.recommendation, "markdown": finding.recommendation},
                "defaultConfiguration": {
                    "level": self._severity_to_sarif_level(finding.severity),
                },
                "properties": {
                    "security-severity": self._SECURITY_SEVERITY[finding.severity]
                },
            })

        return rules

    # Numeric scores used in rule.properties.security-severity.
    # GitHub code scanning maps these to colored severity badges:
    #   >= 9.0 → Critical, >= 7.0 → High, >= 4.0 → Medium, >= 0.1 → Low
    _SECURITY_SEVERITY: dict = {
        Severity.CRITICAL: "9.5",
        Severity.HIGH: "8.0",
        Severity.MEDIUM: "5.0",
        Severity.LOW: "2.0",
    }

    def _severity_to_sarif_level(self, severity: Severity) -> str:
        """Map Severity enum to SARIF level string."""
        severity_map = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
        }
        return severity_map[severity]

    def _finding_to_sarif(self, finding) -> dict:
        """Convert Finding to SARIF result object."""
        region: dict = {"startLine": finding.line_number or 1}
        if finding.matched_content:
            region["snippet"] = {"text": finding.matched_content}

        message = finding.description
        if finding.matched_content:
            message = f"{finding.description}\nMatched: {finding.matched_content}"

        return {
            "ruleId": finding.rule_id,
            "level": self._severity_to_sarif_level(finding.severity),
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": str(finding.file_path),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": region,
                    }
                }
            ],
        }
