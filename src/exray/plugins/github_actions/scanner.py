"""
GitHub Actions workflow scanner.

Detects malicious patterns in GitHub Actions workflow files including:
- Workflow injection attacks
- Self-hosted runner abuse
- Secret exfiltration
- Suspicious external actions
"""

from pathlib import Path
from typing import Any
import logging
import yaml

from exray.core.plugin import BasePlugin
from exray.core.models import Finding, Rule
from exray.core.static_analysis import match_rules

logger = logging.getLogger(__name__)


class GitHubActionsPlugin(BasePlugin):
    """Scanner for GitHub Actions workflow files."""

    def __init__(self):
        """Initialize plugin and load rules."""
        self.rules = self._load_rules()

    def scan(self, target_path: Path) -> list[Finding]:
        """
        Scan directory for GitHub Actions workflow files.

        Args:
            target_path: Root directory to scan

        Returns:
            List of security findings
        """
        findings = []
        self.scanned_files = []

        # Find all workflow files
        workflows_dir = target_path / ".github" / "workflows"
        if not workflows_dir.exists():
            return findings

        for workflow_file in workflows_dir.glob("*.y*ml"):  # *.yml and *.yaml
            try:
                self.scanned_files.append(workflow_file)
                findings.extend(self._scan_workflow_file(workflow_file))
            except Exception as e:
                logger.error(f"Error scanning {workflow_file}: {e}")
                # Continue scanning other files per DEC-009

        return findings

    def _scan_workflow_file(self, workflow_file: Path) -> list[Finding]:
        """
        Scan a single workflow file.

        Args:
            workflow_file: Path to workflow YAML file

        Returns:
            List of findings from this file
        """
        findings = []

        try:
            # Read file content
            with open(workflow_file, "r", encoding="utf-8") as f:
                content = f.read()

            # Apply rules
            findings = match_rules(
                text=content,
                rules=self.rules,
                file_path=workflow_file,
                plugin_name="github_actions",
            )

        except Exception as e:
            logger.error(f"Failed to scan {workflow_file}: {e}")

        return findings

    def _load_rules(self) -> list[Rule]:
        """Load detection rules from YAML file."""
        rules_file = Path(__file__).parent / "rules" / "gha_rules.yaml"
        rules = []

        try:
            with open(rules_file, "r") as f:
                data = yaml.safe_load(f)

            for rule_data in data.get("rules", []):
                rules.append(Rule(**rule_data))

            logger.info(f"Loaded {len(rules)} GitHub Actions rules")
        except Exception as e:
            logger.error(f"Failed to load rules from {rules_file}: {e}")

        return rules

    def get_metadata(self) -> dict[str, Any]:
        """Return plugin metadata."""
        return {
            "name": "github_actions",
            "version": "0.2.0",
            "description": "Detects malicious patterns in GitHub Actions workflow files",
            "author": "Dev Trust Scanner Team",
        }

    def get_supported_files(self) -> list[str]:
        """Return glob patterns for supported files."""
        return [".github/workflows/*.yml", ".github/workflows/*.yaml"]
