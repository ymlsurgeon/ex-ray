"""
GitHub Actions workflow scanner.

Detects malicious patterns in GitHub Actions workflow files including:
- Workflow injection attacks
- Self-hosted runner abuse
- Secret exfiltration
- Suspicious external actions
"""

import re
from pathlib import Path
from typing import Any
import logging
import yaml

from exray.core.plugin import BasePlugin
from exray.core.models import Finding, Rule, Severity
from exray.core.static_analysis import get_context_lines, match_rules

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

            # Programmatic: detect unpinned third-party action references
            findings.extend(self._detect_unpinned_actions(content, workflow_file))

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
                # Skip GHA-008 — checked programmatically in _detect_unpinned_actions
                if rule_data["id"] == "GHA-008":
                    continue
                rules.append(Rule(**rule_data))

            logger.info(f"Loaded {len(rules)} GitHub Actions rules")
        except Exception as e:
            logger.error(f"Failed to load rules from {rules_file}: {e}")

        return rules

    # Patterns for unpinned action detection (GHA-008)
    _USES_RE = re.compile(r'^\s*-?\s*uses:\s*(.+)', re.MULTILINE)
    _SHA_RE = re.compile(r'@[0-9a-f]{40}\b')
    _FIRST_PARTY_RE = re.compile(r'^(actions|github)/')
    _LOCAL_RE = re.compile(r'^\./')
    _DOCKER_RE = re.compile(r'^docker://')

    def _detect_unpinned_actions(self, content: str, workflow_file: Path) -> list[Finding]:
        """Detect third-party GitHub Action references not pinned to a commit SHA."""
        findings = []
        for match in self._USES_RE.finditer(content):
            ref = match.group(1).strip().strip('"').strip("'")
            # Strip inline comments
            if " #" in ref:
                ref = ref[: ref.index(" #")].strip()
            # Skip first-party, local, and docker references
            if self._FIRST_PARTY_RE.match(ref):
                continue
            if self._LOCAL_RE.match(ref):
                continue
            if self._DOCKER_RE.match(ref):
                continue
            # Check if pinned to full SHA
            if self._SHA_RE.search(ref):
                continue
            line_number = content[: match.start()].count("\n") + 1
            findings.append(
                Finding(
                    rule_id="GHA-008",
                    rule_name="Unpinned third-party GitHub Action reference",
                    severity=Severity.MEDIUM,
                    file_path=workflow_file,
                    line_number=line_number,
                    matched_content=f"uses: {ref}",
                    context_lines=get_context_lines(content, line_number),
                    description=f"Action '{ref}' uses a mutable tag instead of a commit SHA. Mutable tags can be force-pushed to point to malicious code (TeamPCP/Trivy attack, March 2026).",
                    recommendation="Pin this Action to a full commit SHA instead of a version tag.",
                    plugin_name="github_actions",
                )
            )
        return findings

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
