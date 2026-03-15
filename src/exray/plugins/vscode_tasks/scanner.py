"""Scanner plugin for VS Code tasks.json malicious configurations."""

import json
import logging
import re
from pathlib import Path

import yaml

from ...core.models import Finding, Rule, Severity
from ...core.plugin import BasePlugin
from ...core.static_analysis import (
    calculate_entropy,
    detect_base64,
    detect_obfuscation,
    get_context_lines,
    match_rules,
)

logger = logging.getLogger(__name__)

# Entropy threshold for detecting encoded/obfuscated content
ENTROPY_THRESHOLD = 5.0  # Higher for tasks (often have long paths)


class VsCodeTasksPlugin(BasePlugin):
    """Scanner for malicious VS Code tasks.json configurations."""

    def __init__(self):
        """Initialize plugin and load detection rules."""
        self.rules = self._load_rules()

    def _load_rules(self) -> list[Rule]:
        """Load rules from vscode_rules.yaml."""
        rules_file = Path(__file__).parent / "rules" / "vscode_rules.yaml"

        try:
            with open(rules_file) as f:
                data = yaml.safe_load(f)

            rules = []
            for rule_data in data.get("rules", []):
                # Skip VSC-002 (obfuscation) as it's checked programmatically
                if rule_data["id"] == "VSC-002":
                    continue
                rules.append(Rule(**rule_data))

            logger.info(f"Loaded {len(rules)} VS Code task rules")
            return rules

        except Exception as e:
            logger.error(f"Failed to load vscode rules: {e}")
            return []

    def scan(self, target_path: Path) -> list[Finding]:
        """
        Scan .vscode/tasks.json for malicious configurations.

        Args:
            target_path: Root directory to scan

        Returns:
            List of findings from tasks.json files found
        """
        findings = []
        self.scanned_files = []

        try:
            # Look for .vscode/tasks.json
            tasks_file = target_path / ".vscode" / "tasks.json"
            if tasks_file.exists():
                # Check file size (10MB limit)
                if tasks_file.stat().st_size > 10 * 1024 * 1024:
                    logger.warning(f"Skipping {tasks_file}: exceeds 10MB")
                    return findings

                self.scanned_files.append(tasks_file)
                findings.extend(self._scan_tasks_file(tasks_file, target_path))

        except Exception as e:
            logger.error(f"Error scanning {target_path}: {e}")

        return findings

    def _strip_json_comments(self, content: str) -> str:
        """
        Remove // and /* */ comments from JSON content (JSONC format).

        VS Code allows comments in tasks.json, but standard JSON parser doesn't.
        This implementation respects string boundaries to avoid treating URLs
        like https:// as comment markers.

        Args:
            content: JSONC content

        Returns:
            JSON content with comments removed
        """
        result = []
        i = 0
        in_string = False
        escape_next = False

        while i < len(content):
            char = content[i]

            # Handle escape sequences in strings
            if in_string and escape_next:
                result.append(char)
                escape_next = False
                i += 1
                continue

            # Track string boundaries
            if char == '"' and not escape_next:
                in_string = not in_string
                result.append(char)
                i += 1
                continue

            # Mark next character as escaped
            if char == '\\' and in_string:
                escape_next = True
                result.append(char)
                i += 1
                continue

            # Only process comments outside of strings
            if not in_string:
                # Check for // single-line comment
                if i + 1 < len(content) and content[i:i+2] == '//':
                    # Skip until end of line
                    while i < len(content) and content[i] != '\n':
                        i += 1
                    continue

                # Check for /* multi-line comment */
                if i + 1 < len(content) and content[i:i+2] == '/*':
                    # Skip until */
                    i += 2
                    while i + 1 < len(content):
                        if content[i:i+2] == '*/':
                            i += 2
                            break
                        i += 1
                    continue

            result.append(char)
            i += 1

        return ''.join(result)

    def _scan_tasks_file(self, tasks_path: Path, root: Path) -> list[Finding]:
        """
        Scan a single tasks.json file.

        Args:
            tasks_path: Path to tasks.json
            root: Root directory being scanned

        Returns:
            List of findings from this tasks.json
        """
        findings = []

        # Read and parse JSONC
        try:
            with open(tasks_path, encoding="utf-8", errors="replace") as f:
                raw_content = f.read()

            # Strip comments for parsing
            clean_content = self._strip_json_comments(raw_content)
            data = json.loads(clean_content)

        except json.JSONDecodeError as e:
            logger.warning(f"Malformed JSON in {tasks_path}: {e}")
            # Fallback: scan raw content for suspicious patterns
            return self._scan_raw_content(raw_content, tasks_path, root)
        except Exception as e:
            logger.warning(f"Could not read {tasks_path}: {e}")
            return []

        # Get relative path for reporting
        try:
            relative_path = tasks_path.relative_to(root)
        except ValueError:
            relative_path = tasks_path

        # Extract tasks array
        tasks = data.get("tasks", [])
        if not tasks or not isinstance(tasks, list):
            return []

        # Build task-label → line-number map from the raw JSON text.
        # Pins each task's findings to the "label": "..." line so GitHub Code
        # Scanning shows the actual task block as context instead of line 1.
        task_line_numbers: dict[str, int] = {}
        for task in tasks:
            if not isinstance(task, dict):
                continue
            label = task.get("label", "")
            if label:
                m = re.search(
                    rf'"label"\s*:\s*"{re.escape(label)}"', raw_content
                )
                if m:
                    task_line_numbers[label] = raw_content[:m.start()].count('\n') + 1

        # Analyze each task
        for task in tasks:
            if not isinstance(task, dict):
                continue

            task_label = task.get("label", "unnamed")
            task_json_line = task_line_numbers.get(task_label)

            # Collect all findings for this task before pinning line numbers
            task_findings = []

            # Critical check: auto-execution on folder open
            run_options = task.get("runOptions", {})
            if isinstance(run_options, dict):
                run_on = run_options.get("runOn", "default")
                if run_on == "folderOpen":
                    task_findings.append(
                        Finding(
                            rule_id="VSC-001",
                            rule_name="Auto-executing task on folder open",
                            severity=Severity.CRITICAL,
                            file_path=relative_path,
                            matched_content=f"Task '{task_label}' with runOn: folderOpen",
                            description="CRITICAL: Task runs automatically when folder opens (Contagious Interview attack)",
                            recommendation="Remove auto-execution immediately. This is a known malware technique.",
                            plugin_name=self.get_metadata()["name"],
                        )
                    )

            # Check command content
            command = task.get("command", "")
            if command and isinstance(command, str):
                task_findings.extend(self._analyze_command(command, task_label, relative_path))

            # Check args array
            args = task.get("args", [])
            if args and isinstance(args, list):
                for arg in args:
                    if isinstance(arg, str):
                        task_findings.extend(self._analyze_command(arg, task_label, relative_path))

            # Check platform-specific commands (osx, linux, windows)
            for platform in ["osx", "linux", "windows"]:
                if platform in task and isinstance(task[platform], dict):
                    platform_config = task[platform]

                    platform_command = platform_config.get("command", "")
                    if platform_command and isinstance(platform_command, str):
                        task_findings.extend(
                            self._analyze_command(
                                platform_command,
                                f"{task_label} ({platform})",
                                relative_path
                            )
                        )

                    platform_args = platform_config.get("args", [])
                    if platform_args and isinstance(platform_args, list):
                        for arg in platform_args:
                            if isinstance(arg, str):
                                task_findings.extend(
                                    self._analyze_command(
                                        arg,
                                        f"{task_label} ({platform})",
                                        relative_path
                                    )
                                )

            # Check presentation settings (hidden output)
            presentation = task.get("presentation", {})
            if isinstance(presentation, dict):
                raw_task_str = json.dumps(presentation)
                task_findings.extend(
                    match_rules(
                        text=raw_task_str,
                        rules=self.rules,
                        file_path=relative_path,
                        plugin_name=self.get_metadata()["name"],
                    )
                )

            # Pin all findings for this task to the task's line in tasks.json
            if task_json_line:
                for finding in task_findings:
                    finding.line_number = task_json_line
                    finding.context_lines = get_context_lines(raw_content, task_json_line)

            findings.extend(task_findings)

        return findings

    def _analyze_command(self, command: str, task_label: str, file_path: Path) -> list[Finding]:
        """
        Analyze a task command string for malicious patterns.

        Args:
            command: Command string to analyze
            task_label: Label of the task (for context)
            file_path: Path to tasks.json (for reporting)

        Returns:
            List of findings from this command
        """
        findings = []

        # Apply detection rules
        findings.extend(
            match_rules(
                text=command,
                rules=self.rules,
                file_path=file_path,
                plugin_name=self.get_metadata()["name"],
            )
        )

        # Check for base64
        base64_matches = detect_base64(command, min_length=30)
        if base64_matches:
            findings.append(
                Finding(
                    rule_id="VSC-002",
                    rule_name="Base64 content in task command",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    matched_content=base64_matches[0].matched_text,
                    description=f"Task '{task_label}' command contains base64-encoded content",
                    recommendation="Decode and inspect the base64 content.",
                    plugin_name=self.get_metadata()["name"],
                )
            )

        # Check for obfuscation
        obfuscation_matches = detect_obfuscation(command)
        if obfuscation_matches:
            findings.append(
                Finding(
                    rule_id="VSC-002",
                    rule_name="Obfuscated command in task",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    matched_content=obfuscation_matches[0].matched_text[:200],
                    description=f"Task '{task_label}' contains obfuscated code ({obfuscation_matches[0].pattern_name})",
                    recommendation="Deobfuscate and inspect. Obfuscation is highly suspicious.",
                    plugin_name=self.get_metadata()["name"],
                )
            )

        # Check entropy
        entropy = calculate_entropy(command)
        if entropy > ENTROPY_THRESHOLD:
            findings.append(
                Finding(
                    rule_id="VSC-ENTROPY",
                    rule_name="High entropy in task command",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    matched_content=command[:200],
                    description=f"Task '{task_label}' has high entropy ({entropy}), may contain encoded content",
                    recommendation="Decode and inspect the command.",
                    plugin_name=self.get_metadata()["name"],
                )
            )

        return findings

    def _scan_raw_content(self, content: str, tasks_path: Path, root: Path) -> list[Finding]:
        """
        Fallback scanner for malformed JSON files.

        When JSON parsing fails, scan the raw text for known malicious patterns.
        This ensures we don't miss attacks hidden in deliberately malformed files.

        Args:
            content: Raw file content
            tasks_path: Path to the tasks file
            root: Root directory being scanned

        Returns:
            List of findings from raw content scanning
        """
        findings = []

        try:
            relative_path = tasks_path.relative_to(root)
        except ValueError:
            relative_path = tasks_path

        # Check for critical auto-execution pattern
        if re.search(r'"runOn"\s*:\s*"folderOpen"', content, re.IGNORECASE):
            findings.append(
                Finding(
                    rule_id="VSC-001",
                    rule_name="Auto-executing task on folder open",
                    severity=Severity.CRITICAL,
                    file_path=relative_path,
                    matched_content="runOn: folderOpen (detected in malformed JSON)",
                    description="CRITICAL: Malformed tasks.json contains auto-execution pattern",
                    recommendation="Remove auto-execution immediately. File appears deliberately malformed to evade detection.",
                    plugin_name=self.get_metadata()["name"],
                )
            )

        # Check for suspicious shell commands
        shell_patterns = [
            (r'curl.*\|.*(?:sh|bash)', "curl | sh"),
            (r'wget.*\|.*(?:sh|bash)', "wget | sh"),
            (r'\beval\s*\(', "eval()"),
            (r'/dev/tcp/', "/dev/tcp/"),
        ]

        for pattern, description in shell_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                findings.append(
                    Finding(
                        rule_id="VSC-003",
                        rule_name="Suspicious shell command in task",
                        severity=Severity.HIGH,
                        file_path=relative_path,
                        matched_content=match.group()[:200],
                        description=f"Malformed tasks.json contains suspicious pattern: {description}",
                        recommendation="Review carefully. Malformed JSON with shell injection patterns is highly suspicious.",
                        plugin_name=self.get_metadata()["name"],
                    )
                )

        # Check for hidden presentation
        if re.search(r'"reveal"\s*:\s*"never"', content, re.IGNORECASE):
            findings.append(
                Finding(
                    rule_id="VSC-004",
                    rule_name="Hidden task presentation",
                    severity=Severity.MEDIUM,
                    file_path=relative_path,
                    matched_content='reveal: "never"',
                    description="Malformed tasks.json configured to hide task output",
                    recommendation="Verify why output is hidden. Combined with malformed JSON, this is suspicious.",
                    plugin_name=self.get_metadata()["name"],
                )
            )

        # Check for base64 content
        base64_matches = detect_base64(content, min_length=40)
        if base64_matches:
            findings.append(
                Finding(
                    rule_id="VSC-002",
                    rule_name="Base64 content in task file",
                    severity=Severity.HIGH,
                    file_path=relative_path,
                    matched_content=base64_matches[0].matched_text[:200],
                    description="Malformed tasks.json contains base64-encoded content",
                    recommendation="Decode and inspect. Base64 in malformed JSON is highly suspicious.",
                    plugin_name=self.get_metadata()["name"],
                )
            )

        if findings:
            logger.info(f"Fallback raw scan detected {len(findings)} issue(s) in malformed JSON")

        return findings

    def get_metadata(self) -> dict:
        """Return plugin metadata."""
        return {
            "name": "vscode-tasks",
            "version": "0.1.0",
            "author": "Dev Trust Scanner",
            "description": "Detects malicious VS Code tasks.json configurations (Contagious Interview attacks)",
        }

    def get_supported_files(self) -> list[str]:
        """Return supported file patterns."""
        return [".vscode/tasks.json"]
