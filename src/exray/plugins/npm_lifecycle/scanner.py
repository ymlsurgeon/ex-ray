"""Scanner plugin for npm lifecycle scripts."""

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

# Lifecycle scripts that execute automatically (higher risk)
LIFECYCLE_SCRIPTS = {
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "prepublishOnly",
    "prepack",
    "postpack",
    "prepare",
}

# Entropy threshold for detecting encoded/obfuscated content
ENTROPY_THRESHOLD = 4.5


class NpmLifecyclePlugin(BasePlugin):
    """Scanner for malicious patterns in npm lifecycle scripts."""

    def __init__(self):
        """Initialize plugin and load detection rules."""
        self.rules = self._load_rules()

    def _load_rules(self) -> list[Rule]:
        """Load rules from npm_rules.yaml."""
        rules_file = Path(__file__).parent / "rules" / "npm_rules.yaml"

        try:
            with open(rules_file) as f:
                data = yaml.safe_load(f)

            rules = []
            for rule_data in data.get("rules", []):
                rules.append(Rule(**rule_data))

            logger.info(f"Loaded {len(rules)} npm rules")
            return rules

        except Exception as e:
            logger.error(f"Failed to load npm rules: {e}")
            return []

    def scan(self, target_path: Path) -> list[Finding]:
        """
        Scan package.json files for malicious lifecycle scripts.

        Args:
            target_path: Root directory to scan

        Returns:
            List of findings from all package.json files found
        """
        findings = []
        self.scanned_files = []

        try:
            # Find all package.json files (supports monorepos)
            # Skip node_modules per design decision
            for pkg_file in target_path.rglob("package.json"):
                # Skip node_modules directories
                if "node_modules" in pkg_file.parts:
                    continue

                # Check file size (10MB limit per design decision)
                if pkg_file.stat().st_size > 10 * 1024 * 1024:
                    logger.warning(f"Skipping {pkg_file}: exceeds 10MB size limit")
                    continue

                self.scanned_files.append(pkg_file)
                findings.extend(self._scan_package_json(pkg_file, target_path))

        except Exception as e:
            logger.error(f"Error scanning {target_path}: {e}")

        return findings

    def _extract_script_files(self, script_command: str) -> list[str]:
        """
        Extract JavaScript file references from a script command.

        Examples:
            "node index.js" -> ["index.js"]
            "node ./scripts/build.js" -> ["./scripts/build.js"]
            "npm run build && node dist/index.js" -> ["dist/index.js"]

        Args:
            script_command: The script command to parse

        Returns:
            List of .js file paths referenced in the command
        """
        files = []

        # Pattern: node <path.js>
        # Handles: node file.js, node ./file.js, node ../dir/file.js
        node_pattern = r'\bnode\s+([^\s;&|]+\.js)'
        for match in re.finditer(node_pattern, script_command):
            files.append(match.group(1))

        # Pattern: require() or import() with file path
        # Handles: require('./file.js'), import('./file.js')
        require_pattern = r'(?:require|import)\s*\(\s*["\']([^"\']+\.js)["\']\s*\)'
        for match in re.finditer(require_pattern, script_command):
            files.append(match.group(1))

        return files

    def _scan_js_file(
        self, js_path: Path, root: Path, script_name: str, pkg_path: Path
    ) -> list[Finding]:
        """
        Scan a JavaScript file referenced by a lifecycle script.

        Args:
            js_path: Path to the JavaScript file
            root: Root directory being scanned
            script_name: Name of the lifecycle script that references this file
            pkg_path: Path to the package.json containing the script

        Returns:
            List of findings from the JavaScript file
        """
        findings = []

        if not js_path.exists():
            logger.debug(f"Referenced file not found: {js_path}")
            return []

        # Check file size (10MB limit)
        if js_path.stat().st_size > 10 * 1024 * 1024:
            logger.warning(f"Skipping {js_path}: exceeds 10MB size limit")
            return []

        self.scanned_files.append(js_path)

        # Read the JavaScript file
        try:
            with open(js_path, encoding="utf-8", errors="replace") as f:
                js_content = f.read()
        except Exception as e:
            logger.warning(f"Could not read {js_path}: {e}")
            return []

        # Get relative path for reporting
        try:
            relative_path = js_path.relative_to(root)
        except ValueError:
            relative_path = js_path

        # Apply detection rules to the JavaScript content
        js_findings = match_rules(
            text=js_content,
            rules=self.rules,
            file_path=relative_path,
            plugin_name=self.get_metadata()["name"],
        )

        # Add context that this file is executed by a lifecycle script
        for finding in js_findings:
            finding.description = (
                f"[Lifecycle script '{script_name}' executes {js_path.name}] {finding.description}"
            )

        findings.extend(js_findings)

        # High entropy check
        entropy = calculate_entropy(js_content)
        if entropy > ENTROPY_THRESHOLD:
            findings.append(
                Finding(
                    rule_id="NPM-ENTROPY",
                    rule_name="High entropy in lifecycle script file",
                    severity=Severity.HIGH,
                    file_path=relative_path,
                    matched_content=js_content[:200],
                    description=f"File executed by '{script_name}' has high entropy ({entropy:.2f}), may contain encoded/encrypted malware",
                    recommendation="Decode and inspect the file content. High entropy often indicates base64, compression, or encryption.",
                    plugin_name=self.get_metadata()["name"],
                )
            )

        # Base64 detection
        base64_matches = detect_base64(js_content, min_length=30)
        if base64_matches:
            b64_line = base64_matches[0].line_number
            findings.append(
                Finding(
                    rule_id="NPM-BASE64",
                    rule_name="Base64 content in lifecycle script file",
                    severity=Severity.HIGH,
                    file_path=relative_path,
                    line_number=b64_line,
                    matched_content=base64_matches[0].matched_text,
                    context_lines=get_context_lines(js_content, b64_line) if b64_line else None,
                    description=f"File executed by '{script_name}' contains base64-encoded content",
                    recommendation="Decode the base64 content and verify it is legitimate.",
                    plugin_name=self.get_metadata()["name"],
                )
            )

        # Obfuscation detection
        obfuscation_matches = detect_obfuscation(js_content)
        if obfuscation_matches:
            obf_line = obfuscation_matches[0].line_number
            findings.append(
                Finding(
                    rule_id="NPM-OBFUSCATION",
                    rule_name="Code obfuscation in lifecycle script file",
                    severity=Severity.HIGH,
                    file_path=relative_path,
                    line_number=obf_line,
                    matched_content=obfuscation_matches[0].matched_text[:200],
                    context_lines=get_context_lines(js_content, obf_line) if obf_line else None,
                    description=f"File executed by '{script_name}' contains obfuscated code ({obfuscation_matches[0].pattern_name})",
                    recommendation="Deobfuscate and inspect. Legitimate packages rarely use obfuscation.",
                    plugin_name=self.get_metadata()["name"],
                )
            )

        return findings

    def _scan_package_json(self, pkg_path: Path, root: Path) -> list[Finding]:
        """
        Scan a single package.json file.

        Args:
            pkg_path: Path to package.json
            root: Root directory being scanned (for relative paths)

        Returns:
            List of findings from this package.json
        """
        findings = []

        # Read raw text first so we can resolve line numbers, then parse JSON.
        try:
            with open(pkg_path, encoding="utf-8", errors="replace") as f:
                raw_content = f.read()
            data = json.loads(raw_content)
        except json.JSONDecodeError as e:
            logger.warning(f"Malformed JSON in {pkg_path}: {e}")
            return []
        except Exception as e:
            logger.warning(f"Could not read {pkg_path}: {e}")
            return []

        # Extract package identity for finding metadata
        pkg_name = data.get("name", "unknown")
        pkg_version = data.get("version", "unknown")
        pkg_meta = {"package_name": pkg_name, "package_version": pkg_version}

        # Extract scripts section
        scripts = data.get("scripts", {})
        if not scripts or not isinstance(scripts, dict):
            return []

        # Build script-name → line-number map from the raw JSON.
        # This pins findings to the exact "scriptName": "command" line so
        # GitHub Code Scanning shows the actual script as context, not line 1.
        script_line_numbers: dict[str, int] = {}
        for sname in scripts:
            m = re.search(rf'"{re.escape(sname)}"\s*:', raw_content)
            if m:
                script_line_numbers[sname] = raw_content[:m.start()].count('\n') + 1

        # Check for preinstall presence
        has_preinstall = "preinstall" in scripts
        has_suspicious_preinstall = False
        preinstall_findings_indices = []

        # Analyze each script
        for script_name, script_content in scripts.items():
            if not isinstance(script_content, str):
                continue

            # Get relative path for reporting
            try:
                relative_path = pkg_path.relative_to(root)
            except ValueError:
                relative_path = pkg_path

            script_json_line = script_line_numbers.get(script_name)

            # Collect findings produced from the script command string itself
            # separately from JS file findings (which keep their own line numbers).
            script_level_findings = []

            # Apply detection rules to the script command itself
            rule_findings = match_rules(
                text=script_content,
                rules=self.rules,
                file_path=relative_path,
                plugin_name=self.get_metadata()["name"],
            )

            # Tag lifecycle scripts with higher severity
            if script_name in LIFECYCLE_SCRIPTS:
                for finding in rule_findings:
                    finding.description = (
                        f"[Lifecycle script: {script_name}] {finding.description}"
                    )

            script_level_findings.extend(rule_findings)

            # Additional checks for lifecycle scripts
            if script_name in LIFECYCLE_SCRIPTS:
                # High entropy check (encoded/encrypted content)
                entropy = calculate_entropy(script_content)
                if entropy > ENTROPY_THRESHOLD:
                    script_level_findings.append(
                        Finding(
                            rule_id="NPM-ENTROPY",
                            rule_name="High entropy in lifecycle script",
                            severity=Severity.HIGH,
                            file_path=relative_path,
                            matched_content=script_content[:200],
                            description=f"Script '{script_name}' has high entropy ({entropy}), may contain encoded/encrypted malware",
                            recommendation="Decode and inspect the script content. High entropy often indicates base64, compression, or encryption.",
                            plugin_name=self.get_metadata()["name"],
                        )
                    )

                # Base64 detection
                base64_matches = detect_base64(script_content, min_length=30)
                if base64_matches:
                    script_level_findings.append(
                        Finding(
                            rule_id="NPM-BASE64",
                            rule_name="Base64 content detected in lifecycle script",
                            severity=Severity.HIGH,
                            file_path=relative_path,
                            matched_content=base64_matches[0].matched_text,
                            description=f"Script '{script_name}' contains base64-encoded content",
                            recommendation="Decode the base64 content and verify it is legitimate.",
                            plugin_name=self.get_metadata()["name"],
                        )
                    )

                # Obfuscation detection
                obfuscation_matches = detect_obfuscation(script_content)
                if obfuscation_matches:
                    script_level_findings.append(
                        Finding(
                            rule_id="NPM-OBFUSCATION",
                            rule_name="Code obfuscation in lifecycle script",
                            severity=Severity.HIGH,
                            file_path=relative_path,
                            matched_content=obfuscation_matches[0].matched_text[:200],
                            description=f"Script '{script_name}' contains obfuscated code ({obfuscation_matches[0].pattern_name})",
                            recommendation="Deobfuscate and inspect. Legitimate packages rarely use obfuscation.",
                            plugin_name=self.get_metadata()["name"],
                        )
                    )

            # Pin all script-level findings to the actual line in package.json.
            # This replaces the meaningless line-1 default with the real script line
            # so GitHub Code Scanning shows the "scriptName": "command" line as context.
            if script_json_line:
                for finding in script_level_findings:
                    finding.line_number = script_json_line
                    finding.context_lines = get_context_lines(raw_content, script_json_line)

            # Track if this is preinstall with suspicious content
            if script_name == "preinstall" and script_level_findings:
                has_suspicious_preinstall = True
                preinstall_findings_indices.extend(
                    range(len(findings), len(findings) + len(script_level_findings))
                )

            findings.extend(script_level_findings)

            # JS file findings are separate — they have their own line numbers
            # in the referenced file and must not be overwritten with json line.
            if script_name in LIFECYCLE_SCRIPTS:
                referenced_files = self._extract_script_files(script_content)
                for file_ref in referenced_files:
                    js_path = (pkg_path.parent / file_ref).resolve()
                    js_findings = self._scan_js_file(js_path, root, script_name, pkg_path)
                    findings.extend(js_findings)

        # Escalate severity for preinstall scripts with suspicious content
        for idx in preinstall_findings_indices:
            if idx < len(findings):
                finding = findings[idx]
                # Escalate severity by one level
                if finding.severity == Severity.HIGH:
                    finding.severity = Severity.CRITICAL
                    finding.description = f"[PREINSTALL ESCALATION] {finding.description} (Found in preinstall script, which executes earlier and has wider impact)"
                elif finding.severity == Severity.MEDIUM:
                    finding.severity = Severity.HIGH
                    finding.description = f"[PREINSTALL ESCALATION] {finding.description} (Found in preinstall script)"

        # Add informational finding if preinstall exists with suspicious content
        if has_suspicious_preinstall:
            try:
                relative_path = pkg_path.relative_to(root)
            except ValueError:
                relative_path = pkg_path

            preinstall_line = script_line_numbers.get("preinstall")
            findings.append(
                Finding(
                    rule_id="NPM-019",
                    rule_name="Preinstall script with suspicious patterns",
                    severity=Severity.MEDIUM,
                    file_path=relative_path,
                    line_number=preinstall_line,
                    matched_content=f"preinstall: {scripts['preinstall'][:100]}...",
                    context_lines=get_context_lines(raw_content, preinstall_line) if preinstall_line else None,
                    description="This package uses a preinstall script combined with suspicious patterns. Preinstall scripts execute before dependencies are installed and are less commonly used by legitimate packages.",
                    recommendation="Review the preinstall script contents carefully. Consider whether this package genuinely needs to run code before dependency installation.",
                    plugin_name=self.get_metadata()["name"],
                )
            )

        # Stamp package identity onto every finding from this package.json
        pkg_label = f"[package: {pkg_name}@{pkg_version}]"
        for finding in findings:
            finding.metadata = pkg_meta
            finding.description = f"{pkg_label} {finding.description}"

        return findings

    def get_metadata(self) -> dict:
        """Return plugin metadata."""
        return {
            "name": "npm-lifecycle",
            "version": "0.1.0",
            "author": "Dev Trust Scanner",
            "description": "Detects malicious patterns in npm lifecycle scripts (postinstall, preinstall, etc.)",
        }

    def get_supported_files(self) -> list[str]:
        """Return supported file patterns."""
        return ["package.json"]
