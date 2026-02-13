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
            findings.append(
                Finding(
                    rule_id="NPM-BASE64",
                    rule_name="Base64 content in lifecycle script file",
                    severity=Severity.HIGH,
                    file_path=relative_path,
                    line_number=base64_matches[0].line_number,
                    matched_content=base64_matches[0].matched_text,
                    description=f"File executed by '{script_name}' contains base64-encoded content",
                    recommendation="Decode the base64 content and verify it is legitimate.",
                    plugin_name=self.get_metadata()["name"],
                )
            )

        # Obfuscation detection
        obfuscation_matches = detect_obfuscation(js_content)
        if obfuscation_matches:
            findings.append(
                Finding(
                    rule_id="NPM-OBFUSCATION",
                    rule_name="Code obfuscation in lifecycle script file",
                    severity=Severity.HIGH,
                    file_path=relative_path,
                    line_number=obfuscation_matches[0].line_number,
                    matched_content=obfuscation_matches[0].matched_text[:200],
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

        # Parse JSON with error handling
        try:
            with open(pkg_path, encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            logger.warning(f"Malformed JSON in {pkg_path}: {e}")
            return []
        except Exception as e:
            logger.warning(f"Could not read {pkg_path}: {e}")
            return []

        # Extract scripts section
        scripts = data.get("scripts", {})
        if not scripts or not isinstance(scripts, dict):
            return []

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

            # Apply detection rules to the script command itself
            script_findings = match_rules(
                text=script_content,
                rules=self.rules,
                file_path=relative_path,
                plugin_name=self.get_metadata()["name"],
            )

            # Tag lifecycle scripts with higher severity
            if script_name in LIFECYCLE_SCRIPTS:
                for finding in script_findings:
                    # Add context that this is a lifecycle script
                    finding.description = (
                        f"[Lifecycle script: {script_name}] {finding.description}"
                    )

            # Track if this is preinstall with suspicious content
            if script_name == "preinstall" and script_findings:
                has_suspicious_preinstall = True
                preinstall_findings_indices.extend(
                    range(len(findings), len(findings) + len(script_findings))
                )

            findings.extend(script_findings)

            # For lifecycle scripts, also scan any referenced JavaScript files
            if script_name in LIFECYCLE_SCRIPTS:
                referenced_files = self._extract_script_files(script_content)
                for file_ref in referenced_files:
                    # Resolve path relative to package.json location
                    js_path = (pkg_path.parent / file_ref).resolve()

                    # Scan the referenced JavaScript file
                    js_findings = self._scan_js_file(
                        js_path, root, script_name, pkg_path
                    )
                    findings.extend(js_findings)

            # Additional checks for lifecycle scripts
            if script_name in LIFECYCLE_SCRIPTS:
                # High entropy check (encoded/encrypted content)
                entropy = calculate_entropy(script_content)
                if entropy > ENTROPY_THRESHOLD:
                    findings.append(
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
                    findings.append(
                        Finding(
                            rule_id="NPM-BASE64",
                            rule_name="Base64 content detected in lifecycle script",
                            severity=Severity.HIGH,
                            file_path=relative_path,
                            line_number=base64_matches[0].line_number,
                            matched_content=base64_matches[0].matched_text,
                            description=f"Script '{script_name}' contains base64-encoded content",
                            recommendation="Decode the base64 content and verify it is legitimate.",
                            plugin_name=self.get_metadata()["name"],
                        )
                    )

                # Obfuscation detection
                obfuscation_matches = detect_obfuscation(script_content)
                if obfuscation_matches:
                    findings.append(
                        Finding(
                            rule_id="NPM-OBFUSCATION",
                            rule_name="Code obfuscation in lifecycle script",
                            severity=Severity.HIGH,
                            file_path=relative_path,
                            line_number=obfuscation_matches[0].line_number,
                            matched_content=obfuscation_matches[0].matched_text[:200],
                            description=f"Script '{script_name}' contains obfuscated code ({obfuscation_matches[0].pattern_name})",
                            recommendation="Deobfuscate and inspect. Legitimate packages rarely use obfuscation.",
                            plugin_name=self.get_metadata()["name"],
                        )
                    )

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

            findings.append(
                Finding(
                    rule_id="NPM-019",
                    rule_name="Preinstall script with suspicious patterns",
                    severity=Severity.MEDIUM,
                    file_path=relative_path,
                    matched_content=f"preinstall: {scripts['preinstall'][:100]}...",
                    description="This package uses a preinstall script combined with suspicious patterns. Preinstall scripts execute before dependencies are installed and are less commonly used by legitimate packages.",
                    recommendation="Review the preinstall script contents carefully. Consider whether this package genuinely needs to run code before dependency installation.",
                    plugin_name=self.get_metadata()["name"],
                )
            )

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
