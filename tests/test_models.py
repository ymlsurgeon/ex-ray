"""Tests for core data models."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from exray.core.models import Finding, Match, Rule, ScanResult, Severity


class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_values(self):
        """Test all severity levels are defined."""
        assert Severity.CRITICAL == "critical"
        assert Severity.HIGH == "high"
        assert Severity.MEDIUM == "medium"
        assert Severity.LOW == "low"

    def test_severity_ordering(self):
        """Test severity can be compared."""
        severities = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        assert len(severities) == 4


class TestMatch:
    """Tests for Match dataclass."""

    def test_match_creation(self):
        """Test creating a Match object."""
        match = Match(
            pattern_name="test_pattern",
            matched_text="eval(",
            start_position=10,
            end_position=15,
            line_number=5,
        )
        assert match.pattern_name == "test_pattern"
        assert match.matched_text == "eval("
        assert match.start_position == 10
        assert match.end_position == 15
        assert match.line_number == 5

    def test_match_without_line_number(self):
        """Test Match with optional line_number."""
        match = Match(
            pattern_name="test",
            matched_text="text",
            start_position=0,
            end_position=4,
        )
        assert match.line_number is None


class TestFinding:
    """Tests for Finding model."""

    def test_finding_creation(self):
        """Test creating a valid Finding."""
        finding = Finding(
            rule_id="NPM-001",
            rule_name="Suspicious eval",
            severity=Severity.HIGH,
            file_path=Path("package.json"),
            line_number=12,
            matched_content='eval("malicious")',
            description="Detected eval in npm script",
            recommendation="Remove eval usage",
            plugin_name="npm-lifecycle",
        )
        assert finding.rule_id == "NPM-001"
        assert finding.severity == Severity.HIGH
        assert isinstance(finding.file_path, Path)

    def test_finding_json_serialization(self):
        """Test Finding serializes to JSON correctly."""
        finding = Finding(
            rule_id="TEST-001",
            rule_name="Test Rule",
            severity=Severity.MEDIUM,
            file_path=Path("test.json"),
            matched_content="test content",
            description="Test description",
            recommendation="Test recommendation",
            plugin_name="test-plugin",
        )

        json_str = finding.model_dump_json()
        data = json.loads(json_str)

        assert data["rule_id"] == "TEST-001"
        assert data["severity"] == "medium"
        assert data["file_path"] == "test.json"  # Path serialized to string

    def test_finding_json_roundtrip(self):
        """Test Finding can be serialized and deserialized."""
        original = Finding(
            rule_id="NPM-002",
            rule_name="Base64 content",
            severity=Severity.HIGH,
            file_path=Path("src/index.js"),
            line_number=42,
            matched_content="YXRvYg==",
            description="Base64 encoding detected",
            recommendation="Decode and inspect",
            plugin_name="npm-lifecycle",
        )

        # Serialize to JSON
        json_str = original.model_dump_json()

        # Deserialize back
        data = json.loads(json_str)
        reconstructed = Finding(**data)

        assert reconstructed.rule_id == original.rule_id
        assert reconstructed.severity == original.severity
        assert str(reconstructed.file_path) == str(original.file_path)

    def test_finding_path_validation(self):
        """Test Finding accepts both string and Path for file_path."""
        # Test with Path
        finding1 = Finding(
            rule_id="TEST-001",
            rule_name="Test",
            severity=Severity.LOW,
            file_path=Path("test.txt"),
            matched_content="content",
            description="desc",
            recommendation="rec",
            plugin_name="test",
        )
        assert isinstance(finding1.file_path, Path)

        # Test with string (should be converted to Path)
        finding2 = Finding(
            rule_id="TEST-002",
            rule_name="Test",
            severity=Severity.LOW,
            file_path="test2.txt",
            matched_content="content",
            description="desc",
            recommendation="rec",
            plugin_name="test",
        )
        assert isinstance(finding2.file_path, Path)

    def test_finding_optional_line_number(self):
        """Test Finding with no line number."""
        finding = Finding(
            rule_id="TEST-003",
            rule_name="Test",
            severity=Severity.LOW,
            file_path=Path("test.txt"),
            matched_content="content",
            description="desc",
            recommendation="rec",
            plugin_name="test",
        )
        assert finding.line_number is None

    def test_finding_unicode_content(self):
        """Test Finding handles Unicode in matched_content."""
        finding = Finding(
            rule_id="TEST-004",
            rule_name="Test",
            severity=Severity.LOW,
            file_path=Path("test.txt"),
            matched_content="console.log('你好世界')",
            description="desc",
            recommendation="rec",
            plugin_name="test",
        )
        json_str = finding.model_dump_json()
        assert "你好世界" in json_str


class TestRule:
    """Tests for Rule model."""

    def test_rule_with_single_pattern(self):
        """Test Rule with single regex pattern."""
        rule = Rule(
            id="NPM-001",
            name="Eval detection",
            severity=Severity.HIGH,
            description="Detects eval usage",
            pattern=r"\beval\s*\(",
            recommendation="Remove eval",
        )
        assert rule.pattern == r"\beval\s*\("
        assert rule.patterns is None
        assert rule.keywords is None

    def test_rule_with_multiple_patterns(self):
        """Test Rule with multiple patterns (OR logic)."""
        rule = Rule(
            id="NPM-002",
            name="Obfuscation",
            severity=Severity.HIGH,
            description="Detects obfuscation",
            patterns=[r"\\x[0-9a-f]{2}", r"\\u[0-9a-f]{4}"],
            recommendation="Investigate obfuscation",
        )
        assert len(rule.patterns) == 2
        assert rule.pattern is None

    def test_rule_with_keywords(self):
        """Test Rule with keyword list."""
        rule = Rule(
            id="NPM-003",
            name="Network calls",
            severity=Severity.MEDIUM,
            description="Detects network calls",
            keywords=["curl", "wget", "http://"],
            recommendation="Verify network calls",
        )
        assert len(rule.keywords) == 3

    def test_rule_without_matching_strategy_fails(self):
        """Test Rule validation fails without pattern/patterns/keywords."""
        with pytest.raises(ValidationError) as exc_info:
            Rule(
                id="INVALID-001",
                name="Invalid",
                severity=Severity.LOW,
                description="Missing matching strategy",
                recommendation="N/A",
            )

        assert "at least one of: pattern, patterns, or keywords" in str(exc_info.value)

    def test_rule_json_serialization(self):
        """Test Rule serializes correctly."""
        rule = Rule(
            id="TEST-001",
            name="Test Rule",
            severity=Severity.MEDIUM,
            description="Test",
            patterns=["pattern1", "pattern2"],
            recommendation="Test rec",
        )

        json_str = rule.model_dump_json()
        data = json.loads(json_str)

        assert data["id"] == "TEST-001"
        assert data["severity"] == "medium"
        assert len(data["patterns"]) == 2

    def test_rule_with_extended_metadata(self):
        """Test Rule with Phase 2 extended metadata fields."""
        rule = Rule(
            id="NPM-LC-001",
            name="TruffleHog Binary Download",
            severity=Severity.CRITICAL,
            description="Detects TruffleHog downloads",
            patterns=["trufflesecurity/trufflehog"],
            recommendation="Remove package",
            # Extended metadata
            campaign="shai-hulud",
            confidence="high",
            false_positive_rate=0.0,
            references=[
                "https://reversinglabs.com/blog/shai-hulud",
                "https://opensourcemalware.com/sample/xyz",
            ],
            mitre_attack=["T1195.002", "T1552.001"],
            created="2025-02-10",
            updated="2025-02-10",
        )

        assert rule.campaign == "shai-hulud"
        assert rule.confidence == "high"
        assert rule.false_positive_rate == 0.0
        assert len(rule.references) == 2
        assert len(rule.mitre_attack) == 2
        assert rule.created == "2025-02-10"
        assert rule.updated == "2025-02-10"

    def test_rule_backward_compatibility(self):
        """Test old rules without metadata still work (backward compatibility)."""
        # Old-style rule without extended metadata
        rule = Rule(
            id="NPM-001",
            name="Eval detection",
            severity=Severity.HIGH,
            description="Detects eval",
            pattern=r"\beval\s*\(",
            recommendation="Remove eval",
        )

        # All metadata fields should be None
        assert rule.campaign is None
        assert rule.confidence is None
        assert rule.false_positive_rate is None
        assert rule.references is None
        assert rule.mitre_attack is None
        assert rule.created is None
        assert rule.updated is None

        # Rule should still function normally
        json_str = rule.model_dump_json()
        data = json.loads(json_str)
        assert data["id"] == "NPM-001"

    def test_rule_metadata_json_serialization(self):
        """Test Rule with metadata serializes to JSON correctly."""
        rule = Rule(
            id="NPM-LC-003",
            name="Campaign Markers",
            severity=Severity.CRITICAL,
            description="Shai-Hulud markers",
            patterns=["shai-hulud", "goldox-t3chs"],
            recommendation="Remove immediately",
            campaign="shai-hulud",
            confidence="high",
            false_positive_rate=0.0,
            references=["https://example.com/threat-intel"],
            mitre_attack=["T1195.002"],
            created="2025-02-12",
            updated="2025-02-12",
        )

        json_str = rule.model_dump_json()
        data = json.loads(json_str)

        assert data["campaign"] == "shai-hulud"
        assert data["confidence"] == "high"
        assert data["false_positive_rate"] == 0.0
        assert len(data["references"]) == 1
        assert data["mitre_attack"] == ["T1195.002"]

    def test_rule_metadata_json_roundtrip(self):
        """Test Rule with metadata can be serialized and deserialized."""
        original = Rule(
            id="NPM-LC-004",
            name="Webhook Exfiltration",
            severity=Severity.HIGH,
            description="Detects webhook exfil",
            patterns=["webhook\\.site"],
            recommendation="Investigate",
            campaign="shai-hulud",
            confidence="medium",
            false_positive_rate=0.1,
            references=["https://example.com"],
            mitre_attack=["T1041"],
        )

        # Serialize to JSON
        json_str = original.model_dump_json()

        # Deserialize back
        data = json.loads(json_str)
        reconstructed = Rule(**data)

        # Verify metadata preserved
        assert reconstructed.campaign == original.campaign
        assert reconstructed.confidence == original.confidence
        assert reconstructed.false_positive_rate == original.false_positive_rate
        assert reconstructed.references == original.references
        assert reconstructed.mitre_attack == original.mitre_attack

    def test_rule_false_positive_rate_validation(self):
        """Test false_positive_rate must be between 0.0 and 1.0."""
        # Valid: 0.0
        rule1 = Rule(
            id="TEST-001",
            name="Test",
            severity=Severity.LOW,
            description="Test",
            pattern="test",
            recommendation="Test",
            false_positive_rate=0.0,
        )
        assert rule1.false_positive_rate == 0.0

        # Valid: 1.0
        rule2 = Rule(
            id="TEST-002",
            name="Test",
            severity=Severity.LOW,
            description="Test",
            pattern="test",
            recommendation="Test",
            false_positive_rate=1.0,
        )
        assert rule2.false_positive_rate == 1.0

        # Valid: 0.5
        rule3 = Rule(
            id="TEST-003",
            name="Test",
            severity=Severity.LOW,
            description="Test",
            pattern="test",
            recommendation="Test",
            false_positive_rate=0.5,
        )
        assert rule3.false_positive_rate == 0.5

        # Invalid: > 1.0
        with pytest.raises(ValidationError) as exc_info:
            Rule(
                id="TEST-004",
                name="Test",
                severity=Severity.LOW,
                description="Test",
                pattern="test",
                recommendation="Test",
                false_positive_rate=1.5,
            )
        assert "less than or equal to 1" in str(exc_info.value).lower()

        # Invalid: < 0.0
        with pytest.raises(ValidationError) as exc_info:
            Rule(
                id="TEST-005",
                name="Test",
                severity=Severity.LOW,
                description="Test",
                pattern="test",
                recommendation="Test",
                false_positive_rate=-0.1,
            )
        assert "greater than or equal to 0" in str(exc_info.value).lower()

    def test_rule_partial_metadata(self):
        """Test Rule can have some metadata fields but not all."""
        # Only campaign and confidence
        rule = Rule(
            id="TEST-006",
            name="Test",
            severity=Severity.MEDIUM,
            description="Test",
            pattern="test",
            recommendation="Test",
            campaign="test-campaign",
            confidence="medium",
        )

        assert rule.campaign == "test-campaign"
        assert rule.confidence == "medium"
        assert rule.false_positive_rate is None  # Not provided
        assert rule.references is None  # Not provided
        assert rule.mitre_attack is None  # Not provided


class TestScanResult:
    """Tests for ScanResult model."""

    def test_scan_result_creation(self):
        """Test creating a ScanResult."""
        result = ScanResult(
            target_path=Path("/path/to/project"),
            findings=[],
            plugins_run=["npm-lifecycle", "vscode-tasks"],
            scan_duration_seconds=1.23,
            summary={"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
        )
        assert isinstance(result.target_path, Path)
        assert len(result.findings) == 0
        assert len(result.plugins_run) == 2
        assert result.scan_duration_seconds == 1.23

    def test_scan_result_with_findings(self):
        """Test ScanResult with multiple findings."""
        findings = [
            Finding(
                rule_id="NPM-001",
                rule_name="Test",
                severity=Severity.HIGH,
                file_path=Path("package.json"),
                matched_content="eval()",
                description="desc",
                recommendation="rec",
                plugin_name="npm",
            ),
            Finding(
                rule_id="VSC-001",
                rule_name="Test",
                severity=Severity.CRITICAL,
                file_path=Path(".vscode/tasks.json"),
                matched_content='runOn: "folderOpen"',
                description="desc",
                recommendation="rec",
                plugin_name="vscode",
            ),
        ]

        result = ScanResult(
            target_path=Path("."),
            findings=findings,
            plugins_run=["npm-lifecycle", "vscode-tasks"],
            scan_duration_seconds=2.5,
            summary={},
        )

        assert len(result.findings) == 2

    def test_scan_result_calculate_summary(self):
        """Test summary calculation from findings."""
        findings = [
            Finding(
                rule_id="T1",
                rule_name="T",
                severity=Severity.CRITICAL,
                file_path=Path("f1"),
                matched_content="c",
                description="d",
                recommendation="r",
                plugin_name="p",
            ),
            Finding(
                rule_id="T2",
                rule_name="T",
                severity=Severity.HIGH,
                file_path=Path("f2"),
                matched_content="c",
                description="d",
                recommendation="r",
                plugin_name="p",
            ),
            Finding(
                rule_id="T3",
                rule_name="T",
                severity=Severity.HIGH,
                file_path=Path("f3"),
                matched_content="c",
                description="d",
                recommendation="r",
                plugin_name="p",
            ),
            Finding(
                rule_id="T4",
                rule_name="T",
                severity=Severity.MEDIUM,
                file_path=Path("f4"),
                matched_content="c",
                description="d",
                recommendation="r",
                plugin_name="p",
            ),
        ]

        result = ScanResult(
            target_path=Path("."),
            findings=findings,
            plugins_run=["test"],
            scan_duration_seconds=1.0,
            summary={},
        )

        summary = result.calculate_summary()

        assert summary["critical"] == 1
        assert summary["high"] == 2
        assert summary["medium"] == 1
        assert summary["low"] == 0
        assert summary["total"] == 4

    def test_scan_result_empty_findings(self):
        """Test ScanResult with no findings."""
        result = ScanResult(
            target_path=Path("."),
            scan_duration_seconds=0.5,
            summary={},
        )

        assert len(result.findings) == 0
        assert len(result.plugins_run) == 0
        summary = result.calculate_summary()
        assert summary["total"] == 0

    def test_scan_result_json_serialization(self):
        """Test ScanResult serializes to JSON."""
        result = ScanResult(
            target_path=Path("/project"),
            findings=[],
            plugins_run=["npm-lifecycle"],
            scan_duration_seconds=1.5,
            summary={"total": 0},
        )

        json_str = result.model_dump_json()
        data = json.loads(json_str)

        assert data["target_path"] == "/project"
        assert data["scan_duration_seconds"] == 1.5

    def test_scan_result_path_validation(self):
        """Test ScanResult accepts string or Path for target_path."""
        # With Path
        result1 = ScanResult(
            target_path=Path("/test"),
            scan_duration_seconds=1.0,
            summary={},
        )
        assert isinstance(result1.target_path, Path)

        # With string
        result2 = ScanResult(
            target_path="/test2",
            scan_duration_seconds=1.0,
            summary={},
        )
        assert isinstance(result2.target_path, Path)

    def test_scan_result_long_content(self):
        """Test ScanResult handles very long matched_content."""
        long_content = "A" * 10000  # 10K characters
        finding = Finding(
            rule_id="TEST-001",
            rule_name="Test",
            severity=Severity.LOW,
            file_path=Path("test.txt"),
            matched_content=long_content,
            description="desc",
            recommendation="rec",
            plugin_name="test",
        )

        result = ScanResult(
            target_path=Path("."),
            findings=[finding],
            plugins_run=["test"],
            scan_duration_seconds=1.0,
            summary={},
        )

        json_str = result.model_dump_json()
        assert len(json_str) > 10000  # Should contain the long content
