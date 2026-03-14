"""Static analysis utilities for detecting malicious patterns."""

import math
import re
from pathlib import Path
from typing import Optional

from .models import Finding, Match, Rule, Severity


# Compiled regex patterns for performance
_BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
_HEX_ESCAPE_PATTERN = re.compile(r'\\x[0-9a-fA-F]{2}')
_UNICODE_ESCAPE_PATTERN = re.compile(r'\\u[0-9a-fA-F]{4}')
_CHAR_CODE_PATTERN = re.compile(r'(?:String\.fromCharCode|chr)\s*\(')
_CURL_PIPE_SH = re.compile(r'(?:curl|wget)\s+[^\|]+\|\s*(?:sh|bash)', re.IGNORECASE)
_POWERSHELL_CRADLE = re.compile(
    r'(?:IEX|Invoke-Expression|Invoke-WebRequest|iwr).*\|.*(?:IEX|Invoke-Expression)',
    re.IGNORECASE
)
_DEV_TCP = re.compile(r'/dev/tcp/[^\s]+')
_EVAL_NETWORK = re.compile(r'eval.*(?:http|https|fetch|ajax)', re.IGNORECASE)


def detect_base64(text: str, min_length: int = 40) -> list[Match]:
    """
    Detect base64-encoded strings in text.

    Args:
        text: Text to search
        min_length: Minimum length for base64 strings (default 40)

    Returns:
        List of Match objects for each base64 string found
    """
    if not text:
        return []

    matches = []
    pattern = re.compile(f'[A-Za-z0-9+/]{{{min_length},}}={{0,2}}')

    for match in pattern.finditer(text):
        matched_text = match.group()

        # Filter out false positives (UUIDs, hex strings without padding)
        if '=' not in matched_text and len(set(matched_text)) < 10:
            continue  # Too few unique characters, likely not base64

        matches.append(Match(
            pattern_name="base64",
            matched_text=matched_text[:100],  # Truncate for readability
            start_position=match.start(),
            end_position=match.end(),
            line_number=_position_to_line(text, match.start())
        ))

    return matches


def detect_obfuscation(text: str) -> list[Match]:
    """
    Detect obfuscation techniques in text.

    Detects:
    - Hex escapes (\\xNN)
    - Unicode escapes (\\uNNNN)
    - Character code building (String.fromCharCode, chr)
    - Excessive string concatenation

    Args:
        text: Text to search

    Returns:
        List of Match objects for obfuscation patterns
    """
    if not text:
        return []

    matches = []

    # Hex escapes
    for match in _HEX_ESCAPE_PATTERN.finditer(text):
        matches.append(Match(
            pattern_name="hex_escape",
            matched_text=match.group(),
            start_position=match.start(),
            end_position=match.end(),
            line_number=_position_to_line(text, match.start())
        ))

    # Unicode escapes
    for match in _UNICODE_ESCAPE_PATTERN.finditer(text):
        matches.append(Match(
            pattern_name="unicode_escape",
            matched_text=match.group(),
            start_position=match.start(),
            end_position=match.end(),
            line_number=_position_to_line(text, match.start())
        ))

    # Character code building
    for match in _CHAR_CODE_PATTERN.finditer(text):
        context_start = max(0, match.start() - 10)
        context_end = min(len(text), match.end() + 50)
        context = text[context_start:context_end]

        matches.append(Match(
            pattern_name="char_code_building",
            matched_text=context,
            start_position=match.start(),
            end_position=match.end(),
            line_number=_position_to_line(text, match.start())
        ))

    # Excessive string concatenation (e.g., "a"+"b"+"c"+"d"...)
    concat_pattern = re.compile(r'["\'][^"\']{1,5}["\'](?:\s*\+\s*["\'][^"\']{1,5}["\']){5,}')
    for match in concat_pattern.finditer(text):
        matches.append(Match(
            pattern_name="string_concatenation",
            matched_text=match.group()[:100],
            start_position=match.start(),
            end_position=match.end(),
            line_number=_position_to_line(text, match.start())
        ))

    return matches


def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of text in bits per character.

    High entropy (>4.5) may indicate encoded/encrypted content.

    Args:
        text: Text to analyze

    Returns:
        Entropy in bits per character (0.0 for empty string)
    """
    if not text:
        return 0.0

    # Calculate frequency of each character
    char_counts = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1

    # Calculate entropy
    text_len = len(text)
    entropy = 0.0

    for count in char_counts.values():
        probability = count / text_len
        entropy -= probability * math.log2(probability)

    return round(entropy, 2)


def check_ioc_patterns(text: str, ioc_patterns: list[str]) -> list[Match]:
    """
    Match text against IOC (Indicator of Compromise) patterns.

    Args:
        text: Text to search
        ioc_patterns: List of regex patterns (domains, IPs, URLs)

    Returns:
        List of Match objects for each IOC pattern that matched
    """
    if not text or not ioc_patterns:
        return []

    matches = []

    for pattern_str in ioc_patterns:
        try:
            pattern = re.compile(pattern_str, re.IGNORECASE)

            for match in pattern.finditer(text):
                matches.append(Match(
                    pattern_name=f"ioc_{pattern_str[:30]}",
                    matched_text=match.group(),
                    start_position=match.start(),
                    end_position=match.end(),
                    line_number=_position_to_line(text, match.start())
                ))
        except re.error:
            # Skip invalid regex patterns
            continue

    return matches


def detect_suspicious_commands(text: str) -> list[Match]:
    """
    Detect suspicious shell commands and download cradles.

    Detects:
    - curl/wget piped to sh/bash
    - PowerShell download cradles (IEX, Invoke-WebRequest)
    - eval with network calls
    - /dev/tcp/ network redirections

    Args:
        text: Text to search

    Returns:
        List of Match objects for suspicious commands
    """
    if not text:
        return []

    matches = []

    # curl/wget | sh/bash
    for match in _CURL_PIPE_SH.finditer(text):
        matches.append(Match(
            pattern_name="curl_pipe_shell",
            matched_text=match.group(),
            start_position=match.start(),
            end_position=match.end(),
            line_number=_position_to_line(text, match.start())
        ))

    # PowerShell download cradles
    for match in _POWERSHELL_CRADLE.finditer(text):
        matches.append(Match(
            pattern_name="powershell_cradle",
            matched_text=match.group(),
            start_position=match.start(),
            end_position=match.end(),
            line_number=_position_to_line(text, match.start())
        ))

    # /dev/tcp/ redirection
    for match in _DEV_TCP.finditer(text):
        matches.append(Match(
            pattern_name="dev_tcp",
            matched_text=match.group(),
            start_position=match.start(),
            end_position=match.end(),
            line_number=_position_to_line(text, match.start())
        ))

    # eval with network calls
    for match in _EVAL_NETWORK.finditer(text):
        matches.append(Match(
            pattern_name="eval_with_network",
            matched_text=match.group()[:100],
            start_position=match.start(),
            end_position=match.end(),
            line_number=_position_to_line(text, match.start())
        ))

    return matches


def match_rules(
    text: str,
    rules: list[Rule],
    file_path: Path,
    plugin_name: str
) -> list[Finding]:
    """
    Apply detection rules against text and generate findings.

    This is the core rule matching engine used by all plugins.

    Args:
        text: Text to analyze
        rules: List of Rule objects to apply
        file_path: Path to file being scanned (for Finding)
        plugin_name: Name of plugin running the scan (for Finding)

    Returns:
        List of Finding objects for each rule match
    """
    if not text or not rules:
        return []

    findings = []

    for rule in rules:
        rule_matched = False
        matched_content = ""
        line_number: Optional[int] = None

        # Try pattern matching
        if rule.pattern:
            try:
                pattern = re.compile(rule.pattern, re.IGNORECASE)
                match = pattern.search(text)
                if match:
                    rule_matched = True
                    matched_content = match.group()[:200]  # Truncate
                    line_number = _position_to_line(text, match.start())
            except re.error:
                # Skip invalid regex
                continue

        # Try patterns (OR logic)
        elif rule.patterns:
            for pattern_str in rule.patterns:
                try:
                    pattern = re.compile(pattern_str, re.IGNORECASE)
                    match = pattern.search(text)
                    if match:
                        rule_matched = True
                        matched_content = match.group()[:200]
                        line_number = _position_to_line(text, match.start())
                        break  # First match wins
                except re.error:
                    continue

        # Try keywords (simple substring matching)
        elif rule.keywords:
            for keyword in rule.keywords:
                if keyword.lower() in text.lower():
                    rule_matched = True
                    # Find context around keyword
                    index = text.lower().index(keyword.lower())
                    start = max(0, index - 20)
                    end = min(len(text), index + len(keyword) + 20)
                    matched_content = text[start:end]
                    line_number = _position_to_line(text, index)
                    break

        # Create Finding if rule matched
        if rule_matched:
            # Only capture context for multi-line content (e.g. JS files).
            # Single-line command strings already have full content in matched_content.
            ctx = (
                get_context_lines(text, line_number)
                if (line_number and '\n' in text)
                else None
            )
            findings.append(Finding(
                rule_id=rule.id,
                rule_name=rule.name,
                severity=rule.severity,
                file_path=file_path,
                line_number=line_number,
                matched_content=matched_content,
                context_lines=ctx,
                description=rule.description,
                recommendation=rule.recommendation,
                plugin_name=plugin_name
            ))

    return findings


def get_context_lines(content: str, line_number: int, window: int = 4) -> list[str]:
    """
    Return lines surrounding line_number (1-based), ±window lines.

    Args:
        content: Full file text
        line_number: 1-based line number to centre on
        window: Number of lines before and after to include

    Returns:
        Slice of lines (may be fewer than 2*window+1 near file boundaries)
    """
    lines = content.splitlines()
    start = max(0, line_number - 1 - window)
    end = min(len(lines), line_number + window)
    return lines[start:end]


def _position_to_line(text: str, position: int) -> int:
    """
    Convert character position to line number.

    Args:
        text: Full text
        position: Character offset

    Returns:
        Line number (1-indexed)
    """
    if not text or position < 0:
        return 1

    return text[:position].count('\n') + 1
