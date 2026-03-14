"""Core data models for Dev Trust Scanner."""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field, field_serializer, field_validator, model_validator


class Severity(str, Enum):
    """Severity levels for security findings."""

    CRITICAL = "critical"  # Active exploitation pattern (known malware signature)
    HIGH = "high"  # Strong malicious indicators (obfuscated eval + network)
    MEDIUM = "medium"  # Suspicious patterns (base64 in lifecycle script)
    LOW = "low"  # Informational (lifecycle script exists but benign)


@dataclass
class Match:
    """
    Pattern match result from static analysis.

    Attributes:
        pattern_name: Name of the pattern that matched
        matched_text: The actual text that matched
        start_position: Character offset where match starts
        end_position: Character offset where match ends
        line_number: Line number of the match (optional)
    """

    pattern_name: str
    matched_text: str
    start_position: int
    end_position: int
    line_number: Optional[int] = None


class Finding(BaseModel):
    """
    A security finding detected by a scanner plugin.

    Represents a single detected issue with all context needed for
    reporting and remediation.
    """

    rule_id: str = Field(..., description="Unique rule identifier (e.g., NPM-001)")
    rule_name: str = Field(..., description="Human-readable rule name")
    severity: Severity = Field(..., description="Severity level of the finding")
    file_path: Path = Field(..., description="Path to file containing the finding")
    line_number: Optional[int] = Field(None, description="Line number in the file")
    matched_content: str = Field(..., description="The suspicious content found")
    context_lines: Optional[list[str]] = Field(
        None,
        description="Surrounding lines of code (±window) for analyst context",
    )
    description: str = Field(..., description="What was detected and why it matters")
    recommendation: str = Field(..., description="Remediation advice")
    plugin_name: str = Field(..., description="Plugin that produced this finding")

    @field_serializer("file_path")
    def serialize_path(self, path: Path) -> str:
        """Serialize Path to string for JSON output."""
        return str(path)

    @field_validator("file_path", mode="before")
    @classmethod
    def validate_path(cls, v):
        """Convert string to Path if needed."""
        if isinstance(v, str):
            return Path(v)
        return v


class Rule(BaseModel):
    """
    Detection rule definition loaded from YAML.

    Rules support multiple matching strategies:
    - Single pattern (regex)
    - Multiple patterns (OR logic)
    - Keyword list (simple string matching)

    Phase 2 Extended Metadata (optional, for campaign tracking):
    - campaign: Campaign name (e.g., "shai-hulud", "contagious-interview")
    - confidence: Detection confidence ("high" | "medium" | "low")
    - false_positive_rate: Measured FP rate (0.0 to 1.0)
    - references: Threat intelligence URLs
    - mitre_attack: MITRE ATT&CK technique IDs
    - created/updated: ISO8601 timestamps
    """

    # Core rule fields (Phase 1)
    id: str = Field(..., description="Unique rule identifier")
    name: str = Field(..., description="Human-readable rule name")
    severity: Severity = Field(..., description="Severity if rule matches")
    description: str = Field(..., description="What this rule detects")
    pattern: Optional[str] = Field(None, description="Single regex pattern")
    patterns: Optional[list[str]] = Field(None, description="Multiple patterns (OR)")
    keywords: Optional[list[str]] = Field(None, description="Simple keyword list")
    recommendation: str = Field(..., description="Remediation advice")

    # Extended metadata fields (Phase 2 - all optional for backward compatibility)
    campaign: Optional[str] = Field(
        None, description="Campaign name (e.g., 'shai-hulud')"
    )
    confidence: Optional[str] = Field(
        None, description="Detection confidence: 'high' | 'medium' | 'low'"
    )
    false_positive_rate: Optional[float] = Field(
        None,
        description="Measured false positive rate (0.0 = 0%, 1.0 = 100%)",
        ge=0.0,
        le=1.0,
    )
    references: Optional[list[str]] = Field(
        None, description="Threat intelligence URLs and documentation"
    )
    mitre_attack: Optional[list[str]] = Field(
        None, description="MITRE ATT&CK technique IDs (e.g., T1195.002)"
    )
    created: Optional[str] = Field(None, description="Rule creation date (ISO8601)")
    updated: Optional[str] = Field(None, description="Last update date (ISO8601)")

    @model_validator(mode="after")
    def validate_matching_strategy(self):
        """Ensure at least one matching strategy is defined."""
        if not any([self.pattern, self.patterns, self.keywords]):
            raise ValueError(
                "Rule must have at least one of: pattern, patterns, or keywords"
            )
        return self


class ScanResult(BaseModel):
    """
    Aggregated results from a complete scan.

    Contains findings from all plugins, execution metadata, and summary statistics.
    """

    target_path: Path = Field(..., description="Root directory that was scanned")
    findings: list[Finding] = Field(
        default_factory=list, description="All findings from all plugins"
    )
    plugins_run: list[str] = Field(
        default_factory=list, description="Names of plugins that executed"
    )
    scan_duration_seconds: float = Field(..., description="Total scan time")
    summary: dict[str, int] = Field(
        default_factory=dict, description="Severity counts and totals"
    )

    @field_serializer("target_path")
    def serialize_path(self, path: Path) -> str:
        """Serialize Path to string for JSON output."""
        return str(path)

    @field_validator("target_path", mode="before")
    @classmethod
    def validate_path(cls, v):
        """Convert string to Path if needed."""
        if isinstance(v, str):
            return Path(v)
        return v

    def calculate_summary(self) -> dict[str, int]:
        """
        Calculate severity summary from findings.

        Returns:
            Dictionary with counts per severity level plus total
        """
        summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "total": len(self.findings),
        }

        for finding in self.findings:
            summary[finding.severity.value] += 1

        return summary
