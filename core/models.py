"""Core data models for VulnScan findings."""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_cvss(cls, score: Optional[float]) -> "Severity":
        if score is None:
            return cls.UNKNOWN
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0:
            return cls.LOW
        return cls.INFO

    def rich_style(self) -> str:
        return {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "blue",
            "UNKNOWN": "dim white",
        }.get(self.value, "white")

    def emoji(self) -> str:
        return {
            "CRITICAL": "[bold red]CRIT[/bold red]",
            "HIGH": "[red]HIGH[/red]",
            "MEDIUM": "[yellow]MED [/yellow]",
            "LOW": "[cyan]LOW [/cyan]",
            "INFO": "[blue]INFO[/blue]",
            "UNKNOWN": "[dim]UNK [/dim]",
        }.get(self.value, "    ")

    @property
    def sort_key(self) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}.get(self.value, 99)


@dataclass
class CVEReference:
    cve_id: str
    description: str
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    severity: Severity = Severity.UNKNOWN
    nvd_url: str = ""
    mitre_url: str = ""
    published: Optional[str] = None
    fixed_versions: List[str] = field(default_factory=list)


@dataclass
class Finding:
    title: str
    description: str
    scanner: str  # "dependency" | "sast" | "network"
    severity: Severity
    location: str
    cve_refs: List[CVEReference] = field(default_factory=list)
    remediation: Optional[str] = None
    evidence: Optional[str] = None
    line_number: Optional[int] = None

    def worst_severity(self) -> Severity:
        if not self.cve_refs:
            return self.severity
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO, Severity.UNKNOWN]
        for sev in order:
            if any(r.severity == sev for r in self.cve_refs):
                return sev
        return self.severity

    def max_cvss(self) -> Optional[float]:
        scores = [r.cvss_score for r in self.cve_refs if r.cvss_score is not None]
        return max(scores) if scores else None

    def scanner_icon(self) -> str:
        return {"dependency": "📦", "sast": "🔍", "network": "🌐"}.get(self.scanner, "⚠️")
