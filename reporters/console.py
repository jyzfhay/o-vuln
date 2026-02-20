"""Rich terminal reporter — colorized tables, severity badges, CVE links."""
from typing import List
from collections import Counter

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule
from rich import box
from rich.columns import Columns
from rich.padding import Padding

from core.models import CVEReference, Finding, Severity

console = Console()

_SEV_COLORS = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH:     "bold red",
    Severity.MEDIUM:   "bold yellow",
    Severity.LOW:      "bold cyan",
    Severity.INFO:     "bold blue",
    Severity.UNKNOWN:  "dim white",
}

_SEV_BADGE = {
    Severity.CRITICAL: "[bold white on red] CRIT [/bold white on red]",
    Severity.HIGH:     "[bold red] HIGH [/bold red]",
    Severity.MEDIUM:   "[bold yellow] MED  [/bold yellow]",
    Severity.LOW:      "[bold cyan] LOW  [/bold cyan]",
    Severity.INFO:     "[bold blue] INFO [/bold blue]",
    Severity.UNKNOWN:  "[dim] UNK  [/dim]",
}

_SCANNER_ICON = {
    "dependency": "📦",
    "sast":       "🔍",
    "network":    "🌐",
}


def print_banner() -> None:
    console.print()
    console.print(Panel.fit(
        "[bold cyan]VulnScan[/bold cyan]  [dim]|  CVE-Validated Security Scanner[/dim]\n"
        "[dim]OSV · NVD · MITRE · SAST · Network[/dim]",
        border_style="cyan",
        padding=(0, 2),
    ))
    console.print()


def print_scan_start(scanner: str, target: str) -> None:
    icon = _SCANNER_ICON.get(scanner, "⚙️")
    console.print(f"{icon}  [bold]Starting {scanner} scan[/bold] → [cyan]{target}[/cyan]")


def print_findings(findings: List[Finding], verbose: bool = False) -> None:
    if not findings:
        console.print("\n[bold green]✓ No findings![/bold green]\n")
        return

    sorted_findings = sorted(findings, key=lambda f: f.worst_severity().sort_key)

    console.print()
    console.print(Rule("[bold]Findings[/bold]", style="dim"))
    console.print()

    for finding in sorted_findings:
        _print_finding(finding, verbose)

    _print_summary(findings)


def _print_finding(finding: Finding, verbose: bool) -> None:
    sev = finding.worst_severity()
    badge = _SEV_BADGE[sev]
    icon = _SCANNER_ICON.get(finding.scanner, "⚠️")

    # Title line
    loc_suffix = f":{finding.line_number}" if finding.line_number else ""
    console.print(
        f"{badge} {icon} [bold]{finding.title}[/bold]  "
        f"[dim]{finding.location}{loc_suffix}[/dim]"
    )

    if verbose or sev in (Severity.CRITICAL, Severity.HIGH):
        console.print(f"   [italic dim]{finding.description}[/italic dim]")

        if finding.evidence:
            console.print(f"   [dim]Evidence:[/dim] [red]{finding.evidence}[/red]")

        if finding.remediation:
            console.print(f"   [dim]Fix:[/dim] [green]{finding.remediation}[/green]")

        if finding.cve_refs:
            _print_cve_refs(finding.cve_refs)

    console.print()


def _print_cve_refs(cve_refs: List[CVEReference]) -> None:
    table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="bold dim",
        padding=(0, 1),
        expand=False,
    )
    table.add_column("CVE / ID", style="cyan", no_wrap=True)
    table.add_column("CVSS", justify="right", no_wrap=True)
    table.add_column("Severity")
    table.add_column("Published", no_wrap=True)
    table.add_column("NVD Link", style="blue dim")

    for ref in sorted(cve_refs, key=lambda r: r.severity.sort_key):
        score_str = f"{ref.cvss_score:.1f}" if ref.cvss_score is not None else "—"
        sev_text = Text(ref.severity.value, style=_SEV_COLORS.get(ref.severity, "white"))
        nvd = ref.nvd_url if ref.nvd_url else ref.mitre_url
        table.add_row(
            ref.cve_id,
            score_str,
            sev_text,
            ref.published or "—",
            nvd,
        )

    console.print(Padding(table, (0, 0, 0, 4)))


def _print_summary(findings: List[Finding]) -> None:
    console.print(Rule("[bold]Summary[/bold]", style="dim"))
    console.print()

    sev_counts: Counter = Counter()
    scanner_counts: Counter = Counter()
    for f in findings:
        sev_counts[f.worst_severity()] += 1
        scanner_counts[f.scanner] += 1

    # Severity breakdown
    sev_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    sev_table.add_column("Sev")
    sev_table.add_column("Count", justify="right")

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO, Severity.UNKNOWN]:
        count = sev_counts.get(sev, 0)
        if count > 0:
            badge = _SEV_BADGE[sev]
            sev_table.add_row(badge, f"[bold]{count}[/bold]")

    # Scanner breakdown
    scan_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    scan_table.add_column("Scanner")
    scan_table.add_column("Count", justify="right")

    for scanner, count in scanner_counts.most_common():
        icon = _SCANNER_ICON.get(scanner, "⚠️")
        scan_table.add_row(f"{icon}  {scanner}", f"[bold]{count}[/bold]")

    console.print(Columns([
        Panel(sev_table, title="By Severity", border_style="dim", expand=False),
        Panel(scan_table, title="By Scanner", border_style="dim", expand=False),
    ]))

    total = len(findings)
    critical = sev_counts.get(Severity.CRITICAL, 0)
    high = sev_counts.get(Severity.HIGH, 0)

    console.print()
    if critical > 0:
        console.print(f"[bold red]⚠  {critical} CRITICAL and {high} HIGH findings require immediate attention.[/bold red]")
    elif high > 0:
        console.print(f"[bold yellow]⚠  {high} HIGH findings require attention.[/bold yellow]")
    else:
        console.print(f"[bold green]✓  {total} findings, none critical or high severity.[/bold green]")
    console.print()


def print_no_targets(scanner: str) -> None:
    console.print(f"[yellow]⚠  No targets found for {scanner} scanner.[/yellow]")
