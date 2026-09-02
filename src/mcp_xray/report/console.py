"""Rich terminal report — the 'scary red table'. No composite letter grade
(Round 1 review: an invented CVSS-lite number is the easiest thing to poke a
hole in) — per-finding severity plus a plain count summary instead.
"""
from __future__ import annotations

from rich.console import Console
from rich.table import Table

from ..probes.base import Finding, Severity

_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "dim",
}


def render(findings: list[Finding], server_label: str) -> None:
    console = Console()
    findings = sorted(findings, key=lambda f: -f.severity.rank)

    table = Table(title=f"mcp-xray > {server_label}")
    table.add_column("SEV")
    table.add_column("CATEGORY")
    table.add_column("TARGET")
    table.add_column("FINDING")

    for f in findings:
        style = _STYLE[f.severity]
        table.add_row(
            f"[{style}]{f.severity.value.upper()}[/{style}]",
            f.category,
            f.target,
            f.summary,
        )

    console.print(table)

    counts = {s: sum(1 for f in findings if f.severity == s) for s in Severity}
    summary = " · ".join(f"{counts[s]} {s.value}" for s in Severity if counts[s])
    console.print(f"\n{len(findings)} findings — {summary or 'none'}")
