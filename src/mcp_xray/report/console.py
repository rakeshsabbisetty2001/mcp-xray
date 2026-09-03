"""Rich terminal report — the 'scary red table'. No composite letter grade
(Round 1 review: an invented CVSS-lite number is the easiest thing to poke a
hole in) — per-finding severity plus a plain count summary instead.
"""
from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from ..probes.base import Finding, Severity

_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "dim",
}
_MAX_EVIDENCE_CHARS = 80


def _display_safe(text: str) -> str:
    """unicode_escape makes hidden/bidi characters visible as \\uXXXX
    instead of invisible or reordering the row — applied to every
    server-controlled field, not just evidence (whole-repo review: html.py
    already did this for target/summary/server_label, console.py only did
    it for evidence — a hostile tool name with an RLO char could reorder
    this table's TARGET column undetected)."""
    return text.encode("unicode_escape").decode("ascii")


def render(findings: list[Finding], server_label: str) -> None:
    console = Console()
    findings = sorted(findings, key=lambda f: -f.severity.rank)

    table = Table(title=f"mcp-xray > {_display_safe(server_label)}")
    table.add_column("SEV")
    table.add_column("CATEGORY")
    table.add_column("TARGET")
    table.add_column("FINDING")
    table.add_column("EVIDENCE")

    for f in findings:
        # category/target/summary/evidence come from the server under test —
        # never interpret them as rich markup (a tool named "[green]clean[/green]"
        # must not be able to forge its own severity styling).
        evidence = f.evidence[:_MAX_EVIDENCE_CHARS]
        if len(f.evidence) > _MAX_EVIDENCE_CHARS:
            evidence += "…"
        table.add_row(
            Text(f.severity.value.upper(), style=_STYLE[f.severity]),
            Text(f.category),
            Text(_display_safe(f.target)),
            Text(_display_safe(f.summary)),
            Text(_display_safe(evidence)),
        )

    console.print(table)

    counts = {s: sum(1 for f in findings if f.severity == s) for s in Severity}
    summary = " · ".join(f"{counts[s]} {s.value}" for s in Severity if counts[s])
    console.print(f"\n{len(findings)} findings — {summary or 'none'}")
