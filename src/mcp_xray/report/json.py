"""JSON report — for CI consumption (`mcp-xray ... --json out.json`)."""
from __future__ import annotations

import json as _json
from pathlib import Path

from ..probes.base import Finding, Severity


def to_dict(findings: list[Finding], server_label: str) -> dict:
    findings = sorted(findings, key=lambda f: -f.severity.rank)  # same order as console/html
    # Seed every severity at 0 — a consumer doing counts["high"] on a clean
    # scan shouldn't KeyError just because nothing was found.
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return {
        "server": server_label,
        "finding_count": len(findings),
        "severity_counts": counts,
        # ponytail: evidence is raw here — not truncated (console.py) or
        # bidi-sanitized (html.py). This is the machine-consumed sink where
        # exact bytes matter for reproducibility. Revisit before category E
        # (secrets) ships, and if this file starts getting pasted into
        # GitHub issues raw.
        "findings": [
            {
                "category": f.category,
                "severity": f.severity.value,
                "target": f.target,
                "summary": f.summary,
                "evidence": f.evidence,
            }
            for f in findings
        ],
    }


def write(path: Path, findings: list[Finding], server_label: str) -> None:
    path.write_text(_json.dumps(to_dict(findings, server_label), indent=2), encoding="utf-8")
