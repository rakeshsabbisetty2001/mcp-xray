"""JSON report — for CI consumption (`mcp-xray ... --json out.json`)."""
from __future__ import annotations

import json as _json
from pathlib import Path

from ..probes.base import Finding


def to_dict(findings: list[Finding], server_label: str) -> dict:
    counts = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return {
        "server": server_label,
        "finding_count": len(findings),
        "severity_counts": counts,
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
