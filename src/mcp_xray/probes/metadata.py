"""Category C: tool-description / schema poisoning ("line jumping").

Scans each tool's description and per-parameter descriptions for instruction-like
text — the model reads this metadata before ever calling the tool, so a poisoned
description is a hijack vector with zero tool invocation required. Fully passive:
no calls made, just string analysis of what tools/list already returned.
"""
from __future__ import annotations

from mcp.types import Tool

from .base import Finding
from .patterns import Pattern, scan_text


def run(tools: list[Tool], patterns: list[Pattern]) -> list[Finding]:
    findings: list[Finding] = []
    for tool in tools:
        texts = {"description": tool.description or ""}
        props = (tool.input_schema or {}).get("properties", {})
        for param_name, param_schema in props.items():
            if isinstance(param_schema, dict) and "description" in param_schema:
                texts[f"param:{param_name}"] = param_schema["description"]

        for field_label, text in texts.items():
            for pattern, matched in scan_text(text, patterns):
                findings.append(Finding(
                    category="C: Tool Metadata Poisoning",
                    severity=pattern.severity,
                    target=f"{tool.name} ({field_label})",
                    summary=f"Instruction-like text in tool {field_label}: pattern '{pattern.id}'",
                    evidence=matched,
                ))
    return findings
