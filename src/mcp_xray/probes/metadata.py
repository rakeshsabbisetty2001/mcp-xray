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


def _describable_fields(schema: dict, prefix: str) -> dict[str, str]:
    """Pull every 'description' string out of a JSON Schema fragment, recursively
    (properties, array items, enum-adjacent siblings) — a poisoned description
    can hide anywhere in the schema tree, not just top-level params."""
    texts: dict[str, str] = {}
    if not isinstance(schema, dict):
        return texts
    if desc := schema.get("description"):
        texts[prefix] = desc
    for name, sub in schema.get("properties", {}).items():
        texts.update(_describable_fields(sub, f"{prefix}.{name}" if prefix else name))
    if items := schema.get("items"):
        texts.update(_describable_fields(items, f"{prefix}[]"))
    return texts


def run(tools: list[Tool], patterns: list[Pattern]) -> list[Finding]:
    findings: list[Finding] = []
    for tool in tools:
        texts = {"description": tool.description or ""}
        if tool.title:
            texts["title"] = tool.title
        for field, text in _describable_fields(tool.input_schema or {}, "param").items():
            texts[field] = text

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
