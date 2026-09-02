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


def _resolve_ref(ref: str, defs: dict) -> dict:
    # Only local "#/$defs/Name" refs are relevant here (pydantic-generated
    # schemas, which is how any FastMCP/MCPServer tool with a typed model
    # param — a very common real-world shape — nests its descriptions).
    name = ref.rsplit("/", 1)[-1]
    return defs.get(name, {})


def _describable_fields(schema: dict, prefix: str, defs: dict, _seen: set[str] | None = None) -> dict[str, str]:
    """Pull every 'description' string out of a JSON Schema fragment, recursively
    (properties, array items, $ref/$defs) — a poisoned description can hide
    anywhere in the schema tree, not just top-level params. `_seen` guards
    against a $ref cycle turning this into infinite recursion."""
    texts: dict[str, str] = {}
    if not isinstance(schema, dict):
        return texts
    _seen = _seen or set()

    if ref := schema.get("$ref"):
        if ref in _seen:
            return texts
        return _describable_fields(_resolve_ref(ref, defs), prefix, defs, _seen | {ref})

    if desc := schema.get("description"):
        texts[prefix] = desc
    for name, sub in schema.get("properties", {}).items():
        texts.update(_describable_fields(sub, f"{prefix}.{name}" if prefix else name, defs, _seen))
    if items := schema.get("items"):
        texts.update(_describable_fields(items, f"{prefix}[]", defs, _seen))
    # anyOf/oneOf (e.g. `X | None`) — descend into each branch
    for branch in schema.get("anyOf", []) + schema.get("oneOf", []):
        texts.update(_describable_fields(branch, prefix, defs, _seen))
    return texts


def run(tools: list[Tool], patterns: list[Pattern]) -> list[Finding]:
    findings: list[Finding] = []
    for tool in tools:
        texts = {"description": tool.description or ""}
        if tool.title:
            texts["title"] = tool.title
        schema = tool.input_schema or {}
        defs = schema.get("$defs", {})
        for field, text in _describable_fields(schema, "param", defs).items():
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
