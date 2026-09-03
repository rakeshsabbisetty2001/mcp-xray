"""Shared helper for driving a tool call with a minimal synthesized argument.
Used by driver.py (category A) and secrets.py (category E) — both need "the
one required string arg on this tool" and shouldn't duplicate the logic.
"""
from __future__ import annotations

from mcp.types import Tool


def first_required_string_arg(tool: Tool) -> tuple[str, str] | None:
    schema = tool.input_schema or {}
    for name in schema.get("required", []):
        prop = schema.get("properties", {}).get(name, {})
        if prop.get("type") == "string":
            return name, "test"
    return None
