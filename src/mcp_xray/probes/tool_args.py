"""Shared helpers for driving a tool call — used by every probe that
actually calls a tool (driver.py, errors.py, permissions.py, secrets.py,
schema_confusion.py) so "which tools are safe to call" and "what's a
schema-satisfying default value" aren't each reimplemented per file.
"""
from __future__ import annotations

from mcp.types import Tool

_DEFAULT_BY_TYPE = {
    "string": "", "number": 0, "integer": 0, "boolean": False,
    "array": [], "object": {},
}


def is_read_only(tool: Tool) -> bool:
    """The fail-closed rule every tool-calling probe uses: only call a tool
    whose annotations explicitly declare readOnlyHint=True. Unannotated or
    non-read-only tools are skipped — this is a promise kept by not calling
    a tool the probe can't vouch for, not by guessing from its name."""
    return bool(tool.annotations and tool.annotations.read_only_hint is True)


def first_required_string_arg(tool: Tool) -> tuple[str, str] | None:
    schema = tool.input_schema or {}
    for name in schema.get("required", []):
        prop = schema.get("properties", {}).get(name, {})
        if prop.get("type") == "string":
            return name, "test"
    return None


def default_for(schema: dict) -> object:
    """The minimal schema-satisfying value for a JSON-Schema fragment's
    declared type — "" for string, 0 for number, etc."""
    return _DEFAULT_BY_TYPE.get(schema.get("type"), "")


def default_args(tool: Tool, skip: str | None = None) -> dict:
    """Default value for every required param except `skip` (the one a
    caller is about to override with something else — a probe payload)."""
    schema = tool.input_schema or {}
    props = schema.get("properties", {})
    return {
        name: default_for(props.get(name, {}))
        for name in schema.get("required", [])
        if name != skip
    }
