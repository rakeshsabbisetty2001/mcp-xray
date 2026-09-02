"""Category G: injection-through-errors, from BENIGN calls only.

Calls each tool once with the minimal schema-satisfying value for each required
field (empty string / 0 / false / [] / {}) — not malformed input, just the
laziest valid-shaped call a legitimate client might make — and inspects any
error message for leaked stack traces, file paths, or internal hostnames.
Sending genuinely malformed/adversarial input to *provoke* an error is category
F and lives in active.yaml (Round 2 review: passive = no crafted payload).

Skips any tool whose name hints at a mutation (write/delete/move/exec/...) —
"no state change" is a promise this probe keeps by not calling those tools at
all, not by hoping a benign-looking call happens to be side-effect-free.
"""
from __future__ import annotations

import re

from mcp import ClientSession
from mcp.types import Tool

from .base import Finding, Severity

_MUTATING_NAME_HINTS = re.compile(
    r"(?i)\b(write|delete|remove|move|rename|create|edit|exec|run|update|set|put|post)\w*\b"
)

_LEAK_PATTERNS = [
    (re.compile(r'File "[^"]+\.py"'), "python stack trace"),
    (re.compile(r"at \S+\s+\([^)]+:\d+:\d+\)"), "node/js stack trace"),
    (re.compile(r"[A-Za-z]:\\[\w\\ .-]+"), "windows filesystem path"),
    (re.compile(r"/(?:home|Users|var|etc)/[\w/.-]+"), "unix filesystem path"),
]


def _default_for(schema: dict) -> object:
    t = schema.get("type")
    return {"string": "", "number": 0, "integer": 0, "boolean": False,
            "array": [], "object": {}}.get(t, "")


async def run(session: ClientSession, tools: list[Tool]) -> list[Finding]:
    findings: list[Finding] = []
    for tool in tools:
        if _MUTATING_NAME_HINTS.search(tool.name):
            continue  # can't guarantee no state change — stays passive by skipping, not by risking it
        schema = tool.input_schema or {}
        props = schema.get("properties", {})
        required = schema.get("required", [])
        args = {name: _default_for(props.get(name, {})) for name in required}

        try:
            await session.call_tool(tool.name, args)
        except Exception as exc:
            message = str(exc)
            for pattern, label in _LEAK_PATTERNS:
                m = pattern.search(message)
                if m:
                    findings.append(Finding(
                        category="G: Error Information Leak",
                        severity=Severity.MEDIUM,
                        target=tool.name,
                        summary=f"Error from a benign call leaked a {label}",
                        evidence=m.group(0),
                    ))
    return findings
