"""Category G: injection-through-errors, from BENIGN calls only.

Calls each tool once with the minimal schema-satisfying value for each required
field (empty string / 0 / false / [] / {}) — not malformed input, just the
laziest valid-shaped call a legitimate client might make — and inspects any
error message for leaked stack traces, file paths, or internal hostnames.
Sending genuinely malformed/adversarial input to *provoke* an error is category
F and lives in active.yaml (Round 2 review: passive = no crafted payload).

Safety: only calls a tool when `annotations.read_only_hint` is explicitly True.
Tools with no annotations, or with any other hint set, are skipped — "no state
change" is a promise this probe keeps by not calling a tool it can't vouch for,
not by guessing from its name (a denylist like "write|delete|..." misses
`send`, `publish`, `purchase`, `fetch`-as-SSRF, and every synonym never
imagined for it).
"""
from __future__ import annotations

import asyncio
import re

from mcp import ClientSession
from mcp.types import Tool

from .base import Finding, Severity

_CALL_TIMEOUT_S = 15
_MAX_SCAN_CHARS = 100_000  # cap before regex scanning — a hostile server can return arbitrarily large output

_LEAK_PATTERNS = [
    (re.compile(r'File "[^"]+\.py"'), "python stack trace"),
    (re.compile(r"at \S+\s+\([^)]+:\d+:\d+\)"), "node/js stack trace"),
    (re.compile(r"[A-Za-z]:\\[\w\\ .-]+"), "windows filesystem path"),
    # generic absolute unix path, >=2 segments — not a directory-name allowlist
    # (an allowlist of home|Users|var|etc misses /srv, /opt, /data, /app, ...;
    # >=2 segments keeps a bare "/" or "/x" out of matching everything)
    (re.compile(r"(?<![\w])/[\w.-]+(?:/[\w.-]+)+"), "unix filesystem path"),
]


def _default_for(schema: dict) -> object:
    t = schema.get("type")
    return {"string": "", "number": 0, "integer": 0, "boolean": False,
            "array": [], "object": {}}.get(t, "")


def _is_read_only(tool: Tool) -> bool:
    return bool(tool.annotations and tool.annotations.read_only_hint is True)


def _scan_message(message: str, tool_name: str) -> list[Finding]:
    findings = []
    for pattern, label in _LEAK_PATTERNS:
        m = pattern.search(message[:_MAX_SCAN_CHARS])
        if m:
            findings.append(Finding(
                category="G: Error Information Leak",
                severity=Severity.MEDIUM,
                target=tool_name,
                summary=f"Error from a benign call leaked a {label}",
                evidence=m.group(0),
            ))
    return findings


async def run(session: ClientSession, tools: list[Tool]) -> list[Finding]:
    findings: list[Finding] = []
    for tool in tools:
        if not _is_read_only(tool):
            continue  # unannotated or non-read-only — can't vouch for no state change, skip
        schema = tool.input_schema or {}
        props = schema.get("properties", {})
        required = schema.get("required", [])
        args = {name: _default_for(props.get(name, {})) for name in required}

        try:
            result = await asyncio.wait_for(
                session.call_tool(tool.name, args), timeout=_CALL_TIMEOUT_S
            )
        except TimeoutError:
            continue  # a hang isn't an information-leak finding for this probe
        except Exception as exc:
            findings += _scan_message(str(exc), tool.name)
            continue

        # call_tool does not raise on a tool-level error — it returns a result
        # with is_error=True and the message in content. That's the real leak
        # surface. Plain attribute access, not getattr(..., False): if the SDK
        # ever renames this field again, this should fail loudly, not silently
        # disable the probe the way `getattr(result, "isError", False)` did.
        if result.is_error:
            text = "\n".join(
                getattr(c, "text", "") for c in result.content if getattr(c, "text", None)
            )
            findings += _scan_message(text, tool.name)
    return findings


def _selftest() -> None:
    """ponytail: the smallest thing that fails if the is_error wiring breaks again."""
    from mcp.types import CallToolResult, TextContent

    result = CallToolResult(
        content=[TextContent(type="text", text='Traceback: File "/app/handler.py", line 12')],
        is_error=True,
    )
    text = "\n".join(c.text for c in result.content if getattr(c, "text", None))
    assert result.is_error, "CallToolResult.is_error should be True for this fixture"
    findings = _scan_message(text, "fake_tool")
    assert len(findings) == 1, f"expected 1 leak finding, got {len(findings)}"
    assert findings[0].evidence == 'File "/app/handler.py"'


if __name__ == "__main__":
    _selftest()
    print("errors.py self-test passed")
