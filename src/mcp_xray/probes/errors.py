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

from mcp import ClientSession
from mcp.types import Tool

from .base import Finding, Severity
from .patterns import scan_for_leaks
from .tool_args import default_args, is_read_only

_CALL_TIMEOUT_S = 15


def _scan_message(message: str, tool_name: str) -> list[Finding]:
    return [
        Finding(
            category="G: Error Information Leak",
            severity=Severity.MEDIUM,
            target=tool_name,
            summary=f"Error from a benign call leaked a {label}",
            evidence=matched,
        )
        for label, matched in scan_for_leaks(message)
    ]


async def run(session: ClientSession, tools: list[Tool]) -> list[Finding]:
    findings: list[Finding] = []
    for tool in tools:
        if not is_read_only(tool):
            continue  # unannotated or non-read-only — can't vouch for no state change, skip
        args = default_args(tool)

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
    """ponytail: the smallest thing that fails if the is_error wiring, or the
    leak regex, breaks again. Wired into scripts/eval_ground_truth.py so it's
    not a check nobody runs."""
    from mcp.types import CallToolResult, TextContent

    result = CallToolResult(
        content=[TextContent(type="text", text='Traceback: File "/app/handler.py", line 12')],
        is_error=True,
    )
    text = "\n".join(c.text for c in result.content if getattr(c, "text", None))
    assert result.is_error, "CallToolResult.is_error should be True for this fixture"
    findings = _scan_message(text, "fake_tool")
    # This text is legitimately both a python stack trace AND a generic unix
    # path — two distinct patterns, two findings. That's correct, not double
    # counting (see scripts/eval_ground_truth.py, which groups by
    # (category, target) rather than counting raw findings for this reason).
    labels = {f.summary for f in findings}
    assert len(findings) == 2, f"expected 2 leak findings, got {len(findings)}: {labels}"
    assert any("python stack trace" in s for s in labels)
    assert any("unix filesystem path" in s for s in labels)

    # Regression check for the URL false-positive this probe used to have.
    url_findings = _scan_message("fetch failed for https://api.example.com/v1/users", "fake_tool")
    assert url_findings == [], f"URL should not be flagged as a filesystem path: {url_findings}"


if __name__ == "__main__":
    _selftest()
    print("errors.py self-test passed")
