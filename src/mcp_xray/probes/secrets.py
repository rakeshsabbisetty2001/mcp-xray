"""Category E: secret/credential exfiltration.

Sends a small set of plausible-looking "bait" argument values (config, debug,
env, .env — nothing exploit-shaped, just what a curious legitimate user might
try) to read-only tools and regex-scans the response for credential material.
Active: it's a crafted call expecting a specific (over-permissive) response,
gated behind --authorized same as the rest of category D's active half.

Redaction happens AT THE CAPTURE BOUNDARY (Round 2 review §6 fix), not in a
report writer downstream: Finding.evidence for a hit is never the raw secret,
only "[REDACTED:<pattern_id>]" — every sink (console/html/json) inherits this
for free because the unsafe text never becomes a Finding field in the first
place. The one place raw text can land is a local, gitignored file, and only
when the caller explicitly passes `unsafe_dir` (wired to CLI
--unsafe-full-transcripts) — never printed, never in any of the three reports.

This is where the pattern originated but not the only place it's needed:
permissions.py's active probes (D) can legitimately capture real credentials
too (an SSRF hit on a cloud metadata endpoint is one hop from AccessKeyId/
SecretAccessKey) — patterns.py's `redact_secrets()` is the shared helper both
files route through, found missing from D in this phase's Round 1 review.
"""
from __future__ import annotations

import time
from pathlib import Path

from mcp import ClientSession
from mcp.types import Tool

from .base import Finding, Severity
from .patterns import load_active_catalog, load_secret_patterns, scan_text
from .tool_args import first_required_string_arg


def _save_unsafe_transcript(unsafe_dir: Path, tool_name: str, pattern_id: str, raw_text: str) -> Path:
    unsafe_dir.mkdir(parents=True, exist_ok=True)
    out_path = unsafe_dir / f"{tool_name}-{pattern_id}-{int(time.time() * 1000)}.txt"
    out_path.write_text(raw_text, encoding="utf-8")
    return out_path


async def run(
    session: ClientSession, tools: list[Tool], unsafe_dir: Path | None = None
) -> list[Finding]:
    """Caller gates this on --authorized — never invoked otherwise."""
    patterns = load_secret_patterns()
    bait_values = load_active_catalog()["secret_bait_values"]

    findings: list[Finding] = []
    for tool in tools:
        if not (tool.annotations and tool.annotations.read_only_hint is True):
            continue  # same fail-closed rule as every other tool-calling probe
        arg = first_required_string_arg(tool)
        if arg is None:
            continue
        arg_name, _ = arg

        seen_pattern_ids: set[str] = set()  # one finding per (tool, pattern), not per bait value
        for bait in bait_values:
            try:
                result = await session.call_tool(tool.name, {arg_name: bait})
            except Exception:
                continue
            text = "\n".join(getattr(c, "text", "") for c in result.content if getattr(c, "text", None))
            if not text:
                continue
            for pattern, matched in scan_text(text, patterns):
                if pattern.id in seen_pattern_ids:
                    continue
                seen_pattern_ids.add(pattern.id)

                evidence = f"[REDACTED:{pattern.id}]"
                if unsafe_dir is not None:
                    saved = _save_unsafe_transcript(unsafe_dir, tool.name, pattern.id, matched)
                    evidence += f" (full match saved locally, gitignored: {saved})"

                findings.append(Finding(
                    category="E: Secret Exfiltration",
                    severity=pattern.severity,
                    target=f"{tool.name} (arg.{arg_name}='{bait}')",
                    summary=f"Response to a bait argument value matched credential pattern '{pattern.id}'",
                    evidence=evidence,
                ))
    return findings


async def _selftest() -> None:
    """ponytail: the check that matters most in this file — proves a real
    secret hit against the real fixture never puts the raw credential into
    ANY Finding field. Redaction is the whole point of this probe; an
    assertion that only exercises the regex would miss a bug in the part
    that actually redacts."""
    from pathlib import Path as _Path

    from ..inventory import build_inventory, connect

    fixtures = _Path(__file__).resolve().parents[3] / "fixtures"
    async with connect("uv", ["run", "python", str(fixtures / "vulnerable" / "server.py")]) as session:
        inv = await build_inventory(session)
        findings = await run(session, inv.tools)

    assert findings, "expected debug_status to score at least one secret finding"
    raw_secrets = ("AKIAIOSFODNN7EXAMPLE", "sk-abcdefghijklmnopqrstuvwx1234567890")
    for f in findings:
        for field in (f.target, f.summary, f.evidence):
            for secret in raw_secrets:
                assert secret not in field, f"raw secret leaked into a Finding field: {field!r}"
        assert f.evidence.startswith("[REDACTED:"), f"evidence should be a redaction marker, got {f.evidence!r}"


if __name__ == "__main__":
    import asyncio

    asyncio.run(_selftest())
    print("secrets.py self-test passed")
