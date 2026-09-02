"""mcp-xray CLI.

    uv run mcp-xray [--json out.json] [--html out.html] [--agentic]
                    [--trials N] [--fail-on-hijack-rate N] <command> [args...]

The mcp-xray flags must come before <command> — everything after it is
passed through verbatim to the target server (argparse.REMAINDER).

--agentic runs category A (probes/driver.py) on top of the always-on passive
catalog (B/C/G). It costs real driver-model API calls (ANTHROPIC_API_KEY),
is never run by default, and never gates the exit code unless you pass
--fail-on-hijack-rate — a hijack rate is a signal to read, not a server-
intrinsic pass/fail (plan §3/Round 1 review).

e.g.  uv run mcp-xray --html report.html npx -y @modelcontextprotocol/server-filesystem sandbox
      uv run mcp-xray --agentic uv run python fixtures/vulnerable/server.py
"""
from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
from pathlib import Path

from .inventory import build_inventory, connect
from .probes import driver, errors, metadata, resources
from .probes.base import Finding
from .probes.patterns import load_instruction_patterns
from .report import html as html_report
from .report import json as json_report
from .report.console import render

_AGENTIC_CATEGORY_PREFIX = "A:"  # keeps agentic findings out of the default exit-1 gate (see main())
_HIJACK_RATE_RE = re.compile(r"hijack_rate=([\d.]+)")


async def _scan(command: str, args: list[str], agentic: bool, trials: int) -> list[Finding]:
    patterns = load_instruction_patterns()
    async with connect(command, args) as session:
        inv = await build_inventory(session)
        findings: list[Finding] = []
        findings += metadata.run(inv.tools, patterns)
        findings += await resources.run(session, inv.resources, inv.prompts, patterns)
        findings += await errors.run(session, inv.tools)
        if agentic:
            client = driver.AnthropicDriverClient()
            findings += await driver.run(session, inv.tools, client, trials=trials)
        return findings


async def _selftest() -> None:
    """ponytail: the coupling check for _HIJACK_RATE_RE — proves it actually
    matches what driver.run() emits, so a format change in one place fails
    loudly here instead of --fail-on-hijack-rate silently matching nothing."""
    from pathlib import Path as _Path

    from .inventory import build_inventory as _build_inventory
    from .inventory import connect as _connect
    from .probes.driver import FakeDriverClient

    fixtures = _Path(__file__).resolve().parents[2] / "fixtures"
    async with _connect("uv", ["run", "python", str(fixtures / "vulnerable" / "server.py")]) as session:
        inv = await _build_inventory(session)
        findings = await driver.run(session, inv.tools, FakeDriverClient(), trials=4)
    agentic = [f for f in findings if f.category.startswith(_AGENTIC_CATEGORY_PREFIX)]
    assert agentic, "expected at least one agentic finding from the vulnerable fixture"
    assert _HIJACK_RATE_RE.search(agentic[0].summary), (
        f"_HIJACK_RATE_RE did not match driver.py's summary format: {agentic[0].summary!r}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(prog="mcp-xray")
    parser.add_argument("--json", metavar="PATH", help="write the JSON report to this path")
    parser.add_argument("--html", metavar="PATH", help="write the standalone HTML report to this path")
    parser.add_argument(
        "--agentic", action="store_true",
        help="also run the category-A driver-model hijack probe (costs API calls; requires ANTHROPIC_API_KEY)",
    )
    parser.add_argument("--trials", type=int, default=10, metavar="N", help="agentic trials per tool (default 10)")
    parser.add_argument(
        "--fail-on-hijack-rate", type=float, default=None, metavar="N",
        help="exit 1 if any --agentic finding's hijack rate is >= N (0.0-1.0); without this flag agentic findings never gate the exit code",
    )
    parser.add_argument("command", help="command that launches the target MCP server, e.g. npx")
    parser.add_argument("args", nargs=argparse.REMAINDER, help="arguments to that command")
    parsed = parser.parse_args()

    # --json/--html/--agentic/... placed after <command> silently vanish into
    # REMAINDER instead of erroring — a security CLI failing quiet is the
    # worst class of bug here, so warn rather than let the user believe a
    # report exists or an agentic scan ran.
    for flag in ("--json", "--html", "--agentic", "--trials", "--fail-on-hijack-rate"):
        if any(a == flag or a.startswith(f"{flag}=") for a in parsed.args):
            print(
                f"mcp-xray: warning: '{flag}' must come before <command>, "
                f"not after — ignoring it",
                file=sys.stderr,
            )

    if parsed.agentic and not os.environ.get("ANTHROPIC_API_KEY"):
        print(
            "mcp-xray: --agentic requires ANTHROPIC_API_KEY to be set "
            "(this is a real, opt-in API-credit cost — see driver.py's docstring)",
            file=sys.stderr,
        )
        sys.exit(2)

    if parsed.fail_on_hijack_rate is not None and not parsed.agentic:
        parser.error("--fail-on-hijack-rate has no effect without --agentic")

    try:
        findings = asyncio.run(_scan(parsed.command, parsed.args, parsed.agentic, parsed.trials))
    except Exception as exc:
        print(f"mcp-xray: scan failed: {exc}", file=sys.stderr)
        sys.exit(2)  # distinct from exit 1 (findings) — a crash isn't a clean scan result

    label = " ".join([parsed.command, *parsed.args])
    render(findings, server_label=label)

    # A write failure (bad path, no permission) must not exit 1 — that's
    # indistinguishable from "High+ findings found" in a CI gate.
    try:
        if parsed.json:
            json_report.write(Path(parsed.json), findings, label)
        if parsed.html:
            html_report.write(Path(parsed.html), findings, label)
    except OSError as exc:
        print(f"mcp-xray: failed to write report: {exc}", file=sys.stderr)
        sys.exit(2)

    static_findings = [f for f in findings if not f.category.startswith(_AGENTIC_CATEGORY_PREFIX)]
    agentic_findings = [f for f in findings if f.category.startswith(_AGENTIC_CATEGORY_PREFIX)]

    if any(f.severity.rank >= 2 for f in static_findings):
        sys.exit(1)  # exit 1 on High+ static (B/C/G) findings — always gates

    if parsed.fail_on_hijack_rate is not None:
        # ponytail: Finding has no structured numeric field, so the rate is
        # parsed back out of driver.py's summary text (which always emits
        # "hijack_rate=<float>") rather than adding a schema field for one
        # consumer. _HIJACK_RATE_RE's self-test below is the coupling check
        # that catches driver.py's format drifting out from under this.
        for f in agentic_findings:
            m = _HIJACK_RATE_RE.search(f.summary)
            if m and float(m.group(1)) >= parsed.fail_on_hijack_rate:
                sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
