"""mcp-xray CLI — v1 supports the passive probe catalog only (Phase 1).

    uv run mcp-xray [--json out.json] [--html out.html] <command> [args...]

The --json/--html flags must come before <command> — everything after it is
passed through verbatim to the target server (argparse.REMAINDER).

e.g.  uv run mcp-xray --html report.html npx -y @modelcontextprotocol/server-filesystem sandbox
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from .inventory import build_inventory, connect
from .probes import errors, metadata, resources
from .probes.base import Finding
from .probes.patterns import load_instruction_patterns
from .report import html as html_report
from .report import json as json_report
from .report.console import render


async def _scan(command: str, args: list[str]) -> list[Finding]:
    patterns = load_instruction_patterns()
    async with connect(command, args) as session:
        inv = await build_inventory(session)
        findings: list[Finding] = []
        findings += metadata.run(inv.tools, patterns)
        findings += await resources.run(session, inv.resources, inv.prompts, patterns)
        findings += await errors.run(session, inv.tools)
        return findings


def main() -> None:
    parser = argparse.ArgumentParser(prog="mcp-xray")
    parser.add_argument("--json", metavar="PATH", help="write the JSON report to this path")
    parser.add_argument("--html", metavar="PATH", help="write the standalone HTML report to this path")
    parser.add_argument("command", help="command that launches the target MCP server, e.g. npx")
    parser.add_argument("args", nargs=argparse.REMAINDER, help="arguments to that command")
    parsed = parser.parse_args()

    # --json/--html placed after <command> silently vanish into REMAINDER
    # instead of erroring — a security CLI failing quiet is the worst class
    # of bug here, so warn rather than let the user believe a report exists.
    for flag in ("--json", "--html"):
        if any(a == flag or a.startswith(f"{flag}=") for a in parsed.args):
            print(
                f"mcp-xray: warning: '{flag}' must come before <command>, "
                f"not after — ignoring it, no report will be written for it",
                file=sys.stderr,
            )

    try:
        findings = asyncio.run(_scan(parsed.command, parsed.args))
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

    sys.exit(1 if any(f.severity.rank >= 2 for f in findings) else 0)  # exit 1 on High+ findings


if __name__ == "__main__":
    main()
