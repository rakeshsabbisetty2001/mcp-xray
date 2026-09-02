"""mcp-xray CLI — v1 supports the passive probe catalog only (Phase 1).

    uv run mcp-xray <command> [args...]

e.g.  uv run mcp-xray npx -y @modelcontextprotocol/server-filesystem sandbox
"""
from __future__ import annotations

import argparse
import asyncio
import sys

from .inventory import build_inventory, connect
from .probes import errors, metadata, resources
from .probes.base import Finding
from .probes.patterns import load_instruction_patterns
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
    parser.add_argument("command", help="command that launches the target MCP server, e.g. npx")
    parser.add_argument("args", nargs=argparse.REMAINDER, help="arguments to that command")
    parsed = parser.parse_args()

    try:
        findings = asyncio.run(_scan(parsed.command, parsed.args))
    except Exception as exc:
        print(f"mcp-xray: scan failed: {exc}", file=sys.stderr)
        sys.exit(2)  # distinct from exit 1 (findings) — a crash isn't a clean scan result

    label = " ".join([parsed.command, *parsed.args])
    render(findings, server_label=label)
    sys.exit(1 if any(f.severity.rank >= 2 for f in findings) else 0)  # exit 1 on High+ findings


if __name__ == "__main__":
    main()
