"""Category B: indirect injection via resources & prompts.

Reads every resources/list entry and prompts/list template (read-only —
resources/read is a normal, non-state-changing call) and scans the content for
instruction-like text. A poisoned README-as-resource is a real vector: the
model may ingest it as context without ever calling a "risky" tool.
"""
from __future__ import annotations

import asyncio

from mcp import ClientSession
from mcp.types import Prompt, Resource

from .base import Finding
from .patterns import Pattern, scan_text

_READ_TIMEOUT_S = 15
_MAX_SCAN_CHARS = 100_000  # cap before regex scanning — a hostile server can return arbitrarily large content


async def run(
    session: ClientSession,
    resources: list[Resource],
    prompts: list[Prompt],
    patterns: list[Pattern],
) -> list[Finding]:
    findings: list[Finding] = []

    for res in resources:
        try:
            result = await asyncio.wait_for(
                session.read_resource(res.uri), timeout=_READ_TIMEOUT_S
            )
        except Exception:
            continue  # unreadable/slow resource isn't a finding, just skip
        for content in result.contents:
            text = getattr(content, "text", None)
            if not text:
                continue
            for pattern, matched in scan_text(text[:_MAX_SCAN_CHARS], patterns):
                findings.append(Finding(
                    category="B: Resource Injection",
                    severity=pattern.severity,
                    target=res.name or str(res.uri),
                    summary=f"Instruction-like text in resource content: pattern '{pattern.id}'",
                    evidence=matched,
                ))

    for prompt in prompts:
        texts = {"description": prompt.description or ""}
        for arg in prompt.arguments or []:
            if arg.description:
                texts[f"arg:{arg.name}"] = arg.description
        for field_label, text in texts.items():
            for pattern, matched in scan_text(text, patterns):
                findings.append(Finding(
                    category="B: Prompt Template Injection",
                    severity=pattern.severity,
                    target=f"{prompt.name} ({field_label})",
                    summary=f"Instruction-like text in prompt {field_label}: pattern '{pattern.id}'",
                    evidence=matched,
                ))

    return findings
