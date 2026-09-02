"""Precision/recall calibration against the two fixtures.

    uv run python scripts/eval_ground_truth.py

Runs mcp-xray's passive probes against fixtures/vulnerable (compared to
ground_truth.yaml) and fixtures/hardened (the false-positive baseline, where
every finding is a false positive by definition). Per Round 2 plan review:
this is IN-DISTRIBUTION calibration on the fixture pair the probes were
authored against — a real signal that the wiring works end to end, not a
generalization estimate of real-world precision/recall.
"""
from __future__ import annotations

import asyncio
import sys
from collections import defaultdict
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from mcp_xray.cli import _selftest as cli_selftest  # noqa: E402
from mcp_xray.inventory import build_inventory, connect  # noqa: E402
from mcp_xray.probes import errors, metadata, resources  # noqa: E402
from mcp_xray.probes.base import Finding  # noqa: E402
from mcp_xray.probes.driver import _selftest as driver_selftest  # noqa: E402
from mcp_xray.probes.errors import _selftest as errors_selftest  # noqa: E402
from mcp_xray.probes.patterns import load_instruction_patterns  # noqa: E402
from mcp_xray.report.html import _selftest as html_selftest  # noqa: E402

_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"


async def _scan_fixture(server_dir: Path) -> list[Finding]:
    patterns = load_instruction_patterns()
    async with connect("uv", ["run", "python", str(server_dir / "server.py")]) as session:
        inv = await build_inventory(session)
        findings: list[Finding] = []
        findings += metadata.run(inv.tools, patterns)
        findings += await resources.run(session, inv.resources, inv.prompts, patterns)
        findings += await errors.run(session, inv.tools)
        return findings


def _category_letter(finding: Finding) -> str:
    return finding.category.split(":", 1)[0].strip()


async def main() -> None:
    errors_selftest()  # the one runnable unit check per module — wired in so they're actually part of CI, not dead code
    html_selftest()
    await driver_selftest()  # zero-API-cost: uses FakeDriverClient, proves the agentic pipeline wiring, not a real hijack rate
    await cli_selftest()  # coupling check: --fail-on-hijack-rate's regex actually matches driver.py's summary format

    ground_truth = yaml.safe_load(
        (_FIXTURES_DIR / "vulnerable" / "ground_truth.yaml").read_text(encoding="utf-8")
    )["expected"]

    vuln_findings = await _scan_fixture(_FIXTURES_DIR / "vulnerable")
    hardened_findings = await _scan_fixture(_FIXTURES_DIR / "hardened")

    counts: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})

    # Match at (category, target) granularity, not per-finding: one poisoned
    # target legitimately trips multiple pattern hits (e.g. both
    # "override_directive" and "imperative_tool_call" matching the same
    # description) — that's correct detection, not N false positives.
    vuln_groups: set[tuple[str, str]] = {(_category_letter(f), f.target) for f in vuln_findings}
    matched_groups: set[tuple[str, str]] = set()

    for entry in ground_truth:
        cat, target, field = entry["category"], entry["target"], entry.get("field")
        # `field` pins the specific schema/description location when given —
        # without it, a regression fixture like the $ref one could score a
        # false TP off an unrelated finding on the same tool.
        hit = next(
            (
                g for g in vuln_groups
                if g[0] == cat and g[1].startswith(target) and (field is None or field in g[1])
            ),
            None,
        )
        if hit is not None:
            counts[cat]["tp"] += 1
            matched_groups.add(hit)
        else:
            counts[cat]["fn"] += 1

    # Any finding group not consumed as a TP is an unexpected extra.
    for cat, target in vuln_groups - matched_groups:
        counts[cat]["fp"] += 1

    # Every finding on the hardened baseline is a false positive by definition.
    for cat, target in {(_category_letter(f), f.target) for f in hardened_findings}:
        counts[cat]["fp"] += 1

    print("mcp-xray ground-truth calibration — IN-DISTRIBUTION, fixture-only,")
    print("NOT a generalization estimate (Round 2 plan review caveat).\n")
    print(f"{'CAT':<4} {'TP':>3} {'FP':>3} {'FN':>3} {'PRECISION':>10} {'RECALL':>8}")
    total_tp = total_fp = total_fn = 0
    for cat in sorted(counts):
        tp, fp, fn = counts[cat]["tp"], counts[cat]["fp"], counts[cat]["fn"]
        total_tp, total_fp, total_fn = total_tp + tp, total_fp + fp, total_fn + fn
        precision = tp / (tp + fp) if (tp + fp) else float("nan")
        recall = tp / (tp + fn) if (tp + fn) else float("nan")
        print(f"{cat:<4} {tp:>3} {fp:>3} {fn:>3} {precision:>10.2f} {recall:>8.2f}")

    overall_p = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else float("nan")
    overall_r = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else float("nan")
    print(f"{'ALL':<4} {total_tp:>3} {total_fp:>3} {total_fn:>3} {overall_p:>10.2f} {overall_r:>8.2f}")

    if total_fp or total_fn:
        sys.exit(1)  # CI signal: calibration regressed


if __name__ == "__main__":
    asyncio.run(main())
