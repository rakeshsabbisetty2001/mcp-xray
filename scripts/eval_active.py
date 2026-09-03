"""Ground-truth calibration for category D (active half) and category E.

    uv run python scripts/eval_active.py

Separate from eval_ground_truth.py (passive B/C/G) because D's structural
half legitimately fires on BOTH fixtures (schema-shape signal, not proof —
see probes/permissions.py) and can't share the "hardened = 0 findings"
precision baseline the passive categories use. This script:
  1. Sanity-checks the structural half fires on both fixtures (expected,
     not scored for precision).
  2. Scores the active half (real payloads: path traversal, SSRF, secret
     bait) against fixtures/vulnerable/ground_truth_active.yaml.
  3. Confirms zero active-D/E findings on fixtures/hardened (the real
     false-positive baseline for the active half).

Runs entirely against locally stdio-spawned fixtures — no --authorized
flag needed here (that gate is CLI-level, for scanning targets other than
this project's own fixtures); this script calls the probe functions
directly. Same in-distribution/fixture-only caveat as eval_ground_truth.py.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from mcp_xray.inventory import build_inventory, connect  # noqa: E402
from mcp_xray.probes import permissions, secrets  # noqa: E402
from mcp_xray.probes.base import Finding  # noqa: E402
from mcp_xray.probes.permissions import _selftest as permissions_selftest  # noqa: E402
from mcp_xray.probes.secrets import _selftest as secrets_selftest  # noqa: E402

_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"


async def _scan_active(server_dir: Path) -> tuple[list[Finding], list[Finding]]:
    async with connect("uv", ["run", "python", str(server_dir / "server.py")]) as session:
        inv = await build_inventory(session)
        structural = permissions.scan_schema(inv.tools)
        active = await permissions.run(session, inv.tools)
        active += await secrets.run(session, inv.tools)
        return structural, active


def _category_letter(finding: Finding) -> str:
    return finding.category.split(":", 1)[0].strip()


async def main() -> None:
    permissions_selftest()  # pure signature-matching logic, no session needed
    await secrets_selftest()  # the redaction-never-leaks check, against the real fixture

    ground_truth = yaml.safe_load(
        (_FIXTURES_DIR / "vulnerable" / "ground_truth_active.yaml").read_text(encoding="utf-8")
    )["expected"]

    vuln_structural, vuln_active = await _scan_active(_FIXTURES_DIR / "vulnerable")
    hard_structural, hard_active = await _scan_active(_FIXTURES_DIR / "hardened")

    print("--- structural D sanity check (expected on both, not scored) ---")
    print(f"vulnerable: {len(vuln_structural)} findings, hardened: {len(hard_structural)} findings")
    if not vuln_structural or not hard_structural:
        print("mcp-xray: structural D found nothing on one of the fixtures — that's a regression", file=sys.stderr)
        sys.exit(1)

    print("\n--- active D + E calibration (vulnerable vs ground_truth_active.yaml) ---")
    matched_ids: set[int] = set()
    tp = fn = 0
    for entry in ground_truth:
        cat, target, field = entry["category"], entry["target"], entry.get("field")
        hit = next(
            (
                i for i, f in enumerate(vuln_active)
                if i not in matched_ids and _category_letter(f) == cat
                # exact tool-name compare (not startswith) so "read_file" can't
                # prefix-match a hypothetical "read_file_v2"; both D and E
                # target strings are "<tool> (...)", so split off the parens
                and f.target.split(" (", 1)[0] == target
                # field is quoted in both D's and E's summary format
                # ("Payload 'x'" / "pattern 'x'") — match the quoted form,
                # not a bare substring, so it can't match inside unrelated text
                and (field is None or f"'{field}'" in f.summary)
            ),
            None,
        )
        if hit is not None:
            tp += 1
            matched_ids.add(hit)
        else:
            fn += 1
            print(f"  MISS: {cat} / {target} / {field}")

    fp = len(vuln_active) - len(matched_ids)
    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    print(f"TP={tp} FP={fp} FN={fn}  precision={precision:.2f} recall={recall:.2f}")

    print(f"\n--- false-positive baseline (hardened, active D+E only) ---")
    print(f"hardened active D+E findings: {len(hard_active)} (expect 0)")
    for f in hard_active:
        print(f"  UNEXPECTED: {f.category} / {f.target} / {f.summary}")

    if fp or fn or hard_active:
        sys.exit(1)  # CI signal: calibration regressed


if __name__ == "__main__":
    asyncio.run(main())
