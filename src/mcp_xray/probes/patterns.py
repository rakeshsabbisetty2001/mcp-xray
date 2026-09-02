"""Load the shared instruction-pattern catalog used by probes B and C."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from .base import Severity

# ponytail: catalog/ ships alongside the repo (not as packaged data) — v1 is
# run from a checkout via `uv run`, not installed standalone. Revisit with
# importlib.resources if/when this ships as a packaged wheel.
_REPO_ROOT = Path(__file__).resolve().parents[3]


@dataclass
class Pattern:
    id: str
    regex: re.Pattern
    severity: Severity


def load_instruction_patterns() -> list[Pattern]:
    catalog_path = _REPO_ROOT / "catalog" / "passive.yaml"
    data = yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
    return [
        Pattern(id=p["id"], regex=re.compile(p["pattern"]), severity=Severity(p["severity"]))
        for p in data["instruction_patterns"]
    ]


def scan_text(text: str, patterns: list[Pattern]) -> list[tuple[Pattern, str]]:
    """Return (pattern, matched substring) for every pattern that hits `text`."""
    hits = []
    for p in patterns:
        m = p.regex.search(text)
        if m:
            hits.append((p, m.group(0)))
    return hits
