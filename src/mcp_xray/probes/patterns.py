"""Load regex-pattern lists shared across probes — both catalog/passive.yaml's
instruction_patterns (B/C) and catalog/active.yaml's secret_patterns (E) use
the same {id, pattern, severity} shape, so one loader serves both."""
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


def _load_patterns(catalog_file: str, key: str) -> list[Pattern]:
    catalog_path = _REPO_ROOT / "catalog" / catalog_file
    data = yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
    return [
        Pattern(id=p["id"], regex=re.compile(p["pattern"]), severity=Severity(p["severity"]))
        for p in data[key]
    ]


def load_instruction_patterns() -> list[Pattern]:
    return _load_patterns("passive.yaml", "instruction_patterns")


def load_secret_patterns() -> list[Pattern]:
    return _load_patterns("active.yaml", "secret_patterns")


def load_active_catalog() -> dict:
    """Raw dict access for active.yaml's non-Pattern-shaped entries
    (ssrf_payloads, path_traversal_payloads, risky_param_names, secret_bait_values)."""
    catalog_path = _REPO_ROOT / "catalog" / "active.yaml"
    return yaml.safe_load(catalog_path.read_text(encoding="utf-8"))


def scan_text(text: str, patterns: list[Pattern]) -> list[tuple[Pattern, str]]:
    """Return (pattern, matched substring) for every pattern that hits `text`."""
    hits = []
    for p in patterns:
        m = p.regex.search(text)
        if m:
            hits.append((p, m.group(0)))
    return hits
