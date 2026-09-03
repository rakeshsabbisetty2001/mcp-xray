"""Load regex-pattern lists shared across probes — both catalog/passive.yaml's
instruction_patterns (B/C) and catalog/active.yaml's secret_patterns (E) use
the same {id, pattern, severity} shape, so one loader serves both."""
from __future__ import annotations

import re
from dataclasses import dataclass
from importlib import resources

import yaml

from .base import Severity


@dataclass
class Pattern:
    id: str
    regex: re.Pattern
    severity: Severity


def _load_yaml(catalog_file: str) -> dict:
    # catalog/ ships INSIDE the package (mcp_xray/catalog/) specifically so
    # this resolves correctly whether running from a checkout via `uv run`
    # or from a real uvx/pipx install with no repo on disk at all — verified
    # by installing the built wheel into an isolated venv and running from
    # outside this directory (Phase 5, packaging).
    text = resources.files("mcp_xray.catalog").joinpath(catalog_file).read_text(encoding="utf-8")
    return yaml.safe_load(text)


def _load_patterns(catalog_file: str, key: str) -> list[Pattern]:
    data = _load_yaml(catalog_file)
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
    return _load_yaml("active.yaml")


def scan_text(text: str, patterns: list[Pattern]) -> list[tuple[Pattern, str]]:
    """Return (pattern, matched substring) for every pattern that hits `text`."""
    hits = []
    for p in patterns:
        m = p.regex.search(text)
        if m:
            hits.append((p, m.group(0)))
    return hits


LEAK_PATTERNS = [
    (re.compile(r'File "[^"]+\.py"'), "python stack trace"),
    (re.compile(r"at \S+\s+\([^)]+:\d+:\d+\)"), "node/js stack trace"),
    (re.compile(r"[A-Za-z]:\\[\w\\ .-]+"), "windows filesystem path"),
    # generic absolute unix path, >=2 segments — not a directory-name allowlist
    # (an allowlist of home|Users|var|etc misses /srv, /opt, /data, /app, ...;
    # >=2 segments keeps a bare "/" or "/x" out of matching everything). The
    # negative lookbehind also excludes ':' and a preceding '/' so it doesn't
    # match the path component of a URL (https://api.example.com/v1/users is
    # an upstream-service reference, not a filesystem leak).
    (re.compile(r"(?<![\w:/])/[\w.-]+(?:/[\w.-]+)+"), "unix filesystem path"),
]
_MAX_LEAK_SCAN_CHARS = 100_000  # cap before regex scanning — a hostile server can return arbitrarily large output


def scan_for_leaks(text: str) -> list[tuple[str, str]]:
    """Return (label, matched substring) for every LEAK_PATTERNS hit.
    Shared between G (leaks from benign calls) and F (leaks provoked by
    malformed input) — same detection logic, different trigger."""
    hits = []
    for pattern, label in LEAK_PATTERNS:
        m = pattern.search(text[:_MAX_LEAK_SCAN_CHARS])
        if m:
            hits.append((label, m.group(0)))
    return hits


def redact_secrets(text: str) -> str:
    """Replace every secret-pattern match in `text` with "[REDACTED:<id>]".
    The shared redact-at-capture-boundary helper (Round 2 review §6) — any
    probe that might echo a real target's response back as evidence must
    route it through this before it becomes a Finding field, not just E's
    own probe (a lesson from category D's own SSRF/traversal responses,
    which can legitimately contain real credentials against a real target)."""
    patterns = load_secret_patterns()
    for p in patterns:
        text = p.regex.sub(f"[REDACTED:{p.id}]", text)
    return text
