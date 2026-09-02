"""Shared types for probes and findings."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"critical": 3, "high": 2, "medium": 1, "low": 0}[self.value]


@dataclass
class Finding:
    category: str          # e.g. "B: Resource/Prompt Injection"
    severity: Severity
    target: str             # tool/resource/prompt name the finding is about
    summary: str
    evidence: str            # the matched text — shown escaped/truncated in reports (report/console.py)
                              # ponytail: not secret-redacted — B/C/G probes match instruction text, not
                              # credentials. Real secret redaction lands with category E (active, Phase 3/4).
