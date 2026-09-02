"""Standalone HTML report — full, unredacted-within-B/C/G evidence per finding
for reproducibility (plan §5: "anyone can verify"). Self-contained (inline
CSS, no external assets) so it's a single file that opens anywhere.

Every server-controlled string (tool/resource/prompt names, evidence, the
server label itself) goes through `html.escape()` — this is the HTML
equivalent of the rich-markup-injection fix in report/console.py: a tool
named `<script>alert(1)</script>` must not be able to run script in a
security report opened in a browser.
"""
from __future__ import annotations

from html import escape
from pathlib import Path

from ..probes.base import Finding, Severity

_SEVERITY_COLOR = {
    Severity.CRITICAL: "#b91c1c",
    Severity.HIGH: "#dc2626",
    Severity.MEDIUM: "#d97706",
    Severity.LOW: "#6b7280",
}

_STYLE = """
  body { font-family: -apple-system, Segoe UI, sans-serif; background: #0b0b0c; color: #e5e5e5; margin: 2rem; }
  h1 { font-size: 1.1rem; font-weight: 600; }
  table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
  th, td { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid #27272a; vertical-align: top; }
  th { color: #a1a1aa; font-weight: 500; font-size: 0.85rem; text-transform: uppercase; }
  code { background: #18181b; padding: 0.1rem 0.35rem; border-radius: 3px; word-break: break-all; }
  .sev { font-weight: 700; padding: 0.15rem 0.5rem; border-radius: 3px; color: #fff; display: inline-block; }
  .summary-line { color: #a1a1aa; margin: 0.25rem 0 1rem; }
"""


def _severity_badge(sev: Severity) -> str:
    return f'<span class="sev" style="background:{_SEVERITY_COLOR[sev]}">{escape(sev.value.upper())}</span>'


def render(findings: list[Finding], server_label: str) -> str:
    findings = sorted(findings, key=lambda f: -f.severity.rank)
    counts = {s: sum(1 for f in findings if f.severity == s) for s in Severity}
    summary = " · ".join(f"{counts[s]} {s.value}" for s in Severity if counts[s]) or "none"

    rows = "\n".join(
        f"""<tr>
          <td>{_severity_badge(f.severity)}</td>
          <td>{escape(f.category)}</td>
          <td><code>{escape(f.target)}</code></td>
          <td>{escape(f.summary)}</td>
          <td><code>{escape(f.evidence)}</code></td>
        </tr>"""
        for f in findings
    )

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>mcp-xray report</title><style>{_STYLE}</style></head>
<body>
  <h1>mcp-xray &gt; {escape(server_label)}</h1>
  <p class="summary-line">{len(findings)} findings — {escape(summary)}</p>
  <table>
    <thead><tr><th>Sev</th><th>Category</th><th>Target</th><th>Finding</th><th>Evidence</th></tr></thead>
    <tbody>{rows or '<tr><td colspan="5">No findings.</td></tr>'}</tbody>
  </table>
</body></html>
"""


def write(path: Path, findings: list[Finding], server_label: str) -> None:
    path.write_text(render(findings, server_label), encoding="utf-8")


def _selftest() -> None:
    """ponytail: the smallest thing that fails if escaping regresses — this
    is a security tool rendering untrusted (server-controlled) strings into
    HTML, so an unescaped '<' here is a real XSS hole in the report itself."""
    hostile = Finding(
        category="C",
        severity=Severity.HIGH,
        target="<script>alert(1)</script>",
        summary="x",
        evidence="<img src=x onerror=alert(1)>",
    )
    out = render([hostile], "<script>alert(2)</script>")
    assert "<script>" not in out, "unescaped '<script>' made it into the report"
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in out
    assert "&lt;img src=x onerror=alert(1)&gt;" in out


if __name__ == "__main__":
    _selftest()
    print("html.py self-test passed")
