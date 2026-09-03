"""Category D: over-broad permissions / capability audit.

Two halves under one category letter, per the plan's finalized catalog split:

- structural (`scan_schema`): flags a tool as arbitrary-execution-risk-shaped
  by param name/type alone. No call made — genuinely passive (no crafted
  payload, no state change) even though it lives alongside D's active half
  for organizational simplicity. Runs unconditionally, same as B/C/G.
- active (`run`): actually sends path-traversal and SSRF payloads and looks
  for escape/fetch signatures in the response. Gated behind --authorized —
  this is an attack, not a scan (Round 1 review §2).
"""
from __future__ import annotations

from mcp import ClientSession
from mcp.types import Tool

from .base import Finding, Severity
from .patterns import load_active_catalog

# Response signatures that indicate a payload actually escaped/reached
# something — heuristic against an unknown real target's real content, exact
# against this project's own fixtures. All matching is case-insensitive
# (a real target's casing is not something to bet detection on).
_UNIX_ESCAPE_SIGNATURES = ("root:x:0:0", "root:*:0:0")
_WINDOWS_ESCAPE_SIGNATURES = ("[fonts]", "[extensions]")
_AWS_METADATA_SIGNATURES = ("iam/security-credentials", "ami-id", "instance-id")
_SSH_BANNER_SIGNATURES = ("ssh-2.0",)

# Each SSRF payload's *successful* response looks different by construction —
# a metadata endpoint returns AWS-shaped text, a port scan returns a banner,
# a file:// fetch returns file content (same shape as a traversal escape).
# One shared signature set for all three (an earlier version of this file)
# meant only the payload matching that one set could ever fire.
_SSRF_SIGNATURE_SETS = {
    "aws_metadata_endpoint": _AWS_METADATA_SIGNATURES,
    "localhost_port_scan": _SSH_BANNER_SIGNATURES,
    "file_scheme": _UNIX_ESCAPE_SIGNATURES,
}


def scan_schema(tools: list[Tool]) -> list[Finding]:
    """Structural half — no calls, param name/type inspection only."""
    risky_names = set(load_active_catalog()["risky_param_names"])
    findings = []
    for tool in tools:
        props = (tool.input_schema or {}).get("properties", {})
        for name, schema in props.items():
            if not isinstance(schema, dict) or schema.get("type") != "string":
                continue
            if name.lower() in risky_names:
                findings.append(Finding(
                    category="D: Over-Broad Permission (Structural)",
                    severity=Severity.MEDIUM,
                    target=f"{tool.name} (param.{name})",
                    summary=(
                        f"Parameter '{name}' accepts a free-form string and its name suggests "
                        f"filesystem/network/command scope — flagged as arbitrary-execution-risk-"
                        f"shaped. This is a schema-shape signal, not proof; confirmed or refuted "
                        f"by --authorized's active path-traversal/SSRF probes."
                    ),
                    evidence=f"param.{name}: string, no visible allowlist/pattern constraint",
                ))
    return findings


async def _probe_param(
    session: ClientSession, tool: Tool, param_name: str, param_kind: str
) -> list[Finding]:
    catalog = load_active_catalog()
    findings = []

    if param_kind == "path":
        payloads = catalog["path_traversal_payloads"]
        signature_sets = {"unix_traversal": _UNIX_ESCAPE_SIGNATURES, "windows_traversal": _WINDOWS_ESCAPE_SIGNATURES}
        category = "D: Path Traversal"
    else:
        payloads = catalog["ssrf_payloads"]
        signature_sets = _SSRF_SIGNATURE_SETS
        category = "D: SSRF"

    for payload in payloads:
        try:
            result = await session.call_tool(tool.name, {param_name: payload["value"]})
        except Exception:
            continue
        if getattr(result, "is_error", False):
            continue  # rejected the payload — not a finding
        text = "\n".join(getattr(c, "text", "") for c in result.content if getattr(c, "text", None))
        signatures = signature_sets.get(payload["id"], ())
        if any(sig in text.lower() for sig in signatures):
            findings.append(Finding(
                category=category,
                severity=Severity(payload["severity"]),
                target=f"{tool.name} (param.{param_name})",
                summary=f"Payload '{payload['id']}' ({payload['value']!r}) produced a response matching a known escape/fetch signature",
                evidence=text[:500],
            ))
    return findings


async def run(session: ClientSession, tools: list[Tool]) -> list[Finding]:
    """Active half — real payloads, real calls. Caller gates this on --authorized."""
    risky_names = load_active_catalog()["risky_param_names"]
    path_names = {n for n in risky_names if n in ("path", "file", "filepath")}
    url_names = {n for n in risky_names if n == "url"}

    findings: list[Finding] = []
    for tool in tools:
        if not (tool.annotations and tool.annotations.read_only_hint is True):
            continue  # same fail-closed rule as every other tool-calling probe
        props = (tool.input_schema or {}).get("properties", {})
        required = set((tool.input_schema or {}).get("required", []))
        for name, schema in props.items():
            if name not in required or not isinstance(schema, dict) or schema.get("type") != "string":
                continue
            lname = name.lower()
            if lname in path_names:
                findings += await _probe_param(session, tool, name, "path")
            elif lname in url_names:
                findings += await _probe_param(session, tool, name, "url")
    return findings


def _selftest() -> None:
    """ponytail: unit-level check on the signature matching itself — the part
    that silently broke once already (one shared signature set for all 3 SSRF
    payloads, case-sensitive) before any fixture caught it. Pure logic, no
    MCP session needed; scripts/eval_active.py covers the live end-to-end path."""
    for payload_id, text, should_match in [
        ("aws_metadata_endpoint", "IAM/Security-Credentials/\nami-id", True),
        ("aws_metadata_endpoint", "just a normal response", False),
        ("localhost_port_scan", "SSH-2.0-OpenSSH_9.6", True),  # case-insensitive: real bug this used to have
        ("file_scheme", "root:x:0:0:root:/root:/bin/bash", True),
        ("file_scheme", "[fetched file:///etc/passwd]", False),  # echoing the URL back isn't a leak
    ]:
        signatures = _SSRF_SIGNATURE_SETS[payload_id]
        matched = any(sig in text.lower() for sig in signatures)
        assert matched == should_match, f"{payload_id} on {text!r}: expected match={should_match}, got {matched}"


if __name__ == "__main__":
    _selftest()
    print("permissions.py self-test passed")
