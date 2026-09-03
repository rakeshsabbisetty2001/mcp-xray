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
from .patterns import load_active_catalog, redact_secrets
from .tool_args import is_read_only

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

# Of risky_param_names (path/file/filepath/cmd/command/query/sql/exec/url),
# only these actually get an active probe today — cmd/command/query/sql/exec
# are flagged structurally but nothing in `run()` sends them a payload
# (whole-repo review: the structural finding's summary used to claim every
# flagged name gets "confirmed or refuted" by --authorized, which was false
# for 5 of 9 catalog entries).
_ACTIVELY_PROBED_NAMES = {"path", "file", "filepath", "url"}


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
                if name.lower() in _ACTIVELY_PROBED_NAMES:
                    followup = "confirmed or refuted by --authorized's active path-traversal/SSRF probes."
                else:
                    followup = (
                        "not yet backed by an active probe (only path/file/filepath/url are "
                        "currently sent payloads) — treat as inventory context, not a confirmed check."
                    )
                findings.append(Finding(
                    category="D: Over-Broad Permission (Structural)",
                    # LOW, not MEDIUM (Round 1 review this phase): this check
                    # fires identically on both fixtures by construction — a
                    # risky-shaped param name is inventory context for a
                    # human or for --authorized's active probes, not a
                    # discriminating finding on its own. eval_active.py
                    # correctly refuses to score it for precision/recall.
                    severity=Severity.LOW,
                    target=f"{tool.name} (param.{name})",
                    summary=(
                        f"Parameter '{name}' accepts a free-form string and its name suggests "
                        f"filesystem/network/command scope — flagged as arbitrary-execution-risk-"
                        f"shaped. This is a schema-shape signal, not proof; {followup}"
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
            # This response can legitimately contain real credentials against
            # a real target — an SSRF hit on the AWS metadata endpoint is one
            # hop from AccessKeyId/SecretAccessKey, and a traversal/file://
            # hit is arbitrary file content. Same capture-boundary redaction
            # E uses, not just a truncation (Round 2 review, this phase).
            findings.append(Finding(
                category=category,
                severity=Severity(payload["severity"]),
                target=f"{tool.name} (param.{param_name})",
                summary=f"Payload '{payload['id']}' ({payload['value']!r}) produced a response matching a known escape/fetch signature",
                # redact first, THEN truncate — a 500-char cut landing mid-key
                # would leave an unmatchable partial "AKIA..." fragment
                evidence=redact_secrets(text)[:500],
            ))
    return findings


async def run(session: ClientSession, tools: list[Tool]) -> list[Finding]:
    """Active half — real payloads, real calls. Caller gates this on --authorized."""
    path_names = _ACTIVELY_PROBED_NAMES - {"url"}
    url_names = {"url"}

    findings: list[Finding] = []
    for tool in tools:
        if not is_read_only(tool):
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

    # _ACTIVELY_PROBED_NAMES is a hardcoded constant, not derived from
    # catalog/active.yaml's risky_param_names — pins that it stays a subset,
    # so editing the catalog can't silently drift the two apart (whole-repo
    # review nit).
    catalog_names = set(load_active_catalog()["risky_param_names"])
    assert _ACTIVELY_PROBED_NAMES <= catalog_names, (
        f"_ACTIVELY_PROBED_NAMES has names not in the catalog: {_ACTIVELY_PROBED_NAMES - catalog_names}"
    )

    # Regression check: D's evidence must be redacted, not just truncated
    # (Round 1 review this phase — a real hole: D's own best-case SSRF hit,
    # the AWS metadata endpoint, is one hop from real AccessKeyId/
    # SecretAccessKey material, and that text used to go straight into
    # Finding.evidence unredacted).
    leaky_response = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nami-id"
    redacted = redact_secrets(leaky_response)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted, "redact_secrets() failed to redact an AWS key"
    assert "[REDACTED:aws_access_key]" in redacted


if __name__ == "__main__":
    _selftest()
    print("permissions.py self-test passed")
