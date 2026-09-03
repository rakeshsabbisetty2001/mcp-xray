"""Category F: schema confusion / input validation.

Sends deliberately wrong-typed values for one required param at a time (a
number where a string is expected, a string where an array is expected,
null everywhere) and a bounded oversized string, watching for two distinct
findings — both real, neither exploitative:

  - crash-with-leak: the malformed input provokes an unhandled error whose
    message leaks internals (reuses G's leak-pattern scanner — same
    detection, different trigger: G's input is benign, F's is malformed).
  - silent acceptance: the tool returns success (is_error=False) despite
    getting the wrong JSON type — the server isn't enforcing its own
    declared schema, so whatever it does with that value downstream is
    unverified by this probe alone.

Active (crafted payload, gated behind --authorized) per Round 2 review's
passive/active split — this category is entirely active by that
definition (catalog/passive.yaml's header), unlike D which has a
structural half.
"""
from __future__ import annotations

import asyncio

from mcp import ClientSession
from mcp.types import Tool

from .base import Finding, Severity
from .patterns import load_active_catalog, scan_for_leaks
from .tool_args import default_args, is_read_only

_CALL_TIMEOUT_S = 15


def _declared_type(prop_schema: dict) -> str | None:
    """The param's JSON-Schema type, unwrapping anyOf/oneOf (how a required
    `X | None`-typed param — no default, so still required — renders: no
    top-level "type" key, just branches). Same failure mode category C was
    fixed for (metadata.py's _describable_fields) — a bare `.get("type")`
    silently misses every anyOf-shaped param, which a `continue` here would
    turn into a silent skip, not a loud gap. $ref (a full nested model
    param, e.g. lookup_user's `filters: list[UserFilter]`) is NOT resolved
    here — only real for this project's fixtures on an optional param
    (skipped anyway, not required), so left as a documented ceiling rather
    than pulling in metadata.py's $defs-resolution machinery for a case
    with no fixture demonstrating it yet."""
    if t := prop_schema.get("type"):
        return t
    for branch in prop_schema.get("anyOf", []) + prop_schema.get("oneOf", []):
        if isinstance(branch, dict) and branch.get("type") not in (None, "null"):
            return branch["type"]
    return None


def _matching_payloads(catalog: dict, declared_type: str) -> list[dict]:
    return [
        p for p in catalog["schema_confusion_payloads"]
        if p["expected_type"] in (declared_type, "any")
    ]


async def _probe_param(
    session: ClientSession, tool: Tool, param_name: str, declared_type: str, catalog: dict
) -> list[Finding]:
    findings = []
    base_args = default_args(tool, skip=param_name)

    for payload in _matching_payloads(catalog, declared_type):
        args = {**base_args, param_name: payload["value"]}
        try:
            result = await asyncio.wait_for(
                session.call_tool(tool.name, args), timeout=_CALL_TIMEOUT_S
            )
        except TimeoutError:
            continue  # a hang on malformed input isn't this probe's finding — no crash/leak/acceptance signal either way
        except Exception:
            continue  # SDK-level rejection (e.g. schema validation before the tool body ever runs) — server working as intended

        text = "\n".join(getattr(c, "text", "") for c in result.content if getattr(c, "text", None))

        if result.is_error:
            for label, matched in scan_for_leaks(text):
                findings.append(Finding(
                    category="F: Schema Confusion (Info Leak)",
                    severity=Severity.MEDIUM,
                    target=f"{tool.name} (param.{param_name})",
                    summary=(
                        f"Malformed input ('{payload['id']}': {declared_type} param given a "
                        f"{type(payload['value']).__name__}) provoked an error that leaked a {label}"
                    ),
                    evidence=matched,
                ))
        else:
            # The call succeeded despite a JSON-type mismatch against the
            # tool's own declared schema — informational: this probe can't
            # know what the tool does with the value downstream, only that
            # it didn't validate its own contract.
            findings.append(Finding(
                category="F: Schema Confusion (Silent Acceptance)",
                severity=Severity(payload["severity"]),
                target=f"{tool.name} (param.{param_name})",
                summary=(
                    f"Tool accepted '{payload['id']}' — a {type(payload['value']).__name__} value "
                    f"for a param whose schema declares type '{declared_type}' — without a "
                    f"validation error. Downstream handling of the mismatched type is unverified."
                ),
                evidence=repr(payload["value"])[:200],
            ))
    return findings


async def _probe_oversized(session: ClientSession, tool: Tool, param_name: str, catalog: dict) -> list[Finding]:
    payload = "x" * catalog["oversized_string_chars"]
    args = {**default_args(tool, skip=param_name), param_name: payload}
    try:
        await asyncio.wait_for(session.call_tool(tool.name, args), timeout=_CALL_TIMEOUT_S)
    except TimeoutError:
        return [Finding(
            category="F: Schema Confusion (DoS Smell)",
            severity=Severity.MEDIUM,
            target=f"{tool.name} (param.{param_name})",
            summary=(
                f"A {catalog['oversized_string_chars']}-char string on this param did not return "
                f"within {_CALL_TIMEOUT_S}s — possible unbounded processing. Heuristic: could also "
                f"be a legitimately slow operation; not proof of a real DoS vector."
            ),
            evidence=f"{catalog['oversized_string_chars']} 'x' characters, no response in {_CALL_TIMEOUT_S}s",
        )]
    except Exception:
        return []  # rejected or crashed cleanly — not a DoS-smell finding
    return []  # returned in time — no finding


async def run(session: ClientSession, tools: list[Tool]) -> list[Finding]:
    """Caller gates this on --authorized — never invoked otherwise.

    Note on _probe_oversized's timeout: asyncio.wait_for cancels the
    in-flight call_tool on timeout, but the target may still be processing
    it — a late response on the same stdio session could land unexpectedly
    during a LATER call. F runs last among cli.py's --authorized probes and
    in scripts/eval_active.py, but --agentic's driver.run() (a separate
    probe, its own real call_tool) can still run after F in the same
    session if both flags are passed together — a real, currently
    unhandled edge case, not fully contained."""
    catalog = load_active_catalog()
    findings: list[Finding] = []
    for tool in tools:
        if not is_read_only(tool):
            continue  # same fail-closed rule as every other tool-calling probe
        schema = tool.input_schema or {}
        props = schema.get("properties", {})
        required = schema.get("required", [])
        oversized_done = False
        for name in required:
            declared_type = _declared_type(props.get(name, {}))
            if not declared_type:
                continue  # documented ceiling — see _declared_type's docstring for what this still misses ($ref)
            findings += await _probe_param(session, tool, name, declared_type, catalog)
            if declared_type == "string" and not oversized_done:
                # One oversized-payload trial per tool, not per param — bounded
                # (plan §2: "DoS smell test, bounded, respectful"), not a call-
                # count multiplier for every string param a tool happens to have.
                findings += await _probe_oversized(session, tool, name, catalog)
                oversized_done = True
    return findings


class _FakeSession:
    """Scripted stand-in for the parts of category F's live-fixture coverage
    the SDK's own pydantic validation makes impossible to trigger for real
    (silent acceptance — a well-typed server correctly rejects every
    top-level type mismatch, verified against both real fixtures). Proves
    the DETECTION logic (branch on is_error, build the right Finding) is
    correct even though no fixture can currently demonstrate this specific
    branch live. The crash-with-leak and SDK-rejection branches ARE also
    covered live (fixtures/vulnerable's process_item, scripts/eval_active.py)
    — this fake only needs to additionally cover what they can't."""

    def __init__(self, response_by_value):
        self._response_by_value = response_by_value

    async def call_tool(self, name, args):
        from mcp.types import CallToolResult, TextContent

        for value, (is_error, text) in self._response_by_value:
            if list(args.values())[0] == value:
                return CallToolResult(content=[TextContent(type="text", text=text)], is_error=is_error)
        raise RuntimeError("no scripted response for this call")  # simulates SDK-level rejection


async def _selftest() -> None:
    from mcp.types import Tool

    catalog = load_active_catalog()
    tool = Tool(
        name="fake_tool", description="d",
        inputSchema={"type": "object", "properties": {"x": {"type": "string"}}, "required": ["x"]},
        annotations=None,
    )

    # Silent acceptance: is_error=False despite a type-mismatched value —
    # can't be triggered by any real fixture in this SDK, only provable here.
    session = _FakeSession([(12345, (False, "ok, processed 12345"))])
    findings = await _probe_param(session, tool, "x", "string", catalog)
    silent = [f for f in findings if "Silent Acceptance" in f.category]
    assert silent, f"expected a silent-acceptance finding, got {findings}"
    assert silent[0].severity == Severity.MEDIUM

    # Crash-with-leak: is_error=True with a leaked path in the message.
    session = _FakeSession([(12345, (True, 'File "/srv/app/handler.py", line 4'))])
    findings = await _probe_param(session, tool, "x", "string", catalog)
    leaked = [f for f in findings if "Info Leak" in f.category]
    assert leaked, f"expected an info-leak finding, got {findings}"

    # SDK-level rejection (the realistic default for a well-typed server):
    # call_tool raises before the tool body runs — no finding either way,
    # that's the server working correctly.
    session = _FakeSession([])  # no scripted response — every call raises
    findings = await _probe_param(session, tool, "x", "string", catalog)
    assert findings == [], f"expected no findings on SDK-level rejection, got {findings}"


if __name__ == "__main__":
    asyncio.run(_selftest())
    print("schema_confusion.py self-test passed")
