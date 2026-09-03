# mcp-xray

MCP security red-team harness — points at any MCP server, enumerates its tools/resources/prompts, and scores which ones leak data, are over-permissioned, or obey injected instructions.

Point it at your own MCP server (or a fixture) and get a scored report of what's wrong with it. No 0-days on live third-party services — just a CI-friendly scanner and a demo harness you can point at anything you're authorized to test.

## Prior art

- **[Invariant Labs `mcp-scan`](https://github.com/invariantlabs-ai/mcp-scan)** — the established name in this space, static-analysis-first (tool description/schema poisoning). mcp-xray's static probes (categories B/C) cover similar ground; its differentiator is the **agentic hijack-rate probe** (category A) — an actual driver LLM given a benign task, watching whether it gets hijacked by a poisoned tool output, reported as a measured rate under a stamped model id, not a static heuristic.
- **[Damn Vulnerable MCP Server](https://github.com/harishsg993010/damn-vulnerable-MCP-server)** — used only as inspiration for realistic vulnerability shapes while designing this project's fixtures, never as a code base. Its README claims MIT but the repo ships no actual `LICENSE` file, so `fixtures/vulnerable` and `fixtures/hardened` here are original code.

## Quickstart

Not published to PyPI yet, so no `uvx mcp-xray` one-liner — run from a checkout:

```bash
git clone https://github.com/rakeshsabbisetty2001/mcp-xray && cd mcp-xray
uv sync
uv run mcp-xray npx -y @modelcontextprotocol/server-filesystem /path/to/sandbox
```

Or against the project's own fixtures (no external server needed):

```bash
uv run mcp-xray --authorized uv run python fixtures/vulnerable/server.py
```

The packaging work is done regardless: catalog data ships inside the package (not repo-relative), so once this is published, `uvx mcp-xray <command>` / `pipx install mcp-xray` will work standalone — verified by building the wheel and running it from an isolated install with no checkout on disk.

## What it checks

| # | Category | What it does | Cost |
|---|---|---|---|
| A | Tool-output prompt injection | A driver LLM is given a benign task; the tool's real output carries an injected instruction; measures whether the model requests an unrequested action | `--agentic`, real API calls |
| B | Resource/prompt injection | Scans resource content and prompt templates for instruction-like text | free, always on |
| C | Tool metadata poisoning | Scans tool/param descriptions (including nested schema, `$ref`/`$defs`, `anyOf`) for injected instructions | free, always on |
| D | Over-broad permissions | Structural: flags risky-shaped param names. Active: real path-traversal and SSRF payloads | structural free; active needs `--authorized` |
| E | Secret exfiltration | Bait argument values (config/debug/env) checked for leaked AWS/GitHub/OpenAI-shaped keys, JWTs, private keys | `--authorized` |
| F | Schema confusion | Wrong-JSON-type payloads and a bounded oversized-string check, watching for crash-leaks or silent schema-contract violations | `--authorized` |
| G | Error information leaks | Benign (schema-satisfying) calls, checked for leaked stack traces/paths in error messages | free, always on |

Categories D (active half), E, and F send real attack payloads — see **Safety** below before running `--authorized` against anything but your own server.

## Example output

Real output from `mcp-xray --authorized` against this project's own deliberately-vulnerable fixture (`fixtures/vulnerable/server.py`) — 19 findings across **six** categories (B, C, D, E, F, G; A needs `--agentic` and a real model, not included here):

```
$ mcp-xray --authorized uv run python fixtures/vulnerable/server.py

19 findings — 3 critical · 7 high · 7 medium · 2 low
```

Abridged to one row per (category, tool) pair — the full 19, including every duplicate hit and the exact JSON, come from `--json`:

| Sev | Category | Target |
|---|---|---|
| CRITICAL | D: SSRF | `fetch_url` (param.url) — AWS metadata endpoint |
| CRITICAL | E: Secret Exfiltration | `debug_status` (arg.mode='config') — 2 patterns matched (AWS key + OpenAI-shaped key), one row each in the real output |
| HIGH | C: Tool Metadata Poisoning | `summarize_document` (description), `lookup_user` (nested `$ref` field) |
| HIGH | B: Resource Injection / Prompt Injection | `readme`, `daily_summary` (description) |
| HIGH | D: Path Traversal / SSRF | `read_file` (param.path), `fetch_url` (param.url) — 2 more SSRF payloads |
| MEDIUM | G: Error Information Leak | `read_note`, `process_item` |
| MEDIUM | F: Schema Confusion (Info Leak) | `process_item` (param.item) |
| LOW | D: Over-Broad Permission (Structural) | `read_file`, `fetch_url` |

The same fixture's hardened counterpart (`fixtures/hardened/server.py`, same tool surface, sanitized) scores **0 findings** — that's the calibration baseline (`scripts/eval_ground_truth.py`, `scripts/eval_active.py`), not a cherry-picked demo.

> No animated demo GIF yet — this environment had no terminal-recording tooling (`vhs`/`asciinema`/`ffmpeg`) available when this README was written. The table above is real captured JSON output, hand-formatted for readability. A GIF is a cheap follow-up whenever there's a machine with that tooling.

## Calibration

Two scripts run mcp-xray's own probes against the fixture pair and report precision/recall against a hand-authored ground truth:

```bash
uv run python scripts/eval_ground_truth.py   # passive: B, C, G
uv run python scripts/eval_active.py         # active: D, E, F
```

Both currently report **1.00 precision / 1.00 recall** — but read that number correctly: it's calibration on the single fixture pair the probes were authored against, run in CI on every probe-catalog change. It's a real signal that the detection wiring works end to end, **not** a generalization estimate of real-world accuracy against servers this project has never seen. Both scripts print that caveat every time they run.

## CI usage

```bash
mcp-xray --json report.json <command> [args...]
echo $?   # 0 = clean, 1 = High+ findings, 2 = crash/misuse
```

`--agentic` findings never gate the exit code by default (a hijack rate is a signal to read, not a pass/fail) — opt in with `--fail-on-hijack-rate N`.

## Safety — what `--authorized` actually does

By default `mcp-xray` only reads what a target server tells you (`tools/list`, `resources/list`, static schema inspection) — nothing is ever sent that the server didn't already offer to accept as a normal call.

**`--authorized` sends real attack payloads.** Specifically:

- **SSRF** — makes the target fetch `http://169.254.169.254/latest/meta-data/` (the cloud-provider instance-metadata endpoint), `http://localhost:22`, and `file:///etc/passwd`, on any tool whose parameter looks URL-shaped.
- **Path traversal** — sends `../../../../etc/passwd` and a Windows equivalent to any tool whose parameter looks path-shaped.
- **Secret-bait probing** — calls tools with argument values like `config`, `debug`, `env`, `.env` to see if a response dumps credential-shaped material.
- **Schema-confusion probing** — sends wrong-JSON-type values and a bounded (50KB) oversized string to required params.

Only run `--authorized` against a server you own or are explicitly authorized to test — same as any other pentest tool. Two things worth being explicit about:

1. **The `read_only_hint` gate is not the safety boundary.** Every probe in this tool only calls tools whose MCP annotations claim `readOnlyHint: true` — but that annotation is self-declared *by the server under test*. A mis-annotated `write_file` or `set_mode` tool would still receive these payloads. `--authorized` (a human deciding to run it) is the actual boundary; the hint only reduces noise against well-behaved servers.
2. **The SSRF probe's risk is about *your* network position, not the target's.** If you run `--authorized` against a server on a cloud instance (yours or otherwise), a vulnerable `fetch_url`-shaped tool will fetch *that host's* real instance-metadata credentials — which then land in the scan output (redacted before they reach any report, but real credentials were still exfiltrated over the network to get there).

No transport beyond locally-spawned stdio processes is supported yet — there is no way to point this at a remote/hosted MCP server in this version.

## Redaction

Category E's secret hits and category D's SSRF/path-traversal responses are redacted at the point of capture, not in a report writer downstream — `Finding.evidence` for a real credential match is never the raw secret, only `[REDACTED:<pattern_id>]`, in every output format (console/JSON/HTML). Full unredacted matches can be saved to a local, gitignored directory with `--unsafe-full-transcripts DIR` (only meaningful with `--authorized`), never printed and never in any of the three reports.

## Status

The full probe catalog (A–G) is built and reviewed. `--agentic` (category A) has now run against a real model (claude-sonnet-5) for the first time — 6 live trials against the `fetch_document` fixture case, 0 hijacks. That's a genuine result on a tiny sample, not a validated hijack-rate baseline; a real evaluation needs many more trials across more tools and payload variations before the rate means anything statistically. (First live call also caught and fixed a real bug: the installed Anthropic SDK version has no `temperature` parameter, which Phase 3's fake-driver-only self-tests never exercised.) Not yet done: a demo GIF (tooling gap, see above), a Show HN launch post, broader real-world validation beyond this project's own fixture pair, and a real sampling-variance strategy now that `temperature` isn't available in this API version.
