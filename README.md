# mcp-xray

MCP security red-team harness — points at an MCP server and scores which tools leak data, are over-permissioned, or obey injected instructions.

> Full README (quickstart, prior art, results table) is Phase 5 (packaging + docs) — not written yet. This is a safety note, not the full doc.

## Safety — what `--authorized` actually does

By default `mcp-xray` only reads what a target server tells you (`tools/list`, `resources/list`, static schema inspection) — nothing is ever sent that the server didn't already offer to accept as a normal call.

**`--authorized` sends real attack payloads.** Specifically:

- **SSRF** — makes the target fetch `http://169.254.169.254/latest/meta-data/` (the cloud-provider instance-metadata endpoint), `http://localhost:22`, and `file:///etc/passwd`, on any tool whose parameter looks URL-shaped.
- **Path traversal** — sends `../../../../etc/passwd` and a Windows equivalent to any tool whose parameter looks path-shaped.
- **Secret-bait probing** — calls tools with argument values like `config`, `debug`, `env`, `.env` to see if a response dumps credential-shaped material.

Only run `--authorized` against a server you own or are explicitly authorized to test — same as any other pentest tool. Two things worth being explicit about:

1. **The `read_only_hint` gate is not the safety boundary.** Every probe in this tool only calls tools whose MCP annotations claim `readOnlyHint: true` — but that annotation is self-declared *by the server under test*. A mis-annotated `write_file` or `set_mode` tool would still receive these payloads. `--authorized` (a human deciding to run it) is the actual boundary; the hint only reduces noise against well-behaved servers.
2. **The SSRF probe's risk is about *your* network position, not the target's.** If you run `--authorized` against a server on a cloud instance (yours or otherwise), a vulnerable `fetch_url`-shaped tool will fetch *that host's* real instance-metadata credentials — which then land in the scan output (redacted before they reach any report, but real credentials were still exfiltrated over the network to get there).

No transport beyond locally-spawned stdio processes is supported yet (plan §1 out-of-scope) — there is no way to point this at a remote/hosted MCP server in this version.
