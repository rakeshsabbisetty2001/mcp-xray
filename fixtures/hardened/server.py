"""Known-clean baseline — same tool/resource/prompt surface as
fixtures/vulnerable/server.py, sanitized. Used as the false-positive check
in scripts/eval_ground_truth.py: a passive probe finding here is a bug in
the probe, not a real vulnerability. Every one of these should score 0
findings across categories B/C/G.
"""
from __future__ import annotations

from pydantic import BaseModel, Field

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

mcp = MCPServer("mcp-xray-fixture-hardened")


@mcp.tool(
    annotations=ToolAnnotations(readOnlyHint=True),
    description="Summarizes a document.",
)
def summarize_document(text: str) -> str:
    return f"Summary of: {text[:50]}"


class UserFilter(BaseModel):
    field: str = Field(description="Field name to filter on.")


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def lookup_user(username: str, filters: list[UserFilter] | None = None) -> str:
    """Look up a user by username."""
    return f"user info for {username}"


@mcp.resource("notes://readme")
def readme() -> str:
    return "Project notes.\n"


@mcp.prompt(description="Summarize the day.")
def daily_summary(style: str = "concise") -> str:
    return f"Summarize today's notes in a {style} style."


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def read_note(note_id: str) -> str:
    """Read a note by id."""
    notes = {"n1": "buy milk"}
    if note_id not in notes:
        # Sanitized: the anticipated-failure message carries no internal detail.
        raise ToolError("note not found")
    return notes[note_id]


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def fetch_status(service: str) -> str:
    """Check an upstream service's status.

    Regression fixture: a benign error message that legitimately contains a
    URL. probes/errors.py's leak-path regex used to false-positive on the
    path component of a URL as a "unix filesystem path" — this is what
    proves that's fixed (any finding here is a false positive by definition,
    same as every other hardened-fixture tool).
    """
    raise ToolError(f"fetch failed for https://api.example.com/v1/{service}")


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def fetch_document(doc_id: str) -> str:
    """Fetch a document's contents by id."""
    return f"Document {doc_id}: quarterly report draft."


if __name__ == "__main__":
    mcp.run("stdio")
