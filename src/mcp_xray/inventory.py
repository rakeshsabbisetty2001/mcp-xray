"""Connect to an MCP server over stdio and enumerate what it exposes."""
from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass, field

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import Prompt, Resource, Tool


@dataclass
class Inventory:
    tools: list[Tool] = field(default_factory=list)
    resources: list[Resource] = field(default_factory=list)
    prompts: list[Prompt] = field(default_factory=list)


@asynccontextmanager
async def connect(command: str, args: list[str]):
    """Spawn a local MCP server over stdio and yield a live ClientSession.

    ponytail: stdio only for v1 (per plan §1 out-of-scope) — HTTP/SSE transport
    added when a real target needs it, not speculatively.
    """
    params = StdioServerParameters(command=command, args=args)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


async def build_inventory(session: ClientSession) -> Inventory:
    tools = (await session.list_tools()).tools
    try:
        resources = (await session.list_resources()).resources
    except Exception:
        resources = []  # server doesn't implement resources — not an error
    try:
        prompts = (await session.list_prompts()).prompts
    except Exception:
        prompts = []
    return Inventory(tools=tools, resources=resources, prompts=prompts)
