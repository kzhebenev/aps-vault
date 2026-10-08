"""Runs in its own venv with the official `mcp` package (its pins clash with the backend's): starts mcp/server.py over
stdio exactly as an MCP host does, performs the calls given as JSON in argv[1] and prints one JSON result per call.
Used by test_mcp_server.py."""
import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main(calls):
    server = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "mcp", "server.py")
    params = StdioServerParameters(command=sys.executable, args=[server], env=dict(os.environ))
    out = []
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            out.append({"tools": sorted(t.name for t in (await s.list_tools()).tools)})
            for name, args in calls:
                res = await s.call_tool(name, args)
                text = "".join(getattr(c, "text", "") for c in res.content)
                try:
                    data = json.loads(text)
                except ValueError:
                    data = text
                if not res.isError and getattr(res, "structuredContent", None):
                    data = res.structuredContent.get("result", res.structuredContent)
                out.append({"error": bool(res.isError), "data": data})
    print(json.dumps(out))


asyncio.run(main(json.loads(sys.argv[1])))
