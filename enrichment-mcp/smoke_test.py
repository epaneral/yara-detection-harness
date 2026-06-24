"""
Live end-to-end smoke test for the enrichment MCP server.

Launches server.py over stdio exactly as an MCP client would, completes the
handshake, lists the tools, and calls vt_lookup_file_hash on the EICAR test
hash - printing the normalized verdict. With a VT_API_KEY in .env you get a
real VirusTotal verdict; without one you get the actionable "key not set"
message, which still proves the client/server wiring works.

Run (after Setup in README):  python smoke_test.py
"""

import asyncio
import pathlib
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SERVER = str(pathlib.Path(__file__).with_name("server.py"))
# EICAR antimalware test-file SHA-256 (a benign test signature, well-known to VT).
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


async def main():
    # Launch the server under the same interpreter running this script, so it
    # shares the venv (deps) and finds the adjacent .env.
    params = StdioServerParameters(command=sys.executable, args=[SERVER])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            info = await session.initialize()
            print(f"connected to '{info.serverInfo.name}'")
            tools = await session.list_tools()
            print("tools:", ", ".join(t.name for t in tools.tools))
            print(f"\nlooking up EICAR hash {EICAR_SHA256} ...")
            result = await session.call_tool(
                "vt_lookup_file_hash", {"params": {"file_hash": EICAR_SHA256}}
            )
            for block in result.content:
                print(getattr(block, "text", block))


if __name__ == "__main__":
    asyncio.run(main())
