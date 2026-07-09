"""Enrich the ingested store: look each stored indicator up across the reputation
sources, by driving the enrichment-mcp server over stdio.

The two components stay independent: this bridge talks to the server as a separate
*process* over stdio (the pattern in enrichment-mcp/investigate_demo.py), never
importing its code. It reads the JSONL store this component writes and calls the
server's `lookup_indicator` tool, which fans out across every configured source.

Running the live bridge needs the enrichment-mcp server's deps available to the
launching interpreter (mcp, httpx, pydantic, ...) -- e.g. run it from an env with
both components installed. The `mcp` import is therefore lazy: importing this module
(and the offline tests, which drive the aggregation core with a stub) needs none of
that, so the ingestion CI job stays lean.

    python -m ingestion.enrich --store ingestion/store/indicators.jsonl
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path

from ingestion import store
from ingestion.record import Indicator

DEFAULT_STORE = Path("ingestion/store/indicators.jsonl")
DEFAULT_SERVER = Path("enrichment-mcp/server.py")

# The server's lookup tool types a hash as "file"; the ingestion store uses
# "file_hash". The other three names already match.
_SERVER_TYPE = {"file_hash": "file", "url": "url", "ip_address": "ip_address", "domain": "domain"}

# call_tool(indicator, server_type) -> the tool's raw JSON string (or an error line).
CallTool = Callable[[str, str], Awaitable[str]]


async def enrich_indicators(
    indicators: list[Indicator], call_tool: CallTool, delay_seconds: float = 0.0
) -> list[dict]:
    """Enrich each indicator via `call_tool`; return one row per indicator.

    `call_tool` is injected so the aggregation is testable without a live server. A
    per-indicator failure becomes that row's `error` without sinking the rest.
    """
    rows = []
    for i, ind in enumerate(indicators):
        if i and delay_seconds:
            await asyncio.sleep(delay_seconds)
        raw = await call_tool(ind.indicator, _SERVER_TYPE[ind.type])
        row = {"indicator": ind.indicator, "type": ind.type}
        try:
            row["enrichment"] = json.loads(raw)
        except ValueError:
            row["error"] = raw
        rows.append(row)
    return rows


def _is_malicious(row: dict) -> bool:
    return bool(row.get("enrichment", {}).get("consensus", {}).get("malicious"))


def summarize(rows: list[dict]) -> dict:
    """One-glance tally over the enriched rows."""
    return {
        "enriched": len(rows),
        "malicious": sum(1 for r in rows if _is_malicious(r)),
        "errors": sum(1 for r in rows if "error" in r),
    }


async def _drive_server(
    indicators: list[Indicator], server_path: Path, delay_seconds: float
) -> list[dict]:
    """Launch the enrichment-mcp server over stdio and enrich via `lookup_indicator`."""
    from mcp import ClientSession, StdioServerParameters  # lazy: only the live path needs mcp
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(command=sys.executable, args=[str(server_path)])
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()

        async def call_tool(indicator: str, server_type: str) -> str:
            result = await session.call_tool(
                "lookup_indicator", {"params": {"indicator": indicator, "type": server_type}}
            )
            return "".join(getattr(block, "text", "") for block in result.content)

        return await enrich_indicators(indicators, call_tool, delay_seconds)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Enrich the ingested IOC store via the enrichment-mcp server."
    )
    parser.add_argument("--store", type=Path, default=DEFAULT_STORE, help="JSONL store to enrich")
    parser.add_argument(
        "--server", type=Path, default=DEFAULT_SERVER, help="path to enrichment-mcp/server.py"
    )
    parser.add_argument("--limit", type=int, default=0, help="enrich only the first N (0 = all)")
    parser.add_argument(
        "--delay-seconds", type=float, default=0.0, help="pause between lookups (rate-limit pacing)"
    )
    args = parser.parse_args(argv)

    indicators = list(store.load(args.store).values())
    if args.limit:
        indicators = indicators[: args.limit]
    if not indicators:
        print(
            f"no indicators in {args.store}; run `python -m ingestion.cli` first", file=sys.stderr
        )
        return 1

    try:
        rows = asyncio.run(_drive_server(indicators, args.server, args.delay_seconds))
    except ImportError as e:
        print(
            f"error: enrichment-mcp client deps not installed ({e}); run the bridge in an "
            "env with both components' deps",
            file=sys.stderr,
        )
        return 1
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    print(json.dumps({"summary": summarize(rows), "results": rows}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
