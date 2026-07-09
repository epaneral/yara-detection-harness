"""Ingestion CLI: run the source adapters, merge results into the JSONL store.

    python -m ingestion.cli --feed ingestion/fixtures/feed.json
    python -m ingestion.cli --feed https://example/feed.json --store path/to/store.jsonl

PR1 wires the structured-feed adapter; the scraped-source adapter joins here in PR2.
Known failure modes (bad source, malformed feed) print one actionable line and exit 1.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ingestion import store
from ingestion.adapters.feed import FeedAdapter

DEFAULT_STORE = Path("ingestion/store/indicators.jsonl")


def run(feed: str, store_path: str | Path) -> int:
    records = FeedAdapter().parse(feed)
    merged, added = store.merge(store.load(store_path), records)
    store.write(store_path, merged)
    print(
        f"ingested {len(records)} record(s) from {feed}; "
        f"{added} new, {len(merged)} total in {store_path}"
    )
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Ingest IOCs into the normalized JSONL store.")
    parser.add_argument("--feed", help="structured JSON feed (file path or http(s) URL)")
    parser.add_argument("--store", type=Path, default=DEFAULT_STORE, help="JSONL store path")
    args = parser.parse_args(argv)
    if not args.feed:
        parser.error("provide at least one source (--feed)")
    try:
        return run(args.feed, args.store)
    except (ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
