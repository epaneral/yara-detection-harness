"""Ingestion CLI: run the source adapters, merge results into the JSONL store.

    python -m ingestion.cli --feed ingestion/fixtures/feed.json
    python -m ingestion.cli --scrape ingestion/fixtures/scrape.html
    python -m ingestion.cli --feed https://x/feed.json --scrape https://x/report.html

Runs the structured-feed and/or scraped-source adapters and merges their results.
Known failure modes (bad source, malformed feed) print one actionable line and exit 1.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ingestion import store
from ingestion.adapters.feed import FeedAdapter
from ingestion.adapters.scrape import ScrapeAdapter

DEFAULT_STORE = Path("ingestion/store/indicators.jsonl")


def run(feed: str | None, scrape: str | None, store_path: str | Path) -> int:
    records = []
    sources = 0
    if feed:
        records.extend(FeedAdapter().parse(feed))
        sources += 1
    if scrape:
        records.extend(ScrapeAdapter().parse(scrape))
        sources += 1
    merged, added = store.merge(store.load(store_path), records)
    store.write(store_path, merged)
    print(
        f"ingested {len(records)} record(s) from {sources} source(s); "
        f"{added} new, {len(merged)} total in {store_path}"
    )
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Ingest IOCs into the normalized JSONL store.")
    parser.add_argument("--feed", help="structured JSON feed (file path or http(s) URL)")
    parser.add_argument("--scrape", help="HTML/text page to scrape for IOCs (file or http(s) URL)")
    parser.add_argument("--store", type=Path, default=DEFAULT_STORE, help="JSONL store path")
    args = parser.parse_args(argv)
    if not args.feed and not args.scrape:
        parser.error("provide at least one source (--feed and/or --scrape)")
    try:
        return run(args.feed, args.scrape, args.store)
    except (ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
