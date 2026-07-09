"""JSONL store of normalized indicators: load, merge (dedup by key), write.

One JSON object per line, sorted by key on write for stable, human-diffable output.
Flat file by design — no database (matches the repo's style; durable persistence is
out of scope).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from ingestion.record import Indicator

Store = dict[tuple[str, str], Indicator]


def load(path: str | Path) -> Store:
    """Read a JSONL store into {key: Indicator}. A missing file is an empty store."""
    path = Path(path)
    if not path.exists():
        return {}
    store: Store = {}
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            record = Indicator.from_dict(json.loads(line))
        except ValueError as e:
            raise ValueError(f"{path}: line {lineno}: {e}") from e
        store[record.key] = record
    return store


def merge(existing: Store, incoming: Iterable[Indicator]) -> tuple[Store, int]:
    """Merge incoming records into existing (dedup by key). Returns (store, new_count)."""
    store: Store = dict(existing)
    added = 0
    for record in incoming:
        if record.key in store:
            store[record.key] = store[record.key].merged_with(record)
        else:
            store[record.key] = record
            added += 1
    return store, added


def write(path: str | Path, store: Store) -> None:
    """Write the store as JSONL, sorted by key for stable diffs."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(store[key].to_dict(), ensure_ascii=False) for key in sorted(store)]
    path.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")
