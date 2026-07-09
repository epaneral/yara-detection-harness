"""Structured-feed adapter: a JSON array of typed IOCs -> normalized Indicators.

Feed schema (one object per indicator):
    [{"indicator": "192.0.2.10", "type": "ip_address", "tags": ["botnet"]}, ...]

`indicator` and `type` are required; `tags` is optional. `type` must be one of the
Indicator vocabulary values (validated by Indicator itself). A malformed feed raises
a single actionable ValueError rather than a stack trace.
"""

from __future__ import annotations

import json

from ingestion.adapters import read_source
from ingestion.record import Indicator


class FeedAdapter:
    name = "feed"

    def parse(self, source: str) -> list[Indicator]:
        raw = read_source(source)
        try:
            rows = json.loads(raw)
        except ValueError as e:
            raise ValueError(f"feed {source}: not valid JSON ({e})") from e
        if not isinstance(rows, list):
            raise ValueError(f"feed {source}: expected a JSON array of indicator objects")

        records = []
        for i, row in enumerate(rows):
            if not isinstance(row, dict) or "indicator" not in row or "type" not in row:
                raise ValueError(f"feed {source}: row {i} missing 'indicator' or 'type'")
            try:
                records.append(
                    Indicator(
                        indicator=str(row["indicator"]).strip(),
                        type=str(row["type"]).strip(),
                        source=self.name,
                        source_ref=source,
                        tags=tuple(row.get("tags", ())),
                    )
                )
            except ValueError as e:
                raise ValueError(f"feed {source}: row {i}: {e}") from e
        return records
