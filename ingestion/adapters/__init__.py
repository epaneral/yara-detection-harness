"""Ingestion source adapters: each turns a source (URL or file) into normalized
Indicators. PR1 ships the structured-feed adapter; the scraped-source adapter follows.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

import httpx

from ingestion.record import Indicator

_TIMEOUT = 30.0


class Adapter(Protocol):
    """A source adapter. `name` labels provenance; `parse` returns normalized records."""

    name: str

    def parse(self, source: str) -> list[Indicator]: ...


def read_source(source: str) -> str:
    """Fetch a URL (a real feed/page) or read a local file (a fixture).

    The one seam that touches the network: tests and CI pass local fixture paths, so
    they stay offline; a real run passes an http(s) URL. httpx errors become one
    actionable line rather than a leaked stack trace.
    """
    if source.startswith(("http://", "https://")):
        try:
            resp = httpx.get(source, timeout=_TIMEOUT)
            resp.raise_for_status()
        except httpx.HTTPError as e:
            raise ValueError(f"fetch failed for {source}: {e}") from e
        return resp.text
    # utf-8-sig: transparently strip a leading BOM (common in Windows-origin feeds and
    # scraped pages) that would otherwise break json.loads / the extraction regexes.
    return Path(source).read_text(encoding="utf-8-sig")
