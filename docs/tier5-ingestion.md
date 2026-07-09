# Tier 5 — Two-path IOC ingestion (design note)

Status: **shipped** (all three PRs merged). Reference for the `ingestion/` component
(roadmap "Two-path ingestion: one scraped static source + one structured feed").

## Goal

Collect indicators of compromise (IOCs) from two source *types* — a scraped static
page and a structured feed — normalize them to one record shape, and dedup them into a
store. Groundwork the enrichment lookups can build on end-to-end.

## Decisions

| Fork | Decision | Why |
|---|---|---|
| What to ingest | **Indicators / IOCs** | Matches the "scraped source + structured feed" language; reuses the enrichment `{indicator, type}` vocabulary. |
| Where it lives | **New `ingestion/` component** | Separates a batch *collection* pipeline from the read-only *lookup* server; own deps/CI/lock, matching the repo's per-component pattern; avoids colliding with the in-flight MCP work. |
| Real vs synthetic | **Real adapters, synthetic in CI** | Real scraper/feed adapters, but committed fixtures + tests + CI use defanged synthetic data; a documented `--live` mode hits real sources, never in CI. Mirrors enrichment-mcp's stubbed tests + optional smoke test. |
| Scraped-source parser | **beautifulsoup4** (stdlib `html.parser` backend) | Pure-Python, no compiled/lxml dep — minimal and reproducible. Strip tags → text → defang-aware regex. |
| Store format | **JSONL** | Append/merge-friendly, human-diffable, flat-file (matches the repo's style; no DB). |
| Interface | **CLI-only** | Ingestion is a run-to-completion batch job, not an interactive request; keeps the component dep-light and preserves the read-only-server boundary (ingestion *writes*). An MCP tool can wrap the same functions later if wanted. |

## Non-goals (scope fence)

No live malware samples on disk; no real network in CI; not a scheduler/daemon; no
database. All committed fixtures are defanged (RFC 5737 IPs, `*.example`, fake hashes).

## Architecture

New self-contained `ingestion/` folder, structured like enrichment-mcp:

```
ingestion/
  __init__.py
  record.py         normalized indicator record + dedup key
  store.py          JSONL read/merge/write, dedup by (type, indicator)
  adapters/
    __init__.py     Adapter protocol -> list[record]
    feed.py         structured-feed adapter (JSON/CSV of typed IOCs)
    scrape.py       scraped-source adapter (bs4 + defang-aware extraction)
  cli.py            entrypoint: run adapters -> merge -> write store
  fixtures/         synthetic sources + expected normalized records
  test_*.py         offline tests over fixtures
  requirements.txt  + requirements.lock (uv, hashed)
  README.md
```

**Normalized record** (reuses the enrichment vocabulary, adds provenance):

```json
{ "indicator": "...", "type": "url|ip_address|domain|file_hash",
  "source": "<adapter name>", "source_ref": "<url/feed id>", "tags": ["..."] }
```

Dedup key = `(type, indicator)`; merge keeps provenance across sources.

**Adapters** share one interface (source path/URL → `list[record]`):
- **feed.py** — parse a JSON/CSV feed of already-typed IOCs; map fields to the record.
- **scrape.py** — fetch an HTML/text page, strip to text (bs4), extract IOCs with
  defang-aware regex (`hxxp://`, `1.2.3[.]4`, `evil[.]com`).

**Scope-fence handling.** Adapters take a source URL/path. Tests + CI run only against
`fixtures/` (no network). A `--live` CLI flag points at real sources; not run in CI.

## Reuse notes

The `{indicator, type}` shape and extraction regexes mirror enrichment-mcp's, but the
components are deliberately independent (no cross-imports) — as the harness and
enrichment-mcp already are. `ingestion/` carries its own small indicator module rather
than reaching across the boundary. The **enrich bridge** (PR3) reuses enrichment-mcp
*as a client* by driving its server over stdio — the pattern in `investigate_demo.py`.

## Testing / CI

New `ingestion` CI job (own `requirements.lock`, hashed via uv), added to `all-green`.
Tests mirror enrichment-mcp discipline: fixture → expected-normalized-records per
adapter; dedup/merge; store round-trip; defang normalization; malformed input returns
one actionable line, never a stack trace. ruff-clean.

## Phasing

All three shipped:

- **PR1** (#33) — component skeleton: record, JSONL store, structured-feed adapter,
  synthetic fixtures, CI job + lock, README.
- **PR2** (#37) — scraped-source adapter (bs4 + defang-aware extraction) + tests.
- **PR3** — enrich bridge: `python -m ingestion.enrich` drives the enrichment-mcp server
  over stdio, looking each stored indicator up via `lookup_indicator` (fan-out across
  every configured source). The aggregation core is offline-tested with a stubbed
  `call_tool`; the `mcp` import is lazy so CI needs no server deps.

## Not this: retro-hunt

The next roadmap item (retro-hunt) is "new *rules* over the stored *corpus*" — a
different axis than IOC ingestion. Ingestion is complementary, not a prerequisite; the
two stay independent rather than being forced together.
