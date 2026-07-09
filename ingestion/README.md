# ingestion

Two-path **IOC ingestion**: collect indicators of compromise from sources,
normalize them to one record shape, and dedup them into a flat JSONL store.
CLI-driven and run-to-completion — a batch *collection* job, deliberately
independent of the enrichment MCP server one level up (that's the read-only
*lookup* layer; this one *writes*).

> Self-contained: its own component, exercised by its own tests. All committed
> fixtures are synthetic and defanged (RFC 5737 IPs, `*.example`, fake hashes),
> and the tests + CI run fully offline.

## Record shape

Every source normalizes to one `Indicator`, deduped by `(type, indicator)`:

| Field | Meaning |
|---|---|
| `indicator` | the IOC string (URL, IP, domain, or file hash) |
| `type` | one of `url`, `ip_address`, `domain`, `file_hash` |
| `source` | which adapter surfaced it (`feed`) |
| `source_ref` | where it came from (the feed path or URL) |
| `tags` | free-form labels, e.g. `["c2", "phishing"]` |

## Feed schema

The structured-feed adapter reads a JSON array of typed IOC objects.
`indicator` and `type` are required; `tags` is optional:

```json
[
  {"indicator": "http://192.0.2.10/gate.php", "type": "url", "tags": ["c2", "phishing-kit"]},
  {"indicator": "192.0.2.44", "type": "ip_address", "tags": ["c2"]},
  {"indicator": "203.0.113.7", "type": "ip_address"}
]
```

A malformed feed (not JSON, not a top-level array, a row missing a required
field, or a bad `type`) raises one actionable error rather than a stack trace.

## Usage

```bash
python -m ingestion.cli --feed ingestion/fixtures/feed.json
python -m ingestion.cli --feed https://example.org/feed.json --store path/to/store.jsonl
```

`--feed` is required. `--store` defaults to `ingestion/store/indicators.jsonl`.
The committed fixture is a local file so the demo stays offline; a **real run**
points `--feed` at an `http(s)` URL. Known failures (bad source, malformed feed)
print `error: ...` to stderr and exit 1.

## Store

The store is **JSONL** — one record per line, sorted by `(type, indicator)` for
stable, human-diffable diffs. Records are **deduped by `(type, indicator)`**:
re-ingesting a known IOC adds nothing new; when the same key arrives from a
second source, its tags are unioned in while the first source's provenance is
kept. Re-running the same feed is idempotent.

## Testing

```bash
pytest ingestion -v
```

Offline — the tests parse the committed fixture and write only to a temp store.

## Roadmap

PR1 (this) ships the structured-feed adapter. The scraped-source adapter (PR2)
and an enrich bridge to the MCP server over stdio (PR3) follow. See
[`docs/tier5-ingestion.md`](../docs/tier5-ingestion.md) for the full design.
