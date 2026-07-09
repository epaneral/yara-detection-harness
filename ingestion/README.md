# ingestion

Two-path **IOC ingestion**: collect indicators of compromise from sources,
normalize them to one record shape, and dedup them into a flat JSONL store.
CLI-driven and run-to-completion — a batch *collection* job, deliberately
independent of the enrichment MCP server one level up (that's the read-only
*lookup* layer; this one *writes*).

Two adapters surface those indicators: the **structured feed** (a JSON array of
typed IOC objects) and the **scraped source** (an HTML/text page mined for IOCs).
Either or both can run in a single invocation; their results are merged and
deduped into the same store.

> Self-contained: its own component, exercised by its own tests. All committed
> fixtures are synthetic and defanged (RFC 5737 IPs, `*.example`, fake hashes),
> and the tests + CI run fully offline.

## Record shape

Every source normalizes to one `Indicator`, deduped by `(type, indicator)`:

| Field | Meaning |
|---|---|
| `indicator` | the IOC string (URL, IP, domain, or file hash) |
| `type` | one of `url`, `ip_address`, `domain`, `file_hash` |
| `source` | which adapter surfaced it (`feed` or `scrape`) |
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

## Scraped source

The scraped-source adapter mines an HTML/text page (advisory, paste dump) for
IOCs. It strips the HTML to visible text and is **defang-aware**, refanging the
common forms (`hxxp`, `[.]`, `(dot)`, `[:]`) before extracting URLs, IPs, file
hashes, and domains. Bare domains are taken **only when they were defanged** in
the source (or appear as a URL host / email domain), so incidental filenames
(`install.sh`) and non-defanged domains (`static.rust-lang.org`) aren't picked
up as indicators.

## Usage

```bash
python -m ingestion.cli --feed ingestion/fixtures/feed.json
python -m ingestion.cli --scrape ingestion/fixtures/scrape.html
python -m ingestion.cli --feed https://example.org/feed.json --store path/to/store.jsonl
```

At least one of `--feed` / `--scrape` is required, and they can be **combined**
in one run — their results merge and dedup into the same store. `--store`
defaults to `ingestion/store/indicators.jsonl`. The committed fixtures are local
files so the demo stays offline; a **real run** points `--feed`/`--scrape` at an
`http(s)` URL. Known failures (bad source, malformed feed) print `error: ...` to
stderr and exit 1.

## Enrich

Once the store is populated, the **enrich bridge** looks each stored indicator
up across the reputation sources by driving the enrichment-mcp server as a
separate process over stdio (the `investigate_demo.py` pattern) — never importing
its code. For each indicator it calls the server's `lookup_indicator` tool, which
fans out across every configured reputation source and returns a per-source
verdict plus a consensus. Results are printed as JSON with a
one-glance `summary` (`enriched` / `malicious` / `errors`).

```bash
python -m ingestion.enrich --store ingestion/store/indicators.jsonl
python -m ingestion.enrich --limit 20 --delay-seconds 15   # pace lookups to respect rate limits
```

Flags: `--store` (JSONL store to enrich, defaults to
`ingestion/store/indicators.jsonl`), `--server` (path to `enrichment-mcp/server.py`),
`--limit` (enrich only the first N; `0` = all), and `--delay-seconds` (pause
between successive lookups for rate-limit pacing).

A **live run** needs the enrichment-mcp server's deps (`mcp`, `httpx`, ...)
available to the launching interpreter — run it from an env with **both**
components installed. The `mcp` import is lazy, so the offline tests and CI need
none of that: they drive the aggregation core with a stubbed `call_tool` and no
server ever starts.

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

All three ingestion PRs have now shipped — the structured-feed adapter (PR1), the
scraped-source adapter (PR2), and the enrich bridge to the MCP server over stdio
(PR3) — so **Tier 5 is complete**. See
[`docs/tier5-ingestion.md`](../docs/tier5-ingestion.md) for the full design.
