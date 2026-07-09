# Multi-source reputation fan-out — design note

How this server grows from one reputation source (VirusTotal) to several
(URLhaus, urlscan, AbuseIPDB — the latter replacing the originally planned Censys,
see the rollout table) **behind the same normalized verdict shape**, plus the
eval approach. This is the design the rollout PRs implement; it captures decisions
made in review so they don't have to be re-derived.

## Principle

Add sources **additively**, never changing the shape callers already know. The
four `vt_lookup_*` tools keep returning a single-source verdict, unchanged. A new
`lookup_indicator` tool fans out across every configured source and returns an
envelope that carries each source's verdict *verbatim* plus a small consensus.

## Adapter interface

Each source implements `ReputationSource` (`server.py`):

- `name` — e.g. `"virustotal"`, `"urlhaus"`.
- `supports(kind) -> bool` — which of `file` / `url` / `ip_address` / `domain` it answers.
- `configured() -> bool` — its API key is present (else it's *skipped*, never an error).
- `async lookup(kind, value) -> str` — the normalized verdict JSON, or an actionable error line.

VirusTotal is the first adapter; it wraps the existing per-kind lookups. New
sources slot in behind this interface without touching it or the verdict shape.

## Envelope + consensus

`lookup_indicator` returns:

```json
{
  "indicator": "192.0.2.44",
  "type": "ip_address",
  "sources": {
    "virustotal": { <existing normalized verdict, verbatim> },
    "urlhaus":    { <same shape, mapped from URLhaus> }
  },
  "consensus": {
    "malicious": true,                            // any source with malicious > 0
    "suspicious": false,                          // any source with suspicious > 0 (independent)
    "sources_malicious": ["urlhaus","virustotal"],
    "sources_suspicious": [],
    "max_malicious": 5,                           // max across sources — NEVER a sum
    "sources_completed": ["urlhaus","virustotal"],// returned a verdict or a not-found
    "sources_skipped": [],                        // not configured (no key)
    "sources_errored": []                         // errored / rate-limited / timed out
  }
}
```

**Why per-source, not merged counts.** VirusTotal's `malicious: 3` means "3 of ~70
AV engines"; URLhaus has no engines (it counts known-bad URLs on a host). Summing
them invents a meaningless number and blends provenance. So each source fills the
normalized shape with its own best mapping, and consensus only *summarizes* —
booleans + rosters + a `max`, never a cross-source sum. A per-source failure
becomes that source's `{"error": ...}` entry (in `sources_errored`) without sinking
the others — the same per-row degradation `investigate_sample` already uses.

## Sources & keys

| Source | Env key (free) | Kinds | Note |
|---|---|---|---|
| VirusTotal | `VT_API_KEY` | file/url/ip/domain | wired in |
| URLhaus (abuse.ch) | `URLHAUS_API_KEY` | url/ip/domain | wired in — read-only **POST** query; `Auth-Key` header (mandatory since 2025-06-30) |
| urlscan.io | `URLSCAN_API_KEY` | url/ip/domain | wired in — GET search existing scans → read top result's verdict; `API-Key` header |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | ip | wired in — GET check; abuseConfidenceScore (0-100) thresholded to the verdict; `Key` header |
| ~~Censys~~ | — | — | **dropped** — its API returns host/attack-surface data, not a malicious verdict, so it can't produce a reputation verdict; AbuseIPDB fills the IP slot instead |

A source with no key is **skipped**, so the server still runs with just VT — as today.

**Read-only, clarified.** The convention relaxes from "GET-only" to **"read-only
queries only"**: URLhaus's lookup is an HTTP POST but only *queries* (no submission,
no mutation). Nothing in this server ever submits a sample or a URL for scanning.

## Eval suite

Two layers, mirroring the repo's existing `pytest`-vs-`smoke_test.py` split:

- **Offline golden-file eval = the CI gate.** Deterministic, no keys, no network.
  Measures the *pipeline* (extract → dispatch → normalize → consensus) against
  labeled fixtures from the synthetic corpus, with stubbed source responses.
  Metrics: extraction precision/recall, verdict-shape conformance, consensus
  correctness. Blocks regressions in *our* code.
- **Live-key eval = opt-in, non-gating script** (`eval_live.py`). Run manually or
  on a schedule with keys from the environment; asserts loose invariants only
  (EICAR is malicious, a known-clean indicator is clean, shapes conform). Not a
  build gate — fork PRs get no secrets, and live verdicts drift.

## Rollout (one focused PR each)

1. ~~**Adapter refactor** (VT-only, non-breaking) + envelope + `lookup_indicator`.~~ ✅ done
2. ~~**URLhaus adapter** behind the interface (+ key/skip handling + the read-only wording).~~ ✅ done
3. ~~**`investigate_sample` `all_sources` toggle** — fan out per indicator.~~ ✅ done
4. ~~**Eval suite** (offline golden-file gate + opt-in `eval_live.py`).~~ ✅ done
5. ~~**urlscan adapter** (search existing scans -> read the top result's verdict).~~ ✅ done
6. ~~**AbuseIPDB adapter**~~ ✅ done — IP reputation (abuseConfidenceScore → verdict). Replaced
   the planned Censys adapter, which returns host/attack-surface data, not a malicious
   verdict, and so can't produce a reputation verdict for the consensus.

**Rollout complete.** Durable cache persistence was considered and **deliberately not
built**: reputation is time-sensitive, so verdicts shouldn't outlive the process. The
short-TTL in-memory cache is the intended design — persisting to disk would push toward
staler verdicts, add concurrency/I-O complexity and a corruption/trust surface, and
record a durable trail of every indicator looked up, all for little cross-session gain
(the in-memory cache already covers within-session dedup).
