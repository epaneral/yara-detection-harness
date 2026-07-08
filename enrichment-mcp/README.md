# enrichment-mcp

A small, local **MCP server** that wraps the [VirusTotal v3](https://docs.virustotal.com/reference/overview)
reputation API as tools an LLM agent can call during an investigation.

It's the **enrichment layer** for this repo. The YARA harness one level up detects
malicious *patterns*; this answers the next question a real investigation asks —
*"that rule fired — is the indicator it surfaced (a hash, a URL) actually
known-bad?"* One source today (VirusTotal), but the tool interface is built so
more reputation sources could slot in behind the same normalized verdict.

> Self-contained: this folder has its own dependencies and does not touch the
> harness or its CI. It is not exercised by the repo's pytest suite.

## Tools

| Tool | Input | Returns |
|---|---|---|
| `vt_lookup_file_hash` | `file_hash` (MD5 / SHA-1 / SHA-256) | normalized verdict |
| `vt_lookup_url` | `url` (incl. scheme) | normalized verdict |
| `vt_lookup_ip_address` | `ip` (IPv4) | normalized verdict |
| `vt_lookup_domain` | `domain` | normalized verdict |
| `extract_indicators` | `text` | URLs / IPs / domains in the text (no network) |
| `investigate_sample` | `text`, `max_indicators`, `delay_seconds` | extract + chain a lookup per indicator → aggregated report |

The four `vt_lookup_*` tools return the **same normalized shape** — the answer, not
VirusTotal's raw 500-field blob:

```json
{
  "indicator": "44d88612fea8a8f36de82e1278abb02f",
  "type": "file",
  "malicious": 62,
  "suspicious": 0,
  "harmless": 0,
  "undetected": 8,
  "reputation": -875,
  "flagged_by": ["ALYac", "AVG", "Avast", "BitDefender", "ClamAV"],
  "permalink": "https://www.virustotal.com/gui/file/44d88612fea8a8f36de82e1278abb02f"
}
```

All tools are **read-only**: the lookups are GET-only (nothing is submitted,
modified, or deleted), and `extract_indicators` makes no network call at all.

## Chained investigation

`investigate_sample` is the "auto-extract + chain" step after a YARA rule fires: hand
it a flagged sample's **text** and it extracts the indicators (same logic as
`extract_indicators`), looks each up sequentially (unpaced by default — set
`delay_seconds` to pace for the free-tier rate limit; ~15 stays under ~4/min),
and returns one aggregated report:

```json
{
  "summary": {"indicators_found": 2, "looked_up": 2, "skipped_for_cap": 0,
              "malicious": 1, "suspicious": 0, "clean_or_unknown": 0,
              "not_found": 1, "errors": 0},
  "results": [
    {"indicator": "http://192.0.2.77/install.sh", "type": "url", "verdict": { ... }},
    {"indicator": "192.0.2.44", "type": "ip_address", "error": "Not found: ..."}
  ],
  "skipped": [],
  "note": "Looked up 2 of 2 indicators sequentially, with no pacing delay (set delay_seconds to pace); VT free tier is ~4/min, 500/day."
}
```

Each result carries a `verdict` *or* an `error`, so one indicator's 404/429 never sinks
the rest. Extraction pulls URLs, bare IPv4s, and email domains; a host inside a URL is not
re-counted, and standalone bare-domain scanning is skipped (dotted code identifiers like
`System.Net.WebClient` are indistinguishable from domains without a TLD list).

**Defanged-corpus caveat:** the repo's corpus is synthetic — RFC 5737 `192.0.2.x`,
`*.example.*`, fake tokens — so live lookups on it mostly return `not_found`. That is
expected: it proves the extract → chain → aggregate *wiring*, not real detections. Point
it at a real sample to see real verdicts.

### End-to-end demo (YARA → investigate)

`investigate_demo.py` ties this to the harness: it compiles the repo's YARA rules,
scans the corpus, and runs `investigate_sample` on each *flagged* sample's text — the
full "flag → auto-extract → chain" flow. YARA stays out of the server; only the demo
imports it (a demo-only dep, not in `requirements.txt`):

```bash
pip install yara-python      # demo-only, into the same env as the server deps
python investigate_demo.py   # a key in .env gives live verdicts
```

## Setup

Requires a real Python 3.10+ interpreter (the Windows Store stub won't work).

```bash
cd enrichment-mcp
python -m venv .venv
.venv\Scripts\activate          # Windows;  source .venv/bin/activate on macOS/Linux
pip install -r requirements.txt
```

Provide your free VirusTotal API key as an environment variable:

```powershell
# PowerShell
$env:VT_API_KEY = "your_key_here"
```
```bash
# bash/zsh
export VT_API_KEY="your_key_here"
```

Or copy `.env.example` to `.env` and put the key there (auto-loaded for local
testing; `.env` is gitignored).

## Run / test it

The server speaks **stdio** and is normally launched by an MCP client. To poke
the tools by hand, use the MCP Inspector (with the [Setup](#setup) venv active, so
`python` resolves to the interpreter that has the deps):

```bash
npx @modelcontextprotocol/inspector python server.py
```

In the Inspector, call `vt_lookup_file_hash` with a known test hash (e.g. the
EICAR test file MD5 `44d88612fea8a8f36de82e1278abb02f`) and confirm you get a
normalized verdict back.

### Wire it into Claude Code

This repo ships a project-scoped [`.mcp.json`](../.mcp.json) at its root, so Claude
Code discovers the server automatically — open the project and approve `enrichment-vt`
when prompted. (MCP servers load at session start, so it appears in a *new* session.)
It launches the server with this folder's `.venv` and reads the key from `.env`, so
run [Setup](#setup) first; no key goes in the client config.

The `command` resolves the venv interpreter cross-platform via env-var expansion:
`${ENRICHMENT_VENV_PYTHON:-enrichment-mcp/.venv/Scripts/python.exe}`. The default is
the **Windows** venv path, so Windows works with no extra step. On **macOS/Linux**,
the venv puts Python under `bin/` instead of `Scripts/`, so set `ENRICHMENT_VENV_PYTHON`
to the POSIX path before launching the client (the value still points at this folder's
`.venv`, so it keeps the dependency-carrying interpreter):

```bash
# bash/zsh — set in your shell profile so every session sees it
export ENRICHMENT_VENV_PYTHON="enrichment-mcp/.venv/bin/python"
```

| Platform | venv interpreter used |
|---|---|
| Windows | `enrichment-mcp/.venv/Scripts/python.exe` (default — nothing to set) |
| macOS/Linux | `enrichment-mcp/.venv/bin/python` (via `ENRICHMENT_VENV_PYTHON`) |

For other clients (e.g. Claude Desktop), point them at that same `.venv` interpreter
running `server.py` over stdio; the key is read from `.env` (or pass `VT_API_KEY` in
the client's `env` block).

## Verify it works

Two ways to confirm the tools work after cloning — pick by whether you have a
(free) VirusTotal key. Both run from the repo root.

**No key, no network — the tool logic, deterministically:**

```bash
pip install -r enrichment-mcp/requirements-dev.txt
pytest enrichment-mcp -v
```

`test_server.py` covers the pure helpers; `test_tools.py` drives the `vt_lookup_*`
tools end-to-end with the network stubbed — validation → fetch → normalize →
verdict, plus the missing-key and 404 paths. No API key, no internet; these also
run in CI.

**With a free key — a live call against VirusTotal:**

Put your key in `.env` (see [Setup](#setup)), then drive the real server over stdio:

```bash
python enrichment-mcp/smoke_test.py
```

It connects, lists the tools, and prints a verdict for the EICAR test hash
(dozens of engines `malicious`). Without a key it still connects and the tool
returns the actionable `VT_API_KEY is not set` message — proof the wiring works
either way.

Expected output (with a key):

```
connected to 'virustotal_mcp'
tools: vt_lookup_file_hash, vt_lookup_url, vt_lookup_ip_address, vt_lookup_domain, extract_indicators, investigate_sample

looking up EICAR hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f ...
{
  "indicator": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
  "type": "file",
  "malicious": 64,
  "suspicious": 0,
  "harmless": 0,
  "undetected": 2,
  "reputation": 3781,
  "flagged_by": ["ALYac", "APEX", "AVG", "AhnLab-V3", "Alibaba"],
  "permalink": "https://www.virustotal.com/gui/file/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
}
```

### Live in an MCP client

The same tools wired into Claude Desktop: a natural-language ask invokes the
`enrichment-vt` tool, which returns the normalized verdict (here for the EICAR
test hash).

![Hash-lookup ask invoking the enrichment-vt tool in Claude Desktop](../docs/enrichment-vt-lookup.png)

![The normalized VirusTotal verdict returned in Claude Desktop](../docs/enrichment-vt-verdict.png)

## Error handling

Every failure mode returns a single actionable line, never a stack trace:

| Situation | Response |
|---|---|
| `VT_API_KEY` unset | `Error: VT_API_KEY is not set. Get a free key at ...` |
| Bad/invalid key (401) | `Error: VirusTotal rejected the API key (401). ...` |
| Rate limited (429) | `Error: VirusTotal rate limit hit (429). The free tier allows ~4/min ...` |
| Indicator unknown (404) | `Not found: '<indicator>' is not in VirusTotal's dataset ...` |
| Timeout / network error | `Error: request to VirusTotal timed out ...` / `network error ...` |

A transient **429 or 5xx is retried first** — honoring a `Retry-After` header when
present, otherwise bounded exponential backoff, capped at a few attempts — and only
degrades to the one-line message above once retries are exhausted. Lookups share a
single pooled HTTP client (closed on server shutdown) rather than opening a fresh
connection per call, and each **successful** lookup is served through a small
in-process TTL cache — so a repeated indicator (including across an `investigate_sample`
run) reuses the stored verdict instead of re-hitting VirusTotal. Errors are never cached.

## Security notes

- **Key in env, never in code or git.** `.env` is gitignored; `.env.example` is a
  template only.
- **Read-only.** Only reputation *lookups*; no submission or mutation endpoints.
- **Rate-limited by design** on the free tier — handled gracefully (see above).

## Roadmap (deliberately out of scope here)

- Multi-source fan-out (e.g. URLhaus, Censys, urlscan) behind the same verdict shape.
- Durable cache **persistence** (the in-process TTL cache above is in-memory only) and
  a formal evaluation suite.
