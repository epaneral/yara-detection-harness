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

Both return the **same normalized shape** — the answer, not VirusTotal's raw
500-field blob:

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

Both tools are **read-only** (GET lookups only — nothing is submitted, modified,
or deleted) and annotated accordingly.

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
the tools by hand, use the MCP Inspector:

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

The committed config uses the **Windows** venv path. On **macOS/Linux**, edit the
`command` in `.mcp.json` to the POSIX path:

| Platform | `.mcp.json` `command` |
|---|---|
| Windows | `enrichment-mcp/.venv/Scripts/python.exe` |
| macOS/Linux | `enrichment-mcp/.venv/bin/python` |

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

It connects, lists the two tools, and prints a verdict for the EICAR test hash
(dozens of engines `malicious`). Without a key it still connects and the tool
returns the actionable `VT_API_KEY is not set` message — proof the wiring works
either way.

## Error handling

Every failure mode returns a single actionable line, never a stack trace:

| Situation | Response |
|---|---|
| `VT_API_KEY` unset | `Error: VT_API_KEY is not set. Get a free key at ...` |
| Bad/invalid key (401) | `Error: VirusTotal rejected the API key (401). ...` |
| Rate limited (429) | `Error: VirusTotal rate limit hit (429). The free tier allows ~4/min ...` |
| Indicator unknown (404) | `Not found: '<indicator>' is not in VirusTotal's dataset ...` |
| Timeout / network error | `Error: request to VirusTotal timed out ...` / `network error ...` |

## Security notes

- **Key in env, never in code or git.** `.env` is gitignored; `.env.example` is a
  template only.
- **Read-only.** Only reputation *lookups*; no submission or mutation endpoints.
- **Rate-limited by design** on the free tier — handled gracefully (see above).

## Roadmap (deliberately out of scope here)

- Multi-source fan-out (e.g. URLhaus, Censys, urlscan) behind the same verdict shape.
- Auto-extracting indicators from a flagged corpus sample and chaining the lookup.
- Caching / persistence and a formal evaluation suite.
