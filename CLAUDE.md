# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A testable detection pipeline for generated text/code (not binary malware): hand-written
YARA rules, a synthetic labeled corpus, and a regression harness gating the build on recall
and false-positive rate. The corpus is fully synthetic and defanged (RFC 5737 IPs, fake tokens).

## Commands

Two independent Python components with separate deps. `pytest.ini` scopes `testpaths` to
`tests/`, so a bare `pytest` runs only the harness — MCP tests must be invoked by path.

```bash
pip install -r requirements.txt && pytest -v        # YARA harness
ruff format --check . && ruff check .               # format + lint gates (pinned ruff==0.15.18 in CI)
pip install -r enrichment-mcp/requirements-dev.txt && pytest enrichment-mcp -v   # MCP server
```

CI = `lint` + `harness` + `enrichment-mcp` jobs, plus an `all-green` aggregate that branch
protection requires; a skipped needed job fails it on purpose.

## Architecture

- **Manifest-driven harness.** `tests/manifest.yml` (label + `expected_rules` per sample) is
  the single source of truth; `tests/test_rules.py` parametrizes over it — add a sample to the
  manifest and it's covered automatically. Three gates: compilation, recall, and FP rate
  (`<= FP_THRESHOLD`, a constant currently `0.0` — any benign match fails CI).
- **Paired corpus.** Every `corpus/malicious/*` sample has a `corpus/benign/*` near-miss that
  shares its surface features but not its intent. The benign column measures precision — add a
  benign shadow whenever you add a malicious sample.
- **Rule conventions** (`rules/`, grouped by family): require two primitives to co-occur
  (single-feature rules cause FPs); anchor on concrete string atoms, not leading-`.*` regex;
  each rule's `meta`/comments name the one feature keeping it off its benign twin — keep that
  comment accurate when editing. Each rule's `meta` also carries an `attack` field listing the
  MITRE ATT&CK technique ID(s) it detects (comma-separated) — add it when writing a new rule.
- **enrichment-mcp/** — self-contained VirusTotal MCP server (`server.py`, stdio, read-only
  reputation lookups (hash/URL/IP/domain) plus extract/investigate tools, normalized verdict
  shape). Separate deps; not run by the bare `pytest`. `VT_API_KEY`
  from env; failures return one actionable line, never a stack trace.
