# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A testable detection pipeline for generated text/code (not binary malware): hand-written
YARA rules, a synthetic labeled corpus, and a regression harness gating the build on recall
and false-positive rate. The corpus is fully synthetic and defanged (RFC 5737 IPs, fake tokens).

## Commands

Three independent Python components with separate deps. `pytest.ini` scopes `testpaths` to
`tests/`, so a bare `pytest` runs only the harness — MCP and ingestion tests are invoked by path.

```bash
pip install -r requirements.txt && pytest -v        # YARA harness
ruff format --check . && ruff check .               # format + lint gates (pinned ruff==0.15.18 in CI)
pip install -r enrichment-mcp/requirements-dev.txt && pytest enrichment-mcp -v   # MCP server
pip install -r ingestion/requirements-dev.txt && pytest ingestion -v   # IOC ingestion
# yaraQA rule-quality gate — mirrors the `yaraqa` CI job (yaraQA is cloned, not on PyPI)
git clone https://github.com/Neo23x0/yaraQA
pip install -r requirements-yaraqa.txt
python yaraQA/yaraQA.py -d rules/ --ignore-performance -b tests/yaraqa-baseline.json -l 2
```

The `requirements.txt` files are the hand-edited direct-pin sources (fine for local
installs). CI instead installs from fully-resolved, hashed lock files — `requirements.lock`,
`enrichment-mcp/requirements-dev.lock`, and `requirements-yaraqa.lock` — so transitive deps
don't float. Regenerate the matching lock after editing a pin (command is in each lock's
header): `uv pip compile <src> -o <lock> --universal --generate-hashes`.

CI = `lint` + `harness` + `enrichment-mcp` + `yaraqa` + `ingestion` jobs, plus an `all-green`
aggregate that branch protection requires; a skipped needed job fails it on purpose.

## Architecture

- **Manifest-driven harness.** `tests/manifest.yml` (label + `expected_rules` per sample) is
  the single source of truth; `tests/test_rules.py` parametrizes over it — add a sample to the
  manifest and it's covered automatically. Four gates: compilation, recall, FP rate
  (`<= FP_THRESHOLD`, a constant currently `0.0` — any benign match fails CI), and
  manifest/ruleset integrity (no orphan rule, no unknown rule name in `expected_rules`,
  no missing sample path).
- **Paired corpus.** Every `corpus/malicious/*` sample has a `corpus/benign/*` near-miss that
  shares its surface features but not its intent. The benign column measures precision — add a
  benign shadow whenever you add a malicious sample. Sample comments are scanned content too
  (YARA is syntax-blind) — never quote a rule's literal atoms in a sample's comments; describe
  the near-miss without spelling the atoms out. The FP gate catches violations.
- **Rule conventions** (`rules/`, grouped by family): require two primitives to co-occur
  (single-feature rules cause FPs); anchor on concrete string atoms, not leading-`.*` regex;
  each rule's `meta`/comments name the one feature keeping it off its benign twin — keep that
  comment accurate when editing. Each rule's `meta` also carries an `attack` field listing the
  MITRE ATT&CK technique ID(s) it detects (comma-separated) — add it when writing a new rule.
  The `yaraqa` CI job gates rule quality: it runs yaraQA with `--ignore-performance` (whose
  regex-timing check is non-deterministic across runners) and fails on any new non-performance
  level-≥2 issue not in the reviewed baseline `tests/yaraqa-baseline.json` (currently empty).
  Beyond that generic gate, a `plyara`-based convention suite (`tests/test_rule_conventions.py`,
  in the `harness` pytest job) parses each rule's source and enforces the house style — a complete
  `meta` block, well-formed MITRE `attack` IDs, a controlled `severity` vocabulary, atom-anchored
  regex (no leading `.*`), and the `>=2`-string (two-primitive) floor — parametrized over every rule.
- **enrichment-mcp/** — self-contained VirusTotal MCP server (`server.py`, stdio, read-only
  reputation lookups (hash/URL/IP/domain) plus extract/investigate tools, normalized verdict
  shape). Separate deps; not run by the bare `pytest`. `VT_API_KEY`
  from env; failures return one actionable line, never a stack trace.
