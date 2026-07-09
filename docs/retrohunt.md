# Retro-hunt (design note)

Status: **shipping** (single PR). Reference for the retro-hunt tool
(roadmap "A retro-hunt job running new rules over the stored corpus").

## Goal

Run a *candidate* rule over the stored corpus to preview its footprint before it is
wired into the manifest, and print a coverage map of the committed ruleset. Discovery,
not gating — the manifest harness (`tests/test_rules.py`) already gates the committed
ruleset (cross-fire, FP, orphan rules); retro-hunt is its observability/authoring
counterpart.

## What it does

`tests/retrohunt.py`, a CLI:

- **Draft-rule preview** — `--rule draft.yar`: compile a candidate rule (not yet in
  `rules/` or the manifest), scan it over all of `corpus/`, and report what it would
  catch — malicious samples matched (coverage), benign matched (flagged as **FPs**), and
  malicious missed. The literal "run new rules over the stored corpus" workflow.
- **Coverage map** (default): compile the committed ruleset, scan the corpus, and print a
  per-`(sample, rule)` map annotated against the manifest — `expected` / `UNEXPECTED`
  cross-fire / `BENIGN_FP` — which also surfaces any drift.
- `--json` for machine-readable output. Always exits 0 on findings (informational); only
  a crash fails it.

## Design

- **Pure core, thin shell.** The annotate/summarize logic is pure functions over dicts
  (scan result + manifest samples), unit-tested with synthetic inputs. The yara scan is a
  thin wrapper integration-tested against the real corpus.
- **Shared harness primitives.** Compilation, manifest loading, and corpus scanning move
  to a small `tests/ruleset.py` that both the pytest harness (`test_rules.py`) and
  retrohunt import — one source of truth for compile + scan.
- **No new deps.** Reuses yara-python + pyyaml already in the harness.

## How it runs

- On-demand CLI, documented in the harness README.
- A **non-blocking** step in the existing `harness` CI job (after pytest) prints the
  coverage map on every push — informational, never fails the build.

## Non-goals

Not a new gate (the harness already gates cross-fire / FP / orphans); no corpus changes;
no network. Its own tests (`tests/test_retrohunt.py`) run in the harness job.

## Not this: the IOC store

Retro-hunt scans text *rules* over the text *corpus*. The ingestion IOC store is a
different axis (indicators, not rule matches) and is unrelated.
