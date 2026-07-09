# yara-detection-harness

[![CI](https://github.com/epaneral/yara-detection-harness/actions/workflows/ci.yml/badge.svg)](https://github.com/epaneral/yara-detection-harness/actions/workflows/ci.yml)

A small, testable detection pipeline for **generated text and code**: hand-written
YARA rules, a labeled synthetic corpus, and a regression harness that gates the
build on recall and false-positive rate.

This is detection-as-code. Rules live in version control, every rule is exercised
against known-positive and known-benign samples on each run, and a rule cannot
"pass" merely by compiling — it has to catch what it should and stay quiet on the
things that look similar but aren't.

## Why this exists

Content-scanning at scale is a data-and-precision problem before it's a
threat-intelligence problem. The hard part isn't writing a rule that fires on a
reverse shell — it's writing one that fires on the reverse shell and *not* on the
backup script three lines away that happens to redirect with `>&`. This repo is
built around that problem: every benign sample is a deliberate **near-miss** for one
of the malicious samples, so the suite measures precision, not just coverage.

## Scope and threat model

- **In scope:** malicious *text and code* artifacts — phishing-kit markup, credential
  harvesters, shell/PowerShell droppers and stagers, exfiltration snippets. This
  mirrors content-scanning (the kind of artifact a generation system might be asked
  to produce), not PE/binary malware analysis.
- **Out of scope:** real malware binaries. The corpus is fully synthetic and lives
  in the repo, so there are no live samples on disk and the benign/malicious split
  is under full control.
- **Defanged by construction:** all network indicators use documentation-reserved
  IPs (`192.0.2.0/24`, RFC 5737) and obviously-fake tokens. Nothing here is runnable.

## Layout

```
rules/        YARA rules, grouped by family (powershell / shell / phishing)
corpus/
  malicious/  known-positive samples
  benign/     known-benign near-misses (each shadows a malicious sample)
tests/
  manifest.yml  ground-truth labels + expected matches (single source of truth)
  test_rules.py the harness
  test_rule_conventions.py  plyara-based rule-convention checks (house style)
enrichment-mcp/
  server.py           enrichment MCP server: VirusTotal + URLhaus + urlscan (separate component, own deps)
  multi-source-design.md  design note: multi-source fan-out + eval roadmap
  test_server.py      unit tests for its pure logic (validation, encoding, normalize)
  test_tools.py       offline tests driving the vt_lookup_* tools, network stubbed
  test_client.py      offline tests for the shared HTTP client + retry/backoff
  test_cache.py       offline tests for the in-process TTL lookup cache
  test_multisource.py offline tests for the adapter layer + lookup_indicator envelope
  test_urlhaus.py     offline tests for the URLhaus source + its fan-out participation
  test_urlscan.py     offline tests for the urlscan.io source (search -> result verdict)
  test_investigate_multisource.py  offline tests for investigate_sample's all_sources mode
  conftest.py         autouse fixtures: clear the cache, unset source keys per test
  eval_cases.py       labeled scenarios for the pipeline eval (corpus-derived)
  eval_harness.py     offline eval: extraction + verdict/shape metrics (report + gate)
  test_eval.py        CI gate asserting the eval metrics meet thresholds
  eval_live.py        opt-in live-key eval: loose invariants against the real APIs
  smoke_test.py       live stdio smoke test (works with or without a VT key)
  investigate_demo.py YARA flag -> investigate_sample chain, end to end
ingestion/    two-path IOC ingestion (separate CLI component, own deps)
  record.py           normalized IOC record + dedup key
  store.py            JSONL store: load / merge / write, dedup by (type, indicator)
  adapters/           source adapters (structured feed; scraped source in PR2)
  cli.py              python -m ingestion.cli --feed <path|url>
  fixtures/           synthetic defanged feeds;  test_*.py  offline tests
.mcp.json     project-scoped MCP config (Claude Code auto-discovers the server)
ruff.toml     lint + format configuration for the Python (harness + MCP server)
.github/workflows/ci.yml   per-component CI (lint / harness / enrichment-mcp / yaraqa / ingestion) on every push
```

## Corpus design

The corpus is paired. For each malicious sample there is a benign sample that shares
its surface features but not its intent:

| malicious | benign near-miss | what separates them |
|---|---|---|
| IEX + `DownloadString` cradle | admin script: `DownloadFile` to disk | execution primitive (IEX), not the download |
| `-enc` + hidden window | base64 *config* decode | the encoded-command + window-suppression combo |
| `bash -i >& /dev/tcp/...` | backup with `>&` / `2>&1` redirects | `/dev/tcp` socket use |
| `bash -i >& /dev/tcp/...` | `/dev/tcp` TCP port-check (no interactive shell) | the interactive shell (`bash -i`), not `/dev/tcp` alone |
| `bash -i >& /dev/tcp/...` | `/dev/tcp` port-check + `ssh -i <keyfile>` | fullword `sh -i` atom — `ssh -i` contains the substring but not the token |
| `curl http://<ip> \| bash` | rustup-style `curl https://host \| sh` | raw-IP-over-http source |
| `$_POST['password']` → `mail(attacker)` | same-origin login handler | the outbound exfil, not the capture |
| `$_REQUEST[ 'password' ]` → `mail(attacker)` | account-settings update, no outbound mail | the outbound exfil (capture regex tolerates spacing + superglobal swap) |
| `$_GET['password']` → `mail(attacker)` | gated-download passphrase check, no outbound mail | the outbound exfil, not the query-string capture |
| Telegram API carrying creds | Telegram API carrying deploy status | credential context |
| Telegram API carrying `login:`/`otp:` | Telegram API posting a "new login" sign-in alert | the credential-value shape (`login:`/`login=`/`login%20`…), not the bare word `login` |
| Telegram API carrying `token=`/`otp=` | Telegram API posting a token-rotation status | credential value-shape, not a benign `token =` assignment |

## The harness

`tests/test_rules.py` is driven entirely by `tests/manifest.yml` — add a sample and
its label there and it's automatically covered. Four gates:

1. **Compilation** — every `.yar` file compiles; a broken rule fails the build.
2. **Recall** — each malicious sample is caught by **exactly** its expected rule(s):
   no missed rule, no cross-fire from another family.
3. **False positives** — benign samples produce no matches, and the aggregate FP rate
   across the benign corpus must stay at or below `FP_THRESHOLD` (held at `0.0` here).
   The threshold is a single constant so the gate is explicit and tunable as the
   corpus grows and a zero-FP bar stops being realistic.
4. **Manifest/ruleset integrity** — the manifest and rules stay in sync: no orphan rule
   (defined but exercised by no sample), no `expected_rules` naming a non-existent rule,
   and every referenced sample path exists.

The `harness` job also runs a `plyara`-based **rule-convention** suite
(`tests/test_rule_conventions.py`) that parses each rule's source and enforces this repo's
house style: a complete `meta` block, well-formed MITRE `attack` technique IDs, a controlled
`severity` vocabulary, atom-anchored regex (no leading `.*`), and the two-primitive floor. It's
the house-style complement to the generic `yaraqa` gate, parametrized over every rule so a new
rule is covered automatically.

```bash
pip install -r requirements.txt
pytest -v
```

Alongside the detection gates, CI runs [`ruff`](https://docs.astral.sh/ruff/) over the
Python (harness + MCP server) as two further gates: a **format check** (`ruff format
--check`) and a **lint pass** (`ruff check`, covering pyflakes, bugbear, blind-except,
pyupgrade, async and pytest-style rules). Both are version-pinned so the result depends
only on the code, not on whichever `ruff` a runner happens to have.

```bash
ruff format --check .   # formatting gate
ruff check .            # lint gate
```

CI runs these as five independent jobs — `lint` (repo-wide ruff), `harness`
(the rules + corpus suite), `enrichment-mcp` (the MCP server's unit tests),
`yaraqa` (Florian Roth's [yaraQA](https://github.com/Neo23x0/yaraQA) rule-quality
analyzer), and `ingestion` (the IOC-ingestion component's offline tests) — each set
up with only the dependencies it needs. The `yaraqa` job runs
yaraQA over `rules/` with `--ignore-performance` (its regex-timing check is
non-deterministic across runners) and fails on any new non-performance level-≥2 issue
not in the reviewed baseline `tests/yaraqa-baseline.json`; the deterministic structural
conventions are covered by the plyara suite instead. The MCP server keeps
its own dependency set, so its tests install and run separately:

```bash
pip install -r enrichment-mcp/requirements-dev.txt
pytest enrichment-mcp -v
```

The same reproducibility logic extends past the direct pins to the whole tree. CI
installs from fully-resolved lock files — `requirements.lock` for the harness,
`enrichment-mcp/requirements-dev.lock` for the MCP server, and `requirements-yaraqa.lock`
for the yaraQA gate — that pin *and hash* every transitive dependency, not just the direct
ones the `requirements.txt` files declare. The locks are compiled with [`uv`](https://docs.astral.sh/uv/)
(`uv pip compile <src> -o <lock> --universal --generate-hashes`); the header of each
lock records the exact command to regenerate it. uv over `pip-compile` here because it
is one fast static binary, `--universal` resolves a single lock valid on both the Linux
CI runner and Windows/macOS dev machines, and the output is plain hashed requirements
that vanilla `pip` installs — no extra tool in CI. The hashes put pip in
`--require-hashes` mode, so an install fails closed rather than drifting to an altered
or newly-floated dependency. The `requirements.txt` files stay the hand-edited direct-pin
sources; recompile the matching lock whenever you change one.

yaraQA is cloned rather than pip-installed (it is not on PyPI); the local run mirrors
the `yaraqa` CI gate:

```bash
git clone https://github.com/Neo23x0/yaraQA
pip install -r requirements-yaraqa.txt
python yaraQA/yaraQA.py -d rules/ --ignore-performance -b tests/yaraqa-baseline.json -l 2
```

## Rule design notes

Rules are written with YARA's matching engine in mind, not just correctness:

- **Atoms over wildcards.** Conditions anchor on concrete strings (`/dev/tcp/`,
  `api.telegram.org/bot`, `http://` before the IP regex) so the scanner gets a fast
  first-pass match rather than being forced into full evaluation. No leading-`.*`
  regex, no mostly-wildcard patterns.
- **Combination over presence.** Almost every rule requires *two* primitives co-occur
  (capture **and** exfil, encode **and** hide, fetch **and** pipe-to-shell). Single-
  feature rules are where false positives come from; the near-miss corpus exists to
  catch exactly that failure.
- **Precision over recall — accepted false negatives.** The flip side of the rule above:
  each rule is scoped to one technique in a specific combination, so a variant that shows
  only one primitive, or uses a different mechanism, is *deliberately* not caught — recall
  is traded to hold precision against the near-miss twin. The sharpest accepted gaps: a
  pipe-to-shell from a **named host** (only a raw-IP source fires — the named-host case is
  sacrificed to keep the `rustup`-style installer quiet), a `/dev/tcp` reverse shell that
  never spawns an interactive `bash -i`/`sh -i`, an encoded PowerShell launcher with **no**
  window suppression, and a PHP harvester that exfiltrates through any channel other than
  `mail()`. These are design choices, not oversights; each rule's `meta`/comments name its
  lever, and closing a gap means adding the matching malicious **and** benign corpus pair,
  not loosening the live rule. In a mature detection portfolio these gaps aren't holes:
  recall is a property of the whole stack, not one rule, so each would be backstopped at
  another layer (EDR process-lineage, network/egress telemetry) and shadowed by a companion
  **low-precision, higher-FP "hunt"-tier rule** routed to a triage queue rather than an
  auto-alert or block — recovering recall without loosening the precise rule. This repo has a
  single static-content layer and one hard `0.0` FP gate, so that tiering isn't wired up; the
  note above is instead its **risk-acceptance record** — the gaps are logged deliberately,
  not left implicit.
- **Precision lever stated in each rule.** Each rule's `meta` and inline comments name
  the one feature that keeps it off its benign twin.
- **Value-shaped keys shrink the FP surface, but don't zero it.** Ambiguous credential
  keywords (`login`, `token`, `pin`, `secret`, …) match only in an exfil *value-shape* —
  the key directly followed by `:`/`=`, `"key":`, or a URL-encoded delimiter (`%20`/`%3a`/
  `%3d`) — never as a bare word. That keeps them off benign identifiers: a bot's own
  `TELEGRAM_BOT_TOKEN`, a `const token = …` assignment (the no-space rule is what excludes
  it), a "new login from …" alert, or substrings like `className`/`shopping`. The residual
  it does *not* cover: a benign object literal such as `{token: x}` (property key, no space)
  still matches the `token:` shape. Nothing in the corpus trips it, but real-world code can —
  `token` is the most ambiguous keyword in the set. The escape hatch, if it ever bites, is to
  restrict `token` to `=` and URL-encoded delimiters only, trading away `"token":"…"`
  JSON-exfil coverage for it.
- **Comments are content.** YARA scans raw bytes with no notion of language syntax, so a
  rule's atoms match inside a sample's *comments* just like in code. This is deliberate:
  for generated-content scanning, a payload string in a comment is still a payload someone
  can copy-paste, and the workarounds (per-language line-guard regexes, comment-stripping
  preprocessing) trade a known FP class for silent false negatives. The accepted cost is
  that documentation quoting attack strings will flag; if that class ever matters, it gets
  modeled as a benign near-miss pair in the corpus, not a comment-blind rule. Corollary for
  corpus authoring: sample header comments must describe their near-miss without quoting
  the rule's atoms — the FP gate enforces this.

## Roadmap (not built yet — phase 2)

Deliberately out of the current scope to keep it shippable:

- Two-path ingestion: one scraped static source + one structured feed.
- A retro-hunt job running new rules over the stored corpus.

## What this is not

- Not production detection content — synthetic corpus, no real-world FP base rate.
- Not trained on or tested against live malware.
- Rule coverage is illustrative (a handful of families), chosen to demonstrate the
  testing discipline rather than to be exhaustive.

---

*Author: Elyse Paneral · 2026*
