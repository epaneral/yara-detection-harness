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
enrichment-mcp/
  server.py           VirusTotal enrichment MCP server (separate component, own deps)
  test_server.py      unit tests for its pure logic (validation, encoding, normalize)
  test_tools.py       offline tests driving the vt_lookup_* tools, network stubbed
  smoke_test.py       live stdio smoke test (works with or without a VT key)
  investigate_demo.py YARA flag -> investigate_sample chain, end to end
.mcp.json     project-scoped MCP config (Claude Code auto-discovers the server)
ruff.toml     lint + format configuration for the Python (harness + MCP server)
.github/workflows/ci.yml   per-component CI (lint / harness / enrichment-mcp) on every push
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

## The harness

`tests/test_rules.py` is driven entirely by `tests/manifest.yml` — add a sample and
its label there and it's automatically covered. Four gates:

1. **Compilation** — every `.yar` file compiles; a broken rule fails the build.
2. **Recall** — each malicious sample is caught by its expected rule(s).
3. **False positives** — benign samples produce no matches, and the aggregate FP rate
   across the benign corpus must stay at or below `FP_THRESHOLD` (held at `0.0` here).
   The threshold is a single constant so the gate is explicit and tunable as the
   corpus grows and a zero-FP bar stops being realistic.
4. **Manifest/ruleset integrity** — the manifest and rules stay in sync: no orphan rule
   (defined but exercised by no sample), no `expected_rules` naming a non-existent rule,
   and every referenced sample path exists.

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

CI runs these as three independent jobs — `lint` (repo-wide ruff), `harness`
(the rules + corpus suite), and `enrichment-mcp` (the MCP server's unit tests) —
each set up with only the dependencies it needs. The MCP server keeps its own
dependency set, so its tests install and run separately:

```bash
pip install -r enrichment-mcp/requirements-dev.txt
pytest enrichment-mcp -v
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
- **Precision lever stated in each rule.** Each rule's `meta` and inline comments name
  the one feature that keeps it off its benign twin.
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

- `yaraQA` (Florian Roth) wired in as a performance/quality **gate**, not just a runner.
- Custom `plyara`-based checks beyond yaraQA.
- Two-path ingestion: one scraped static source + one structured feed.
- A retro-hunt job running new rules over the stored corpus.
- A fully-resolved dependency lock (`uv lock` / `pip-compile`): direct deps are
  `==`-pinned to CI-green versions, but their transitive dependencies still float.

## What this is not

- Not production detection content — synthetic corpus, no real-world FP base rate.
- Not trained on or tested against live malware.
- Rule coverage is illustrative (a handful of families), chosen to demonstrate the
  testing discipline rather than to be exhaustive.

---

*Author: Elyse Paneral · 2026*
