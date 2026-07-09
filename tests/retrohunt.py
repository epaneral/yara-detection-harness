"""Retro-hunt: preview a candidate rule (or map the whole ruleset) over the corpus.

The manifest harness (test_rules.py) *gates* the committed ruleset against its declared
expectations. Retro-hunt is the discovery counterpart: run a NEW/draft rule over the
stored corpus to preview its footprint before wiring it into the manifest, or print a
coverage map of the committed ruleset annotated against the manifest. Informational --
it reports, it does not gate (always exits 0 on findings; only a crash or bad input fails).

    python tests/retrohunt.py                    # coverage map of the committed ruleset
    python tests/retrohunt.py --rule draft.yar   # preview a candidate rule
    python tests/retrohunt.py --json             # machine-readable

Reuses the harness primitives in ruleset.py (compile, manifest, scan) -- no new deps.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yara
from ruleset import compile_ruleset, load_manifest, matches_for

# --- Pure core: annotate/summarize a scan result against the manifest --------


def _expected_index(samples: list[dict]) -> dict[str, tuple[str, set]]:
    """{path: (label, {expected rule names})} from the manifest samples."""
    return {s["path"]: (s["label"], set(s.get("expected_rules") or [])) for s in samples}


def coverage_rows(scan: dict[str, list[str]], samples: list[dict]) -> list[dict]:
    """One row per (sample, fired rule), annotated against the manifest.

    status: 'expected' (a malicious sample declares the rule), 'UNEXPECTED' (a malicious
    sample does not), or 'BENIGN_FP' (fired on a benign sample). Pure -- no yara, no I/O.
    """
    idx = _expected_index(samples)
    rows = []
    for path in sorted(scan):
        label, expected = idx.get(path, ("unknown", set()))
        for rule in scan[path]:
            if label == "benign":
                status = "BENIGN_FP"
            elif rule in expected:
                status = "expected"
            else:
                status = "UNEXPECTED"
            rows.append({"sample": path, "rule": rule, "label": label, "status": status})
    return rows


def preview_summary(scan: dict[str, list[str]], samples: list[dict]) -> dict:
    """Footprint of a candidate ruleset over the corpus: hits, FPs, misses. Pure."""
    idx = _expected_index(samples)
    hits, fps, missed = [], [], []
    for path in sorted(idx):
        label, _ = idx[path]
        matched = bool(scan.get(path))
        if label == "malicious":
            (hits if matched else missed).append(path)
        elif label == "benign" and matched:
            fps.append(path)
    return {"malicious_hits": hits, "benign_fps": fps, "malicious_missed": missed}


# --- Thin scan shell (touches yara + the corpus) ----------------------------


def scan_corpus(rules: yara.Rules, samples: list[dict]) -> dict[str, list[str]]:
    """{sample path: [rule names that fired]} over every manifest sample."""
    return {s["path"]: matches_for(rules, s["path"]) for s in samples}


# --- Text reports -----------------------------------------------------------


def coverage_text(rows: list[dict]) -> str:
    lines = ["Coverage map (committed ruleset over corpus):", ""]
    for r in rows or [{"sample": "(no matches)", "rule": "", "status": ""}]:
        suffix = f"  ::  {r['rule']}  [{r['status']}]" if r["rule"] else ""
        lines.append(f"  {r['sample']}{suffix}")
    unexpected = sum(1 for r in rows if r["status"] == "UNEXPECTED")
    fps = sum(1 for r in rows if r["status"] == "BENIGN_FP")
    lines += ["", f"summary: {len(rows)} match(es), {unexpected} unexpected, {fps} benign FP"]
    return "\n".join(lines)


def preview_text(summary: dict, rule_names: list[str]) -> str:
    lines = [f"Retro-hunt preview of {', '.join(rule_names)} over corpus:", ""]
    for label, key, mark in (
        ("malicious matched ", "malicious_hits", "+"),
        ("benign matched (FP)", "benign_fps", "!"),
        ("malicious missed  ", "malicious_missed", "-"),
    ):
        paths = summary[key]
        lines.append(f"  {label}: {len(paths)}")
        lines.extend(f"    {mark} {p}" for p in paths)
    return "\n".join(lines)


# --- CLI --------------------------------------------------------------------


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Preview a candidate rule, or map the committed ruleset, over the corpus."
    )
    parser.add_argument("--rule", help="candidate .yar to preview (default: the committed ruleset)")
    parser.add_argument("--json", action="store_true", help="machine-readable JSON output")
    args = parser.parse_args(argv)

    samples = load_manifest()

    if args.rule:
        try:
            # utf-8-sig strips a leading BOM (common from Windows editors) that yara's
            # compiler would otherwise reject as a non-ascii character.
            source = Path(args.rule).read_text(encoding="utf-8-sig")
            rules = yara.compile(source=source)
        except (yara.Error, OSError) as e:
            print(f"error: could not compile {args.rule}: {e}", file=sys.stderr)
            return 1
        rule_names = sorted(r.identifier for r in rules)
        summary = preview_summary(scan_corpus(rules, samples), samples)
        if args.json:
            print(
                json.dumps({"mode": "preview", "rules": rule_names, "summary": summary}, indent=2)
            )
        else:
            print(preview_text(summary, rule_names))
    else:
        rows = coverage_rows(scan_corpus(compile_ruleset(), samples), samples)
        if args.json:
            print(json.dumps({"mode": "coverage", "rows": rows}, indent=2))
        else:
            print(coverage_text(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
