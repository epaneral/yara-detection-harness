"""Tests for the retro-hunt tool (retrohunt.py).

The pure annotation/summary functions are locked with hand-built dicts (no yara,
no I/O). Integration tests run the real committed ruleset over the real corpus as a
sanity mirror of the harness, and the CLI paths are exercised end to end via main().
"""

import json

import retrohunt
import yara
from ruleset import compile_ruleset, load_manifest

# --- Pure: coverage_rows ----------------------------------------------------


def test_coverage_rows_statuses():
    samples = [
        {"path": "corpus/malicious/a", "label": "malicious", "expected_rules": ["R"]},
        {"path": "corpus/malicious/b", "label": "malicious", "expected_rules": []},
        {"path": "corpus/benign/c", "label": "benign", "expected_rules": []},
    ]
    scan = {
        "corpus/malicious/a": ["R"],
        "corpus/malicious/b": ["R"],
        "corpus/benign/c": ["R"],
    }
    rows = retrohunt.coverage_rows(scan, samples)
    status_by_sample = {r["sample"]: r["status"] for r in rows}
    assert status_by_sample["corpus/malicious/a"] == "expected"
    assert status_by_sample["corpus/malicious/b"] == "UNEXPECTED"
    assert status_by_sample["corpus/benign/c"] == "BENIGN_FP"


def test_coverage_rows_empty_fired_list_yields_no_rows():
    samples = [
        {"path": "corpus/malicious/a", "label": "malicious", "expected_rules": ["R"]},
    ]
    scan = {"corpus/malicious/a": []}
    assert retrohunt.coverage_rows(scan, samples) == []


# --- Pure: preview_summary --------------------------------------------------


def test_preview_summary_partitions_and_sorts():
    samples = [
        {"path": "corpus/malicious/z", "label": "malicious", "expected_rules": []},
        {"path": "corpus/malicious/a", "label": "malicious", "expected_rules": []},
        {"path": "corpus/benign/b", "label": "benign", "expected_rules": []},
    ]
    scan = {
        "corpus/malicious/a": ["R"],  # matched malicious -> hit
        "corpus/benign/b": ["R"],  # matched benign -> FP
        # corpus/malicious/z absent -> missed
    }
    summary = retrohunt.preview_summary(scan, samples)
    assert summary["malicious_hits"] == ["corpus/malicious/a"]
    assert summary["malicious_missed"] == ["corpus/malicious/z"]
    assert summary["benign_fps"] == ["corpus/benign/b"]
    assert summary["malicious_hits"] == sorted(summary["malicious_hits"])
    assert summary["malicious_missed"] == sorted(summary["malicious_missed"])
    assert summary["benign_fps"] == sorted(summary["benign_fps"])


# --- Integration: committed ruleset agrees with the manifest ----------------


def test_committed_ruleset_matches_manifest():
    rules = compile_ruleset()
    samples = load_manifest()
    rows = retrohunt.coverage_rows(retrohunt.scan_corpus(rules, samples), samples)
    assert not any(r["status"] == "UNEXPECTED" for r in rows)
    assert not any(r["status"] == "BENIGN_FP" for r in rows)
    assert any(r["status"] == "expected" for r in rows)


# --- Draft preview: an over-broad rule that hits both columns ---------------

DRAFT_RULE = 'rule Draft { strings: $a = "api.telegram.org" condition: $a }'


def test_draft_preview_flags_benign_fp(tmp_path, capsys):
    draft = tmp_path / "draft.yar"
    draft.write_text(DRAFT_RULE, encoding="utf-8")
    rc = retrohunt.main(["--rule", str(draft)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "malicious matched" in out
    assert "benign matched (FP)" in out

    samples = load_manifest()
    summary = retrohunt.preview_summary(
        retrohunt.scan_corpus(yara.compile(source=DRAFT_RULE), samples), samples
    )
    assert summary["benign_fps"]
    assert summary["malicious_hits"]


# --- CLI paths --------------------------------------------------------------


def test_main_coverage_map(capsys):
    rc = retrohunt.main([])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Coverage map" in out or "summary:" in out


def test_main_coverage_json(capsys):
    rc = retrohunt.main(["--json"])
    out = capsys.readouterr().out
    assert rc == 0
    payload = json.loads(out)
    assert payload["mode"] == "coverage"
    assert isinstance(payload["rows"], list)


def test_main_missing_rule_file_returns_1(tmp_path, capsys):
    rc = retrohunt.main(["--rule", str(tmp_path / "missing.yar")])
    captured = capsys.readouterr()
    assert rc == 1
    assert captured.err
