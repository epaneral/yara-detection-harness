"""Unit tests for the ingestion CLI end-to-end (parse feed -> merge -> write).

Scope: the happy path against the committed fixture, idempotency of a repeated
run, and the known-error exit code. The store is always written into tmp_path -
the real store is never touched.
"""

from pathlib import Path

import pytest

from ingestion.cli import main

FIXTURE = Path(__file__).parent / "fixtures" / "feed.json"
SCRAPE_FIXTURE = Path(__file__).parent / "fixtures" / "scrape.html"


def _store_lines(path):
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_run_writes_five_line_store(tmp_path, capsys):
    store_path = tmp_path / "store" / "indicators.jsonl"
    rc = main(["--feed", str(FIXTURE), "--store", str(store_path)])
    assert rc == 0
    assert len(_store_lines(store_path)) == 5
    out = capsys.readouterr().out
    assert "5 new" in out
    assert "5 total" in out


def test_second_identical_run_is_idempotent(tmp_path):
    store_path = tmp_path / "indicators.jsonl"
    assert main(["--feed", str(FIXTURE), "--store", str(store_path)]) == 0
    assert main(["--feed", str(FIXTURE), "--store", str(store_path)]) == 0
    assert len(_store_lines(store_path)) == 5


def test_malformed_feed_returns_one(tmp_path):
    bad_feed = tmp_path / "bad_feed.json"
    bad_feed.write_text("not json at all", encoding="utf-8")
    store_path = tmp_path / "indicators.jsonl"
    assert main(["--feed", str(bad_feed), "--store", str(store_path)]) == 1


def test_scrape_writes_eight_line_store(tmp_path):
    store_path = tmp_path / "indicators.jsonl"
    rc = main(["--scrape", str(SCRAPE_FIXTURE), "--store", str(store_path)])
    assert rc == 0
    assert len(_store_lines(store_path)) == 8


def test_feed_and_scrape_merge_deduped_union(tmp_path):
    store_path = tmp_path / "indicators.jsonl"
    assert main(["--feed", str(FIXTURE), "--store", str(store_path)]) == 0
    assert main(["--scrape", str(SCRAPE_FIXTURE), "--store", str(store_path)]) == 0
    # feed's 5 + scrape's 8, minus the shared IP 192.0.2.44 = 12.
    assert len(_store_lines(store_path)) == 12


def test_no_source_returns_argparse_error(tmp_path):
    store_path = tmp_path / "indicators.jsonl"
    with pytest.raises(SystemExit, match="2"):
        main(["--store", str(store_path)])
