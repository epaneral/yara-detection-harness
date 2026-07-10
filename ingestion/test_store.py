"""Unit tests for the JSONL indicator store: load, merge (dedup by key), write.

Scope: the store's dedup/idempotency behavior and its stable, sorted on-disk
form. All I/O goes to pytest's tmp_path - the real store is never touched.
"""

import json

from ingestion import store
from ingestion.record import Indicator


def test_load_missing_path_is_empty(tmp_path):
    assert store.load(tmp_path / "does-not-exist.jsonl") == {}


def test_merge_adds_and_counts_new_keys():
    records = [
        Indicator("192.0.2.44", "ip_address", "feed", tags=("c2",)),
        Indicator("malicious.example", "domain", "feed", tags=("phishing",)),
    ]
    merged, added = store.merge({}, records)
    assert added == 2
    assert set(merged) == {("ip_address", "192.0.2.44"), ("domain", "malicious.example")}


def test_remerge_same_records_is_idempotent():
    records = [Indicator("192.0.2.44", "ip_address", "feed", tags=("c2",))]
    first, added_first = store.merge({}, records)
    assert added_first == 1
    _, added_again = store.merge(first, records)
    assert added_again == 0


def test_collision_unions_tags_without_new_key():
    existing, _ = store.merge({}, [Indicator("192.0.2.44", "ip_address", "feedA", tags=("c2",))])
    merged, added = store.merge(
        existing, [Indicator("192.0.2.44", "ip_address", "feedB", tags=("botnet",))]
    )
    assert added == 0
    record = merged[("ip_address", "192.0.2.44")]
    assert record.tags == ("c2", "botnet")
    assert record.source == "feedA"  # first-source-wins survives the merge


def test_write_load_round_trips(tmp_path):
    records = [
        Indicator("http://192.0.2.10/gate.php", "url", "feed", "feed.json", ("c2",)),
        Indicator("malicious.example", "domain", "feed", "feed.json", ("phishing",)),
    ]
    original, _ = store.merge({}, records)
    path = tmp_path / "store" / "indicators.jsonl"
    store.write(path, original)
    assert store.load(path) == original
    # The atomic-rename write must not leave its temp file behind.
    assert [p.name for p in path.parent.iterdir()] == [path.name]


def test_write_output_is_sorted_by_key(tmp_path):
    records = [
        Indicator("malicious.example", "domain", "feed"),
        Indicator("203.0.113.7", "ip_address", "feed"),
        Indicator("192.0.2.44", "ip_address", "feed"),
        Indicator("http://192.0.2.10/gate.php", "url", "feed"),
    ]
    built, _ = store.merge({}, records)
    path = tmp_path / "indicators.jsonl"
    store.write(path, built)
    lines = path.read_text(encoding="utf-8").splitlines()
    written_keys = [(json.loads(line)["type"], json.loads(line)["indicator"]) for line in lines]
    assert written_keys == sorted(built)
