"""Unit tests for the structured-feed adapter.

Scope: parsing the committed synthetic fixture into normalized Indicators
(source, source_ref, types, tags - including the tag-less row) and the four
malformed-feed error paths. Malformed inputs are written into tmp_path so the
committed fixture stays the single good example.
"""

from pathlib import Path

import pytest

from ingestion.adapters.feed import FeedAdapter

FIXTURE = Path(__file__).parent / "fixtures" / "feed.json"


def test_adapter_name():
    assert FeedAdapter().name == "feed"


def test_parse_fixture_returns_five_normalized_records():
    records = FeedAdapter().parse(str(FIXTURE))
    assert len(records) == 5
    assert all(r.source == "feed" for r in records)
    assert all(r.source_ref == str(FIXTURE) for r in records)


def test_parse_fixture_types_and_tags():
    by_key = {r.key: r for r in FeedAdapter().parse(str(FIXTURE))}
    assert by_key[("url", "http://192.0.2.10/gate.php")].tags == ("c2", "phishing-kit")
    assert by_key[("ip_address", "192.0.2.44")].tags == ("c2",)
    assert by_key[("domain", "malicious.example")].tags == ("phishing",)
    assert by_key[("file_hash", "d41d8cd98f00b204e9800998ecf8427e")].tags == ("dropper",)
    # the tag-less row parses with empty tags
    assert by_key[("ip_address", "203.0.113.7")].tags == ()


def _write(tmp_path, text):
    path = tmp_path / "bad_feed.json"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_non_json_raises(tmp_path):
    with pytest.raises(ValueError, match="not valid JSON"):
        FeedAdapter().parse(_write(tmp_path, "not json at all"))


def test_top_level_object_raises(tmp_path):
    with pytest.raises(ValueError, match="expected a JSON array"):
        FeedAdapter().parse(_write(tmp_path, '{"indicator": "x", "type": "domain"}'))


def test_row_missing_type_raises(tmp_path):
    with pytest.raises(ValueError, match="missing 'indicator' or 'type'"):
        FeedAdapter().parse(_write(tmp_path, '[{"indicator": "malicious.example"}]'))


def test_row_bad_type_raises(tmp_path):
    with pytest.raises(ValueError, match="row 0"):
        FeedAdapter().parse(
            _write(tmp_path, '[{"indicator": "malicious.example", "type": "ipv4"}]')
        )
