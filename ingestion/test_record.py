"""Unit tests for the normalized Indicator record.

Scope: the pure record logic - construction/validation, the dedup key, the
same-key merge (order-preserving tag union, first-source-wins), and the
dict round-trip. No I/O.
"""

import pytest

from ingestion.record import INDICATOR_TYPES, Indicator


def test_valid_indicator():
    ind = Indicator("192.0.2.44", "ip_address", "feed", "feed.json", ("c2",))
    assert ind.indicator == "192.0.2.44"
    assert ind.type == "ip_address"
    assert ind.source == "feed"
    assert ind.source_ref == "feed.json"
    assert ind.tags == ("c2",)


def test_defaults_source_ref_and_tags():
    ind = Indicator("malicious.example", "domain", "feed")
    assert ind.source_ref == ""
    assert ind.tags == ()


@pytest.mark.parametrize("bad_type", ["", "ipv4", "hash", "URL", "unknown"])
def test_bad_type_raises(bad_type):
    with pytest.raises(ValueError, match="unknown indicator type"):
        Indicator("192.0.2.44", bad_type, "feed")


def test_every_known_type_is_accepted():
    for t in INDICATOR_TYPES:
        assert Indicator("x", t, "feed").type == t


@pytest.mark.parametrize("blank", ["", "   ", "\t", "\n"])
def test_blank_indicator_raises(blank):
    with pytest.raises(ValueError, match="non-empty"):
        Indicator(blank, "domain", "feed")


def test_key():
    ind = Indicator("malicious.example", "domain", "feed")
    assert ind.key == ("domain", "malicious.example")


def test_merged_with_unions_tags_and_keeps_first_source():
    first = Indicator("192.0.2.44", "ip_address", "feedA", "a.json", ("c2", "botnet"))
    second = Indicator("192.0.2.44", "ip_address", "feedB", "b.json", ("botnet", "phishing"))
    merged = first.merged_with(second)
    # order-preserving union, no duplicate "botnet"
    assert merged.tags == ("c2", "botnet", "phishing")
    # first-source-wins provenance policy
    assert merged.source == "feedA"
    assert merged.source_ref == "a.json"
    assert merged.key == first.key


def test_to_dict_from_dict_round_trip():
    ind = Indicator(
        "http://192.0.2.10/gate.php", "url", "feed", "feed.json", ("c2", "phishing-kit")
    )
    d = ind.to_dict()
    assert d == {
        "indicator": "http://192.0.2.10/gate.php",
        "type": "url",
        "source": "feed",
        "source_ref": "feed.json",
        "tags": ["c2", "phishing-kit"],
    }
    assert Indicator.from_dict(d) == ind


@pytest.mark.parametrize("missing", ["indicator", "type"])
def test_from_dict_missing_required_field_raises(missing):
    d = {"indicator": "malicious.example", "type": "domain"}
    del d[missing]
    with pytest.raises(ValueError, match="missing required field"):
        Indicator.from_dict(d)
