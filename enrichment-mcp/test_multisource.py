"""
Offline tests for the multi-source adapter layer.

These cover the input model (IndicatorLookupInput), the consensus math
(_build_consensus), source partitioning (_sources_for / VirusTotalSource), and
the lookup_indicator envelope end-to-end with the network (_vt_get) stubbed and
no API key required. They complement test_tools.py, which covers the single-source
vt_lookup_* tool path.
"""

import asyncio
import json

import httpx
import pytest
import server

GOOD_HASH = "d41d8cd98f00b204e9800998ecf8427e"


def _stub_vt_get(captured, payload):
    """An async _vt_get replacement that records the path and returns payload."""

    async def _inner(path):
        captured["path"] = path
        return payload

    return _inner


def _status_error(code):
    """Build an httpx.HTTPStatusError for a given status code (as _vt_get would raise)."""
    request = httpx.Request("GET", "https://www.virustotal.com/api/v3/x")
    response = httpx.Response(code, request=request)
    return httpx.HTTPStatusError(f"HTTP {code}", request=request, response=response)


def _raising_vt_get(exc):
    """An async _vt_get replacement that always raises `exc` (drives error mapping)."""

    async def _inner(path):
        raise exc

    return _inner


def _envelope(coro):
    """Run the async lookup_indicator coroutine and parse its JSON envelope."""
    return json.loads(asyncio.run(coro))


# --- IndicatorLookupInput ---------------------------------------------------
def test_indicator_input_accepts_each_kind():
    # One valid value per kind must construct and expose the declared type, so the
    # single entry point covers all four indicator kinds the vt_lookup_* tools do.
    cases = {
        "file": GOOD_HASH,
        "url": "http://192.0.2.10/x",
        "ip_address": "192.0.2.44",
        "domain": "api.telegram.org",
    }
    for kind, value in cases.items():
        model = server.IndicatorLookupInput(indicator=value, type=kind)
        assert model.type == kind  # the declared kind survives validation


def test_indicator_input_normalizes_via_typed_model():
    # A padded, upper-case hash comes back stripped and lowercased, proving the
    # model reuses HashLookupInput's normalization rather than passing input through raw.
    model = server.IndicatorLookupInput(
        indicator="  D41D8CD98F00B204E9800998ECF8427E  ", type="file"
    )
    assert model.indicator == GOOD_HASH


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        ("not-an-ip", "ip_address"),
        ("nodot", "domain"),
        ("ftp://x/y", "url"),  # wrong scheme
        ("xyz", "file"),  # not a hash
    ],
)
def test_indicator_input_rejects_value_type_mismatch(value, kind):
    # A value that doesn't match its declared type must fail validation, so a
    # mislabeled indicator never reaches the network as the wrong kind.
    with pytest.raises(server.ValidationError):
        server.IndicatorLookupInput(indicator=value, type=kind)


def test_indicator_input_rejects_unknown_type():
    # type is a Literal, so an unrecognized kind is rejected up front rather than
    # dispatched to a nonexistent lookup.
    with pytest.raises(server.ValidationError):
        server.IndicatorLookupInput(indicator=GOOD_HASH, type="banana")


def test_indicator_input_forbids_extra_fields():
    # extra="forbid" keeps a typo'd/unknown kwarg from being silently ignored.
    with pytest.raises(server.ValidationError):
        server.IndicatorLookupInput(indicator=GOOD_HASH, type="file", extra="nope")


# --- _classify_source_result (pure) -----------------------------------------
def test_classify_verdict_json():
    # A parseable JSON string is a verdict and is returned as the parsed dict.
    assert server._classify_source_result('{"malicious": 2}') == {"malicious": 2}


def test_classify_not_found():
    # A "Not found:" line is a completed-but-empty answer, kept under a not_found key.
    raw = "Not found: 'x' is not in VirusTotal's dataset."
    assert server._classify_source_result(raw) == {"not_found": raw}


def test_classify_error():
    # Any other non-JSON line is an error, kept under an error key (not a verdict).
    raw = "Error: something"
    assert server._classify_source_result(raw) == {"error": raw}


# --- _build_consensus (pure) ------------------------------------------------
def test_consensus_malicious_and_clean():
    # One malicious source flips the malicious flag and rosters only that source,
    # while both sources count as completed; suspicious stays False with no sus hits.
    sources = {
        "virustotal": {"malicious": 3, "suspicious": 0},
        "other": {"malicious": 0, "suspicious": 0},
    }
    c = server._build_consensus(sources, [])
    assert c["malicious"] is True
    assert c["sources_malicious"] == ["virustotal"]
    assert c["max_malicious"] == 3
    assert c["sources_completed"] == ["other", "virustotal"]  # sorted, both answered
    assert c["suspicious"] is False


def test_consensus_suspicious_only_does_not_flip_malicious():
    # A suspicious-only hit sets suspicious but must NOT imply malicious, so a
    # low-confidence signal isn't overstated.
    sources = {"virustotal": {"malicious": 0, "suspicious": 2}}
    c = server._build_consensus(sources, [])
    assert c["suspicious"] is True
    assert c["malicious"] is False
    assert c["sources_suspicious"] == ["virustotal"]
    assert c["sources_malicious"] == []


def test_consensus_error_and_notfound():
    # An errored source is excluded from completed and rostered under errored, while
    # a not_found still counts as completed; skipped names pass through untouched.
    sources = {"a": {"error": "boom"}, "b": {"not_found": "Not found: ..."}}
    c = server._build_consensus(sources, ["c"])
    assert c["sources_errored"] == ["a"]
    assert c["sources_completed"] == ["b"]  # not_found counts as completed
    assert c["sources_skipped"] == ["c"]
    assert c["malicious"] is False
    assert c["max_malicious"] == 0


def test_consensus_max_is_max_not_sum():
    # max_malicious is a severity hint (the single largest count), never a sum, so
    # incomparable per-source counts aren't merged into a misleading total.
    sources = {"a": {"malicious": 2}, "b": {"malicious": 5}}
    c = server._build_consensus(sources, [])
    assert c["max_malicious"] == 5  # max(2, 5), not 2 + 5
    assert c["sources_malicious"] == ["a", "b"]


# --- _sources_for / VirusTotalSource ----------------------------------------
def test_sources_for_configured(monkeypatch):
    # With a key present, VirusTotal is active (not skipped) for a supported kind.
    monkeypatch.setattr(server, "VT_API_KEY", "test-key-not-real")
    active, skipped = server._sources_for("ip_address")
    assert "virustotal" in [s.name for s in active]
    assert skipped == []


def test_sources_for_unconfigured_skips(monkeypatch):
    # Without a key, VirusTotal is skipped (not active), so the fan-out reports it
    # as skipped rather than erroring or hitting the network.
    monkeypatch.setattr(server, "VT_API_KEY", "")
    active, skipped = server._sources_for("ip_address")
    assert active == []
    assert skipped == ["virustotal"]


# --- lookup_indicator (async, stub server._vt_get) --------------------------
def test_lookup_indicator_envelope_malicious(monkeypatch):
    # A malicious IP flows through the fan-out into a well-formed envelope: the
    # per-source verdict is preserved and the consensus reflects it.
    monkeypatch.setattr(server, "VT_API_KEY", "test-key-not-real")
    payload = {
        "data": {
            "id": "192.0.2.44",
            "attributes": {"last_analysis_stats": {"malicious": 4}},
        }
    }
    monkeypatch.setattr(server, "_vt_get", _stub_vt_get({}, payload))

    out = _envelope(
        server.lookup_indicator(
            server.IndicatorLookupInput(indicator="192.0.2.44", type="ip_address")
        )
    )

    assert out["type"] == "ip_address"
    assert "virustotal" in out["sources"]
    assert out["sources"]["virustotal"]["malicious"] == 4  # verdict preserved under the source
    assert out["consensus"]["malicious"] is True
    assert out["consensus"]["sources_malicious"] == ["virustotal"]


def test_lookup_indicator_no_key_returns_actionable_line(monkeypatch):
    # No configured source -> a single actionable line, not a JSON envelope, so the
    # caller gets a fix-it message instead of an empty consensus.
    monkeypatch.setattr(server, "VT_API_KEY", "")
    out = asyncio.run(
        server.lookup_indicator(
            server.IndicatorLookupInput(indicator="192.0.2.44", type="ip_address")
        )
    )
    assert "VT_API_KEY is not set" in out
    assert not out.startswith("{")  # not a JSON envelope


def test_lookup_indicator_maps_404_to_not_found_entry(monkeypatch):
    # A 404 is "no reputation data", not a failure: the source completes with a
    # not_found entry, so consensus is clean and nothing lands in errored.
    monkeypatch.setattr(server, "VT_API_KEY", "test-key-not-real")
    monkeypatch.setattr(server, "_vt_get", _raising_vt_get(_status_error(404)))

    out = _envelope(
        server.lookup_indicator(
            server.IndicatorLookupInput(indicator="192.0.2.44", type="ip_address")
        )
    )

    assert "not_found" in out["sources"]["virustotal"]
    assert out["consensus"]["malicious"] is False
    assert out["consensus"]["sources_completed"] == ["virustotal"]  # not_found still completed
    assert out["consensus"]["sources_errored"] == []


def test_lookup_indicator_maps_429_to_error_entry(monkeypatch):
    # A 429 is a genuine failure: the source is rostered as errored (not completed),
    # its entry carries the error text, and it doesn't flip the malicious flag.
    monkeypatch.setattr(server, "VT_API_KEY", "test-key-not-real")
    monkeypatch.setattr(server, "_vt_get", _raising_vt_get(_status_error(429)))

    out = _envelope(
        server.lookup_indicator(
            server.IndicatorLookupInput(indicator="192.0.2.44", type="ip_address")
        )
    )

    assert "error" in out["sources"]["virustotal"]
    assert "429" in out["sources"]["virustotal"]["error"]
    assert out["consensus"]["sources_errored"] == ["virustotal"]
    assert out["consensus"]["malicious"] is False
    assert out["consensus"]["sources_completed"] == []  # an error is not a completion


def test_lookup_indicator_lowercases_hash_in_path(monkeypatch):
    # The upper-case hash must reach VT as the normalized lowercase path, proving the
    # input model's normalization flows all the way through the fan-out to _vt_get.
    monkeypatch.setattr(server, "VT_API_KEY", "test-key-not-real")
    captured = {}
    payload = {"data": {"id": "FID", "attributes": {"last_analysis_stats": {"malicious": 0}}}}
    monkeypatch.setattr(server, "_vt_get", _stub_vt_get(captured, payload))

    _envelope(
        server.lookup_indicator(
            server.IndicatorLookupInput(indicator="D41D8CD98F00B204E9800998ECF8427E", type="file")
        )
    )

    assert captured["path"] == f"files/{GOOD_HASH}"  # normalized lowercase reached the network
