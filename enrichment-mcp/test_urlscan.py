"""
Offline tests for the urlscan.io reputation source.

These cover its search->result->verdict mapping (_urlscan_verdict), its transport-error
mapping (_urlscan_error), the search-query wiring (_urlscan_search), the UrlscanSource
adapter (search then fetch then map), and its participation in the lookup_indicator
fan-out. Run with no API key and the network stubbed (server._request_json /
server._urlscan_search / server._urlscan_result / server._vt_get / server._urlhaus_query),
so nothing hits urlscan.io. Complements test_urlhaus.py.
"""

import asyncio
import json

import httpx
import pytest
import server

URLSCAN_HIT = {"_id": "abc-123-uuid", "page": {"domain": "evil.example", "ip": "192.0.2.9"}}
URLSCAN_RESULT_MAL = {
    "verdicts": {"overall": {"malicious": True, "brands": [{"name": "Paypal"}, {"name": "Bank"}]}}
}
URLSCAN_RESULT_CLEAN = {"verdicts": {"overall": {"malicious": False, "brands": []}}}


def _status_error(code):
    """Build an httpx.HTTPStatusError for a status code (as a GET transport call would raise)."""
    request = httpx.Request("GET", "https://urlscan.io/api/v1/search/")
    response = httpx.Response(code, request=request)
    return httpx.HTTPStatusError(f"HTTP {code}", request=request, response=response)


# --- _urlscan_verdict (pure) ------------------------------------------------
def test_urlscan_verdict_malicious():
    # A malicious overall verdict: malicious=1, flagged_by is urlscan first then the
    # detected brands sorted, permalink is built from the hit's _id, reputation None.
    out = json.loads(
        server._urlscan_verdict("evil.example", "domain", URLSCAN_HIT, URLSCAN_RESULT_MAL)
    )
    assert out["malicious"] == 1
    assert out["flagged_by"] == ["urlscan", "Bank", "Paypal"]  # urlscan first, brands sorted
    assert out["permalink"] == "https://urlscan.io/result/abc-123-uuid/"
    assert out["reputation"] is None
    assert out["type"] == "domain"


def test_urlscan_verdict_clean():
    # A scanned-but-unflagged indicator is a clean verdict (malicious 0, no flaggers),
    # NOT a not-found -- the scan exists, urlscan just didn't call it bad.
    out = json.loads(
        server._urlscan_verdict("evil.example", "domain", URLSCAN_HIT, URLSCAN_RESULT_CLEAN)
    )
    assert out["malicious"] == 0
    assert out["flagged_by"] == []


def test_urlscan_verdict_missing_verdicts():
    # A result with no verdicts key degrades gracefully to a clean verdict.
    out = json.loads(server._urlscan_verdict("evil.example", "domain", URLSCAN_HIT, {}))
    assert out["malicious"] == 0
    assert out["flagged_by"] == []


def test_urlscan_verdict_shape_matches_vt():
    # Both sources must emit the SAME normalized verdict keys, or the fan-out envelope
    # drifts per source; this guards that shape contract.
    urlscan = json.loads(
        server._urlscan_verdict("evil.example", "domain", URLSCAN_HIT, URLSCAN_RESULT_MAL)
    )
    vt = json.loads(
        server._normalize("i", "domain", "gid", {"last_analysis_stats": {"malicious": 1}})
    )
    assert set(urlscan.keys()) == set(vt.keys())


# --- _urlscan_error (pure) --------------------------------------------------
@pytest.mark.parametrize(
    ("code", "needle"),
    [
        (401, "rejected the API key"),
        (429, "rate limit"),
        (503, "HTTP 503"),
    ],
)
def test_urlscan_error_http_status(code, needle):
    # Each HTTP status maps to its own actionable needle in a urlscan-flavored line.
    out = server._urlscan_error(_status_error(code), "IND")
    assert needle in out
    assert out.startswith("Error:")


def test_urlscan_error_timeout_and_network():
    # Transport failures map to plain lines (no stack trace), each starting with Error:.
    timed_out = server._urlscan_error(httpx.TimeoutException("t"), "IND")
    assert "timed out" in timed_out
    assert timed_out.startswith("Error:")

    network = server._urlscan_error(httpx.ConnectError("x"), "IND")
    assert "network error" in network
    assert network.startswith("Error:")


# --- _urlscan_search wiring (async, stub server._request_json) --------------
def test_urlscan_search_gets_search_endpoint(monkeypatch):
    # _urlscan_search must GET the search endpoint with an API-Key header, encode the
    # per-kind field into the query, use a source-prefixed cache key, and return the
    # first result.
    captured = {}

    async def stub(method, url, *, headers, data=None, cache_key):
        captured.update(method=method, url=url, headers=headers, data=data, cache_key=cache_key)
        return {"results": [URLSCAN_HIT], "total": 1}

    monkeypatch.setattr(server, "_request_json", stub)

    hit = asyncio.run(server._urlscan_search("domain", "evil.example"))

    assert hit == URLSCAN_HIT
    assert captured["method"] == "GET"
    assert "search" in captured["url"]
    assert "API-Key" in captured["headers"]
    assert captured["cache_key"] == "urlscan:search:domain:evil.example"


def test_urlscan_search_returns_none_when_empty(monkeypatch):
    # No results -> None (a not-found), so the source reports "no scans" not a verdict.
    async def stub(method, url, *, headers, data=None, cache_key):
        return {"results": [], "total": 0}

    monkeypatch.setattr(server, "_request_json", stub)

    assert asyncio.run(server._urlscan_search("domain", "evil.example")) is None


# --- UrlscanSource ----------------------------------------------------------
def test_urlscan_source_supports():
    # urlscan answers network indicators (url/ip/domain) but not file hashes.
    src = server.UrlscanSource()
    assert src.supports("url")
    assert src.supports("ip_address")
    assert src.supports("domain")
    assert not src.supports("file")


def test_urlscan_source_configured(monkeypatch):
    # configured() tracks the presence of URLSCAN_API_KEY (unset by default via conftest).
    src = server.UrlscanSource()
    assert src.configured() is False  # conftest clears the key
    monkeypatch.setattr(server, "URLSCAN_API_KEY", "us-key")
    assert src.configured() is True


def test_urlscan_source_lookup_returns_verdict(monkeypatch):
    # A search hit + malicious result maps to a verdict JSON with malicious=1.
    monkeypatch.setattr(server, "URLSCAN_API_KEY", "us-key")

    async def fake_search(kind, value):
        return URLSCAN_HIT

    async def fake_result(uuid):
        return URLSCAN_RESULT_MAL

    monkeypatch.setattr(server, "_urlscan_search", fake_search)
    monkeypatch.setattr(server, "_urlscan_result", fake_result)

    out = json.loads(asyncio.run(server.UrlscanSource().lookup("domain", "evil.example")))
    assert out["malicious"] == 1


def test_urlscan_source_lookup_not_found(monkeypatch):
    # No scans (search returns None) -> a plain not-found line naming the indicator.
    monkeypatch.setattr(server, "URLSCAN_API_KEY", "us-key")

    async def fake_search(kind, value):
        return None

    monkeypatch.setattr(server, "_urlscan_search", fake_search)

    out = asyncio.run(server.UrlscanSource().lookup("domain", "evil.example"))
    assert out.startswith("Not found:")
    assert "evil.example" in out


def test_urlscan_source_lookup_maps_error(monkeypatch):
    # A transport error during search is mapped to an actionable Error: line, not raised.
    monkeypatch.setattr(server, "URLSCAN_API_KEY", "us-key")

    async def fake_search(kind, value):
        raise _status_error(429)

    monkeypatch.setattr(server, "_urlscan_search", fake_search)

    out = asyncio.run(server.UrlscanSource().lookup("domain", "evil.example"))
    assert out.startswith("Error:")
    assert "429" in out


# --- Fan-out with urlscan in the mix ----------------------------------------
def _stub_vt_get(payload):
    """An async _vt_get replacement returning a fixed payload."""

    async def _inner(path):
        return payload

    return _inner


def _stub_urlhaus_query(payload):
    """An async _urlhaus_query replacement returning a fixed payload."""

    async def _inner(endpoint, data):
        return payload

    return _inner


def _stub_urlscan_search(hit):
    """An async _urlscan_search replacement returning a fixed hit (or None)."""

    async def _inner(kind, value):
        return hit

    return _inner


def _stub_urlscan_result(result):
    """An async _urlscan_result replacement returning a fixed result."""

    async def _inner(uuid):
        return result

    return _inner


def _envelope(coro):
    """Run the async lookup_indicator coroutine and parse its JSON envelope."""
    return json.loads(asyncio.run(coro))


def test_fanout_three_sources(monkeypatch):
    # All three sources live: VT clean, URLhaus no-data, urlscan malicious. The envelope
    # carries all three and the consensus is malicious with urlscan the only flagger.
    monkeypatch.setattr(server, "VT_API_KEY", "vt-key")
    monkeypatch.setattr(server, "URLHAUS_API_KEY", "uh-key")
    monkeypatch.setattr(server, "URLSCAN_API_KEY", "us-key")
    monkeypatch.setattr(
        server,
        "_vt_get",
        _stub_vt_get(
            {"data": {"id": "x", "attributes": {"last_analysis_stats": {"malicious": 0}}}}
        ),
    )
    monkeypatch.setattr(
        server, "_urlhaus_query", _stub_urlhaus_query({"query_status": "no_results"})
    )
    monkeypatch.setattr(server, "_urlscan_search", _stub_urlscan_search(URLSCAN_HIT))
    monkeypatch.setattr(server, "_urlscan_result", _stub_urlscan_result(URLSCAN_RESULT_MAL))

    out = _envelope(
        server.lookup_indicator(
            server.IndicatorLookupInput(indicator="evil.example", type="domain")
        )
    )

    assert set(out["sources"]) == {"virustotal", "urlhaus", "urlscan"}
    assert out["consensus"]["malicious"] is True
    assert out["consensus"]["sources_malicious"] == ["urlscan"]  # only urlscan flagged


def test_fanout_urlscan_only_when_only_its_key(monkeypatch):
    # With only urlscan configured, the server answers from urlscan alone and reports
    # VT and URLhaus as skipped (never hit) -- proving it works standalone.
    monkeypatch.setattr(server, "URLSCAN_API_KEY", "us-key")  # VT/URLhaus stay "" via conftest
    monkeypatch.setattr(server, "_urlscan_search", _stub_urlscan_search(URLSCAN_HIT))
    monkeypatch.setattr(server, "_urlscan_result", _stub_urlscan_result(URLSCAN_RESULT_MAL))

    out = _envelope(
        server.lookup_indicator(
            server.IndicatorLookupInput(indicator="evil.example", type="domain")
        )
    )

    assert set(out["sources"]) == {"urlscan"}
    skipped = out["consensus"]["sources_skipped"]
    assert {"virustotal", "urlhaus"}.issubset(set(skipped))
    assert out["consensus"]["malicious"] is True
