"""
Offline tests for the URLhaus reputation source.

These cover its response->verdict mapping (_urlhaus_verdict), its transport-error
mapping (_urlhaus_error), the query wiring (_urlhaus_query), the URLhausSource
adapter, and its participation in the lookup_indicator fan-out. Run with no API
key and the network stubbed (server._request_json / server._urlhaus_query /
server._vt_get), so nothing hits abuse.ch. Complements test_multisource.py.
"""

import asyncio
import json

import httpx
import pytest
import server

URLHAUS_HOST_OK = {
    "query_status": "ok",
    "urlhaus_reference": "https://urlhaus.abuse.ch/host/192.0.2.44/",
    "host": "192.0.2.44",
    "url_count": "7",
    "blacklists": {"surbl": "listed", "spamhaus_dbl": "not listed"},
    "urls": [{"url": "http://192.0.2.44/a", "url_status": "online", "threat": "malware_download"}],
}
URLHAUS_URL_OK = {
    "query_status": "ok",
    "id": "99",
    "urlhaus_reference": "https://urlhaus.abuse.ch/url/99/",
    "url": "http://192.0.2.44/a",
    "url_status": "online",
    "threat": "malware_download",
    "blacklists": {"surbl": "not listed", "spamhaus_dbl": "not listed"},
}


def _status_error(code):
    """Build an httpx.HTTPStatusError for a given status code (as a transport call would raise)."""
    request = httpx.Request("POST", "https://urlhaus-api.abuse.ch/v1/host/")
    response = httpx.Response(code, request=request)
    return httpx.HTTPStatusError(f"HTTP {code}", request=request, response=response)


# --- _urlhaus_verdict (pure) ------------------------------------------------
def test_urlhaus_verdict_host_ok():
    # An ok host payload: malicious = url_count, and flagged_by is urlhaus first then
    # only the *listed* external blacklist (the "not listed" one is dropped).
    out = json.loads(server._urlhaus_verdict("192.0.2.44", "ip_address", URLHAUS_HOST_OK))
    assert out["malicious"] == 7
    assert out["suspicious"] == 0
    assert out["flagged_by"] == ["urlhaus", "surbl"]
    assert out["permalink"] == "https://urlhaus.abuse.ch/host/192.0.2.44/"
    assert out["reputation"] is None
    assert out["type"] == "ip_address"


def test_urlhaus_verdict_url_ok():
    # An ok url payload: a listed URL counts as malicious=1, and with no external
    # blacklist listed, flagged_by is urlhaus alone.
    out = json.loads(server._urlhaus_verdict("http://192.0.2.44/a", "url", URLHAUS_URL_OK))
    assert out["malicious"] == 1
    assert out["flagged_by"] == ["urlhaus"]
    assert out["type"] == "url"


def test_urlhaus_verdict_no_results():
    # no_results is "no data" (a not-found), returned as a plain not-found line.
    out = server._urlhaus_verdict("192.0.2.99", "ip_address", {"query_status": "no_results"})
    assert out.startswith("Not found:")
    assert "192.0.2.99" in out


def test_urlhaus_verdict_invalid_status():
    # Any non-ok/non-no_results status (e.g. invalid_host) is an error line naming it.
    out = server._urlhaus_verdict("bad host", "ip_address", {"query_status": "invalid_host"})
    assert out.startswith("Error:")
    assert "invalid_host" in out


def test_urlhaus_verdict_host_url_count_fallback():
    # With a non-numeric url_count, a host ok payload falls back to len(urls).
    data = {
        "query_status": "ok",
        "url_count": "n/a",  # non-numeric -> int() raises -> len(urls) fallback
        "urls": [{"url": "http://192.0.2.44/a"}, {"url": "http://192.0.2.44/b"}],
    }
    out = json.loads(server._urlhaus_verdict("192.0.2.44", "ip_address", data))
    assert out["malicious"] == 2


def test_urlhaus_verdict_all_blacklists_clean():
    # If every external blacklist is "not listed", flagged_by is urlhaus alone.
    data = {
        "query_status": "ok",
        "url_count": "3",
        "blacklists": {"surbl": "not listed", "spamhaus_dbl": "not listed"},
    }
    out = json.loads(server._urlhaus_verdict("192.0.2.44", "ip_address", data))
    assert out["flagged_by"] == ["urlhaus"]


def test_urlhaus_verdict_shape_matches_vt():
    # Both sources must emit the SAME normalized verdict keys, or the fan-out envelope
    # drifts per source; this guards that shape contract.
    urlhaus = json.loads(server._urlhaus_verdict("192.0.2.44", "ip_address", URLHAUS_HOST_OK))
    vt = json.loads(
        server._normalize("i", "ip_address", "gid", {"last_analysis_stats": {"malicious": 1}})
    )
    assert set(urlhaus.keys()) == set(vt.keys())


# --- _urlhaus_error (pure) --------------------------------------------------
@pytest.mark.parametrize(
    ("code", "needle"),
    [
        (401, "rejected the API key"),
        (429, "rate limit"),
        (503, "HTTP 503"),
    ],
)
def test_urlhaus_error_http_status(code, needle):
    # Each HTTP status maps to its own actionable needle in a URLhaus-flavored line.
    out = server._urlhaus_error(_status_error(code), "IND")
    assert needle in out
    assert out.startswith("Error:")


def test_urlhaus_error_timeout_and_network():
    # Transport failures map to plain lines (no stack trace), each starting with Error:.
    timed_out = server._urlhaus_error(httpx.TimeoutException("t"), "IND")
    assert "timed out" in timed_out
    assert timed_out.startswith("Error:")

    network = server._urlhaus_error(httpx.ConnectError("x"), "IND")
    assert "network error" in network
    assert network.startswith("Error:")


# --- _urlhaus_query wiring (async, stub server._request_json) ---------------
def test_urlhaus_query_posts_to_host_endpoint(monkeypatch):
    # _urlhaus_query must POST to the host endpoint with an Auth-Key header, pass the
    # form data through, and use a source-prefixed cache key.
    captured = {}

    async def stub(method, url, *, headers, data=None, cache_key):
        captured.update(method=method, url=url, headers=headers, data=data, cache_key=cache_key)
        return {"query_status": "no_results"}

    monkeypatch.setattr(server, "_request_json", stub)

    asyncio.run(server._urlhaus_query("host", {"host": "192.0.2.44"}))

    assert captured["method"] == "POST"
    assert captured["url"].endswith("/host/")
    assert "Auth-Key" in captured["headers"]
    assert captured["data"] == {"host": "192.0.2.44"}
    assert captured["cache_key"].startswith("urlhaus:host:")


# --- URLhausSource ----------------------------------------------------------
def test_urlhaus_source_supports():
    # URLhaus answers network indicators (url/ip/domain) but not file hashes.
    src = server.URLhausSource()
    assert src.supports("url")
    assert src.supports("ip_address")
    assert src.supports("domain")
    assert not src.supports("file")


def test_urlhaus_source_configured(monkeypatch):
    # configured() tracks the presence of URLHAUS_API_KEY (unset by default via conftest).
    src = server.URLhausSource()
    assert src.configured() is False  # conftest clears the key
    monkeypatch.setattr(server, "URLHAUS_API_KEY", "uh-key")
    assert src.configured() is True


def test_urlhaus_source_lookup_routes_by_kind(monkeypatch):
    # lookup routes url -> url endpoint, and ip_address/domain -> host endpoint.
    monkeypatch.setattr(server, "URLHAUS_API_KEY", "uh-key")
    captured = {}

    async def stub(endpoint, data):
        captured["endpoint"] = endpoint
        return URLHAUS_URL_OK if endpoint == "url" else URLHAUS_HOST_OK

    monkeypatch.setattr(server, "_urlhaus_query", stub)

    asyncio.run(server.URLhausSource().lookup("url", "http://192.0.2.44/a"))
    assert captured["endpoint"] == "url"

    asyncio.run(server.URLhausSource().lookup("ip_address", "192.0.2.44"))
    assert captured["endpoint"] == "host"

    asyncio.run(server.URLhausSource().lookup("domain", "x.example"))
    assert captured["endpoint"] == "host"


# --- Fan-out with URLhaus in the mix (async; stub BOTH _vt_get and _urlhaus_query) ---
def _stub_urlhaus_query(payload):
    """An async _urlhaus_query replacement returning a fixed payload."""

    async def _inner(endpoint, data):
        return payload

    return _inner


def _raising_urlhaus_query(exc):
    """An async _urlhaus_query replacement that always raises `exc` (drives error mapping)."""

    async def _inner(endpoint, data):
        raise exc

    return _inner


def _stub_vt_get(payload):
    """An async _vt_get replacement returning a fixed payload."""

    async def _inner(path):
        return payload

    return _inner


def _envelope(coro):
    """Run the async lookup_indicator coroutine and parse its JSON envelope."""
    return json.loads(asyncio.run(coro))


def test_fanout_two_sources_malicious(monkeypatch):
    # Both sources live and both malicious: the envelope carries both, consensus is
    # malicious, sources_malicious is sorted, and max_malicious is the max (not a sum).
    monkeypatch.setattr(server, "VT_API_KEY", "vt-key")
    monkeypatch.setattr(server, "URLHAUS_API_KEY", "uh-key")
    monkeypatch.setattr(
        server,
        "_vt_get",
        _stub_vt_get(
            {"data": {"id": "192.0.2.44", "attributes": {"last_analysis_stats": {"malicious": 2}}}}
        ),
    )
    monkeypatch.setattr(server, "_urlhaus_query", _stub_urlhaus_query(URLHAUS_HOST_OK))

    out = _envelope(
        server.lookup_indicator(
            server.IndicatorLookupInput(indicator="192.0.2.44", type="ip_address")
        )
    )

    assert set(out["sources"]) == {"virustotal", "urlhaus"}
    assert out["consensus"]["malicious"] is True
    assert out["consensus"]["sources_malicious"] == ["urlhaus", "virustotal"]
    assert out["consensus"]["max_malicious"] == 7  # max(2, 7), never 2 + 7
    assert out["consensus"]["sources_skipped"] == []


def test_fanout_urlhaus_errors_does_not_sink_vt(monkeypatch):
    # A URLhaus 429 becomes its own error entry; VT still completes and still counts,
    # so one source's failure doesn't sink the other.
    monkeypatch.setattr(server, "VT_API_KEY", "vt-key")
    monkeypatch.setattr(server, "URLHAUS_API_KEY", "uh-key")
    monkeypatch.setattr(
        server,
        "_vt_get",
        _stub_vt_get(
            {"data": {"id": "192.0.2.44", "attributes": {"last_analysis_stats": {"malicious": 2}}}}
        ),
    )
    monkeypatch.setattr(server, "_urlhaus_query", _raising_urlhaus_query(_status_error(429)))

    out = _envelope(
        server.lookup_indicator(
            server.IndicatorLookupInput(indicator="192.0.2.44", type="ip_address")
        )
    )

    assert "error" in out["sources"]["urlhaus"]
    assert "429" in out["sources"]["urlhaus"]["error"]
    assert out["consensus"]["sources_errored"] == ["urlhaus"]
    assert out["consensus"]["sources_completed"] == ["virustotal"]
    assert out["consensus"]["malicious"] is True  # VT still counts


def test_fanout_urlhaus_only_when_no_vt_key(monkeypatch):
    # With only URLhaus configured, the server answers from URLhaus alone and reports
    # VT as skipped (not errored, never hit) -- proving it works without VT.
    monkeypatch.setattr(server, "URLHAUS_API_KEY", "uh-key")  # VT_API_KEY stays "" via conftest
    monkeypatch.setattr(server, "_urlhaus_query", _stub_urlhaus_query(URLHAUS_HOST_OK))

    out = _envelope(
        server.lookup_indicator(
            server.IndicatorLookupInput(indicator="192.0.2.44", type="ip_address")
        )
    )

    assert set(out["sources"]) == {"urlhaus"}
    assert out["consensus"]["sources_skipped"] == ["virustotal"]
    assert out["consensus"]["malicious"] is True
