"""
Offline tests for the AbuseIPDB IP-reputation source.

These cover its score->verdict thresholds (_abuseipdb_verdict), its transport-error
mapping (_abuseipdb_error), the check-endpoint wiring (_abuseipdb_check), the
AbuseIPDBSource adapter (IP-only support, configured, lookup), and its participation in
the lookup_indicator fan-out. Run with no API key and the network stubbed
(server._request_json / server._abuseipdb_check / server._vt_get), so nothing hits
AbuseIPDB. Complements test_urlscan.py.
"""

import asyncio
import json

import httpx
import pytest
import server


def _abuse_data(score):
    """An AbuseIPDB /check response body carrying the given abuseConfidenceScore."""
    return {
        "data": {"ipAddress": "192.0.2.5", "abuseConfidenceScore": score, "totalReports": score}
    }


def _status_error(code):
    """Build an httpx.HTTPStatusError for a status code (as a GET transport call would raise)."""
    request = httpx.Request("GET", "https://api.abuseipdb.com/api/v2/check")
    response = httpx.Response(code, request=request)
    return httpx.HTTPStatusError(f"HTTP {code}", request=request, response=response)


# --- _abuseipdb_verdict (pure) ----------------------------------------------
def test_verdict_malicious_high_score():
    # A score at/over the malicious threshold: malicious=1, suspicious=0, the raw score
    # carried through as reputation, abuseipdb the only flagger, IP-typed permalink.
    out = json.loads(server._abuseipdb_verdict("192.0.2.5", _abuse_data(100)))
    assert out["malicious"] == 1
    assert out["suspicious"] == 0
    assert out["reputation"] == 100
    assert out["flagged_by"] == ["abuseipdb"]
    assert out["type"] == "ip_address"
    assert out["permalink"] == "https://www.abuseipdb.com/check/192.0.2.5"


def test_verdict_suspicious_mid_score():
    # A mid-band score is suspicious (not malicious), still flagged by abuseipdb.
    out = json.loads(server._abuseipdb_verdict("192.0.2.5", _abuse_data(50)))
    assert out["suspicious"] == 1
    assert out["malicious"] == 0
    assert out["flagged_by"] == ["abuseipdb"]
    assert out["reputation"] == 50


def test_verdict_clean_low_score():
    # A low score is clean: neither malicious nor suspicious, and no flagger.
    out = json.loads(server._abuseipdb_verdict("192.0.2.5", _abuse_data(10)))
    assert out["malicious"] == 0
    assert out["suspicious"] == 0
    assert out["flagged_by"] == []
    assert out["reputation"] == 10


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (75, (1, 0)),  # at the malicious threshold -> malicious
        (74, (0, 1)),  # just below -> suspicious
        (25, (0, 1)),  # at the suspicious threshold -> suspicious
        (24, (0, 0)),  # just below -> clean
    ],
)
def test_verdict_thresholds_boundaries(score, expected):
    # The exact threshold boundaries between malicious/suspicious/clean.
    out = json.loads(server._abuseipdb_verdict("192.0.2.5", _abuse_data(score)))
    assert (out["malicious"], out["suspicious"]) == expected


def test_verdict_missing_score_is_clean():
    # A body with no score (or no data) defaults to score 0 -> clean, never a crash.
    out = json.loads(server._abuseipdb_verdict("192.0.2.5", {}))
    assert out["malicious"] == 0
    assert out["suspicious"] == 0
    assert out["reputation"] == 0


def test_verdict_shape_matches_vt():
    # Both sources must emit the SAME normalized verdict keys, or the fan-out envelope
    # drifts per source; this guards that shape contract.
    abuse = json.loads(server._abuseipdb_verdict("192.0.2.5", _abuse_data(100)))
    vt = json.loads(
        server._normalize("i", "ip_address", "gid", {"last_analysis_stats": {"malicious": 1}})
    )
    assert set(abuse.keys()) == set(vt.keys())


# --- _abuseipdb_error (pure) ------------------------------------------------
@pytest.mark.parametrize(
    ("code", "needle"),
    [
        (401, "rejected the API key"),
        (429, "rate limit"),
        (422, "invalid IP"),
        (500, "HTTP 500"),
    ],
)
def test_error_http_status(code, needle):
    # Each HTTP status maps to its own actionable needle in an AbuseIPDB-flavored line.
    out = server._abuseipdb_error(_status_error(code), "IND")
    assert needle in out
    assert out.startswith("Error:")


def test_error_timeout_and_network():
    # Transport failures map to plain lines (no stack trace), each starting with Error:.
    timed_out = server._abuseipdb_error(httpx.TimeoutException("t"), "IND")
    assert "timed out" in timed_out
    assert timed_out.startswith("Error:")

    network = server._abuseipdb_error(httpx.ConnectError("x"), "IND")
    assert "network error" in network
    assert network.startswith("Error:")


# --- _abuseipdb_check wiring (async, stub server._request_json) -------------
def test_check_gets_check_endpoint(monkeypatch):
    # _abuseipdb_check must GET the check endpoint with a Key header, encode the IP and
    # maxAgeInDays into the query, and use a source-prefixed cache key.
    captured = {}

    async def stub(method, url, *, headers, data=None, cache_key):
        captured.update(method=method, url=url, headers=headers, data=data, cache_key=cache_key)
        return _abuse_data(0)

    monkeypatch.setattr(server, "_request_json", stub)

    asyncio.run(server._abuseipdb_check("192.0.2.5"))

    assert captured["method"] == "GET"
    assert "/check" in captured["url"]
    assert "ipAddress=192.0.2.5" in captured["url"]
    assert "maxAgeInDays" in captured["url"]
    assert "Key" in captured["headers"]
    assert captured["cache_key"] == "abuseipdb:check:192.0.2.5"


# --- AbuseIPDBSource --------------------------------------------------------
def test_source_supports_ip_only():
    # AbuseIPDB answers IPs only -- not urls, domains, or file hashes.
    src = server.AbuseIPDBSource()
    assert src.supports("ip_address")
    assert not src.supports("url")
    assert not src.supports("domain")
    assert not src.supports("file")


def test_source_configured(monkeypatch):
    # configured() tracks the presence of ABUSEIPDB_API_KEY (unset by default via conftest).
    src = server.AbuseIPDBSource()
    assert src.configured() is False  # conftest clears the key
    monkeypatch.setattr(server, "ABUSEIPDB_API_KEY", "ab-key")
    assert src.configured() is True


def test_source_lookup_returns_verdict(monkeypatch):
    # A high-score check maps to a verdict JSON with malicious=1.
    monkeypatch.setattr(server, "ABUSEIPDB_API_KEY", "ab-key")

    async def fake_check(ip):
        return _abuse_data(90)

    monkeypatch.setattr(server, "_abuseipdb_check", fake_check)

    out = json.loads(asyncio.run(server.AbuseIPDBSource().lookup("ip_address", "192.0.2.5")))
    assert out["malicious"] == 1


def test_source_lookup_maps_error(monkeypatch):
    # A transport error during the check is mapped to an actionable Error: line, not raised.
    monkeypatch.setattr(server, "ABUSEIPDB_API_KEY", "ab-key")

    async def fake_check(ip):
        raise _status_error(429)

    monkeypatch.setattr(server, "_abuseipdb_check", fake_check)

    out = asyncio.run(server.AbuseIPDBSource().lookup("ip_address", "192.0.2.5"))
    assert out.startswith("Error:")
    assert "429" in out


# --- Fan-out with abuseipdb in the mix --------------------------------------
def _stub_vt_get(payload):
    """An async _vt_get replacement returning a fixed payload."""

    async def _inner(path):
        return payload

    return _inner


def _stub_abuseipdb_check(payload):
    """An async _abuseipdb_check replacement returning a fixed payload."""

    async def _inner(ip):
        return payload

    return _inner


def _envelope(coro):
    """Run the async lookup_indicator coroutine and parse its JSON envelope."""
    return json.loads(asyncio.run(coro))


def test_fanout_ip_includes_abuseipdb(monkeypatch):
    # For an IP, abuseipdb joins the fan-out: VT clean, abuseipdb malicious. The envelope
    # carries abuseipdb and the consensus is malicious with abuseipdb the only flagger.
    monkeypatch.setattr(server, "VT_API_KEY", "vt-key")
    monkeypatch.setattr(server, "ABUSEIPDB_API_KEY", "ab-key")
    monkeypatch.setattr(
        server,
        "_vt_get",
        _stub_vt_get(
            {"data": {"id": "x", "attributes": {"last_analysis_stats": {"malicious": 0}}}}
        ),
    )
    monkeypatch.setattr(server, "_abuseipdb_check", _stub_abuseipdb_check(_abuse_data(90)))

    out = _envelope(
        server.lookup_indicator(
            server.IndicatorLookupInput(indicator="192.0.2.5", type="ip_address")
        )
    )

    assert "abuseipdb" in out["sources"]
    assert out["consensus"]["malicious"] is True
    assert out["consensus"]["sources_malicious"] == ["abuseipdb"]  # only abuseipdb flagged


def test_fanout_domain_excludes_abuseipdb(monkeypatch):
    # abuseipdb supports IPs only: for a domain it is neither queried (not in sources) nor
    # skipped (skipped means supports-but-unconfigured), so it must be absent from both.
    monkeypatch.setattr(server, "VT_API_KEY", "vt-key")
    monkeypatch.setattr(server, "ABUSEIPDB_API_KEY", "ab-key")
    monkeypatch.setattr(
        server,
        "_vt_get",
        _stub_vt_get(
            {"data": {"id": "x", "attributes": {"last_analysis_stats": {"malicious": 0}}}}
        ),
    )

    out = _envelope(
        server.lookup_indicator(server.IndicatorLookupInput(indicator="x.example", type="domain"))
    )

    assert "abuseipdb" not in out["sources"]
    assert "abuseipdb" not in out["consensus"]["sources_skipped"]


def test_fanout_abuseipdb_only_when_only_its_key(monkeypatch):
    # With only abuseipdb configured, the server answers from abuseipdb alone and reports
    # the other IP-capable sources as skipped -- proving it works standalone.
    monkeypatch.setattr(server, "ABUSEIPDB_API_KEY", "ab-key")  # others stay "" via conftest
    monkeypatch.setattr(server, "_abuseipdb_check", _stub_abuseipdb_check(_abuse_data(90)))

    out = _envelope(
        server.lookup_indicator(
            server.IndicatorLookupInput(indicator="192.0.2.5", type="ip_address")
        )
    )

    assert set(out["sources"]) == {"abuseipdb"}
    skipped = out["consensus"]["sources_skipped"]
    assert {"virustotal", "urlhaus", "urlscan"}.issubset(set(skipped))
    assert out["consensus"]["malicious"] is True
