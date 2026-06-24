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
