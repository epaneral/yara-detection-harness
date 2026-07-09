"""
Offline tests for investigate_sample's all_sources fan-out mode.

These drive investigate_sample with all_sources=True, where each indicator goes
through the multi-source fan-out (VirusTotal + URLhaus) instead of VT-only. Both
network paths are stubbed (server._vt_get and server._urlhaus_query), so they run
deterministically with no keys and no internet. They complement test_tools.py,
which covers the default VT-only mode.
"""

import asyncio
import json

import httpx
import server


def _stub_vt(payload):
    """An async _vt_get replacement returning a fixed payload (path ignored)."""

    async def _inner(path):
        return payload

    return _inner


def _stub_urlhaus(payload):
    """An async _urlhaus_query replacement returning a fixed payload."""

    async def _inner(endpoint, data):
        return payload

    return _inner


def _raise_urlhaus(exc):
    """An async _urlhaus_query replacement that raises exc (transport failure)."""

    async def _inner(endpoint, data):
        raise exc

    return _inner


def _raise_vt(exc):
    """An async _vt_get replacement that raises exc (transport failure)."""

    async def _inner(path):
        raise exc

    return _inner


def _status_error(code):
    """A URLhaus-flavored (POST) HTTPStatusError for the given status code."""
    request = httpx.Request("POST", "https://urlhaus-api.abuse.ch/v1/host/")
    return httpx.HTTPStatusError(
        f"HTTP {code}", request=request, response=httpx.Response(code, request=request)
    )


def _vt_status_error(code):
    """A VirusTotal-flavored (GET) HTTPStatusError for the given status code."""
    request = httpx.Request("GET", "https://www.virustotal.com/api/v3/x")
    return httpx.HTTPStatusError(
        f"HTTP {code}", request=request, response=httpx.Response(code, request=request)
    )


def _report(coro):
    """Run investigate_sample and parse its JSON report."""
    return json.loads(asyncio.run(coro))


# Reusable source payloads.
VT_MAL = {"data": {"id": "x", "attributes": {"last_analysis_stats": {"malicious": 3}}}}
VT_CLEAN = {"data": {"id": "x", "attributes": {"last_analysis_stats": {"malicious": 0}}}}
UH_OK = {"query_status": "ok", "url_count": "5", "urlhaus_reference": "ref", "blacklists": {}}
UH_NONE = {"query_status": "no_results"}

ONE_URL = "grab http://192.0.2.7/a now"  # -> one url indicator
THREE_URLS = "a http://192.0.2.1/x b http://192.0.2.2/y c http://192.0.2.3/z"  # -> three urls


def test_default_mode_is_vt_only_and_unchanged(monkeypatch):
    # all_sources omitted (default False): VT-only rows, no fan-out.
    monkeypatch.setattr(server, "VT_API_KEY", "test-key-not-real")
    monkeypatch.setattr(server, "_vt_get", _stub_vt(VT_MAL))

    out = _report(server.investigate_sample(server.InvestigateInput(text=ONE_URL)))

    row = out["results"][0]
    assert "verdict" in row  # VT-only row shape
    assert "sources" not in row  # no fan-out keys
    assert "consensus" not in row
    assert out["summary"]["malicious"] == 1
    assert "on VirusTotal" in out["note"]


def test_all_sources_row_has_sources_and_consensus(monkeypatch):
    # all_sources=True: each row carries per-source verdicts + consensus, not a verdict.
    monkeypatch.setattr(server, "VT_API_KEY", "test-key-not-real")
    monkeypatch.setattr(server, "URLHAUS_API_KEY", "uh-key-not-real")
    monkeypatch.setattr(server, "_vt_get", _stub_vt(VT_MAL))
    monkeypatch.setattr(server, "_urlhaus_query", _stub_urlhaus(UH_OK))

    out = _report(
        server.investigate_sample(server.InvestigateInput(text=ONE_URL, all_sources=True))
    )

    row = out["results"][0]
    assert "sources" in row  # fan-out row shape
    assert "consensus" in row
    assert "verdict" not in row
    assert set(row["sources"]) == {"virustotal", "urlhaus"}  # both configured sources ran
    assert out["summary"]["malicious"] == 1
    assert "across all configured sources" in out["note"]


def test_all_sources_tally_malicious_from_consensus(monkeypatch):
    # One source (URLhaus) flags malicious, VT clean -> consensus malicious -> tally malicious.
    monkeypatch.setattr(server, "VT_API_KEY", "test-key-not-real")
    monkeypatch.setattr(server, "URLHAUS_API_KEY", "uh-key-not-real")
    monkeypatch.setattr(server, "_vt_get", _stub_vt(VT_CLEAN))
    monkeypatch.setattr(server, "_urlhaus_query", _stub_urlhaus(UH_OK))

    out = _report(
        server.investigate_sample(server.InvestigateInput(text=ONE_URL, all_sources=True))
    )

    assert out["summary"]["malicious"] == 1  # any source flagging drives the tally
    assert out["results"][0]["consensus"]["sources_malicious"] == ["urlhaus"]


def test_all_sources_error_isolation(monkeypatch):
    # URLhaus errors (429) but VT still flags malicious: the row is malicious, not an error.
    monkeypatch.setattr(server, "VT_API_KEY", "test-key-not-real")
    monkeypatch.setattr(server, "URLHAUS_API_KEY", "uh-key-not-real")
    monkeypatch.setattr(server, "_vt_get", _stub_vt(VT_MAL))
    monkeypatch.setattr(server, "_urlhaus_query", _raise_urlhaus(_status_error(429)))

    out = _report(
        server.investigate_sample(server.InvestigateInput(text=ONE_URL, all_sources=True))
    )

    consensus = out["results"][0]["consensus"]
    assert consensus["sources_errored"] == ["urlhaus"]  # the failing source is isolated
    assert consensus["sources_completed"] == ["virustotal"]  # VT still answered
    assert out["summary"]["malicious"] == 1  # VT's verdict still counts
    assert out["summary"]["errors"] == 0  # malicious row is not an error row


def test_all_sources_all_not_found_tallies_not_found(monkeypatch):
    # Both sources report no data (VT 404, URLhaus no_results) -> not_found row.
    monkeypatch.setattr(server, "VT_API_KEY", "test-key-not-real")
    monkeypatch.setattr(server, "URLHAUS_API_KEY", "uh-key-not-real")
    monkeypatch.setattr(server, "_vt_get", _raise_vt(_vt_status_error(404)))
    monkeypatch.setattr(server, "_urlhaus_query", _stub_urlhaus(UH_NONE))

    out = _report(
        server.investigate_sample(server.InvestigateInput(text=ONE_URL, all_sources=True))
    )

    assert out["summary"]["not_found"] == 1  # every source that answered had no data
    assert out["summary"]["malicious"] == 0
    completed = out["results"][0]["consensus"]["sources_completed"]
    assert set(completed) == {"virustotal", "urlhaus"}  # a not-found still counts as answered


def test_all_sources_clean_tallies_clean_or_unknown(monkeypatch):
    # VT clean (has data, unflagged) + URLhaus no data -> clean_or_unknown, not not_found.
    monkeypatch.setattr(server, "VT_API_KEY", "test-key-not-real")
    monkeypatch.setattr(server, "URLHAUS_API_KEY", "uh-key-not-real")
    monkeypatch.setattr(server, "_vt_get", _stub_vt(VT_CLEAN))
    monkeypatch.setattr(server, "_urlhaus_query", _stub_urlhaus(UH_NONE))

    out = _report(
        server.investigate_sample(server.InvestigateInput(text=ONE_URL, all_sources=True))
    )

    assert out["summary"]["clean_or_unknown"] == 1
    assert out["summary"]["malicious"] == 0
    assert out["summary"]["not_found"] == 0  # VT answered with data, so not "all not-found"


def test_all_sources_no_config_returns_actionable_line(monkeypatch):
    # No key configured at all (conftest default) -> single actionable line, not JSON.
    out = asyncio.run(
        server.investigate_sample(server.InvestigateInput(text=ONE_URL, all_sources=True))
    )

    assert "no reputation source is configured" in out
    assert not out.startswith("{")  # a plain line, not a JSON report


def test_all_sources_urlhaus_only_when_no_vt(monkeypatch):
    # Only URLhaus configured: VT is skipped (unconfigured), URLhaus still runs.
    monkeypatch.setattr(server, "URLHAUS_API_KEY", "uh-key-not-real")
    monkeypatch.setattr(server, "_urlhaus_query", _stub_urlhaus(UH_OK))

    out = _report(
        server.investigate_sample(server.InvestigateInput(text=ONE_URL, all_sources=True))
    )

    row = out["results"][0]
    assert set(row["sources"]) == {"urlhaus"}  # only the configured source ran
    assert row["consensus"]["sources_skipped"] == ["virustotal"]  # VT skipped, no key
    assert out["summary"]["malicious"] == 1


def test_all_sources_respects_delay_and_cap(monkeypatch):
    # Pacing + capping behave identically in fan-out mode: n-1 sleeps for looked-up count.
    monkeypatch.setattr(server, "VT_API_KEY", "test-key-not-real")
    monkeypatch.setattr(server, "URLHAUS_API_KEY", "uh-key-not-real")
    monkeypatch.setattr(server, "_vt_get", _stub_vt(VT_CLEAN))
    monkeypatch.setattr(server, "_urlhaus_query", _stub_urlhaus(UH_NONE))

    sleeps = []

    async def _fake_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr(server.asyncio, "sleep", _fake_sleep)

    out = _report(
        server.investigate_sample(
            server.InvestigateInput(
                text=THREE_URLS, all_sources=True, max_indicators=2, delay_seconds=15
            )
        )
    )

    assert out["summary"]["looked_up"] == 2
    assert out["summary"]["skipped_for_cap"] == 1
    assert sleeps == [15.0]  # between the two looked-up indicators only
