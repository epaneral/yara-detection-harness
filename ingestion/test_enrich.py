"""Offline tests for the enrich bridge (store -> lookup_indicator -> summary).

Scope: the aggregation core with a stubbed `call_tool` (no live server, no
network), the type mapping to the server's tool vocabulary, per-indicator error
isolation, the rate-limit pacing, the summary tally, and `main`'s empty-store /
happy paths. The live `_drive_server` path (which needs `mcp` + a real server)
is never exercised - it's monkeypatched out. All I/O goes to tmp_path.
"""

import asyncio
import json

from ingestion import enrich
from ingestion.record import Indicator


def _stub_call_tool(recorded, payload=None):
    """An async `call_tool` replacement that records `(indicator, server_type)`.

    Returns a JSON verdict (echoing the indicator) unless `payload` maps the
    indicator to a specific raw string to return instead.
    """

    async def _inner(indicator, server_type):
        recorded.append((indicator, server_type))
        if payload and indicator in payload:
            return payload[indicator]
        return json.dumps({"indicator": indicator, "consensus": {"malicious": True}})

    return _inner


def test_type_mapping_and_aggregation():
    recorded = []
    indicators = [
        Indicator("d41d8cd98f00b204e9800998ecf8427e", "file_hash", "feed"),
        Indicator("192.0.2.44", "ip_address", "feed"),
        Indicator("malicious.example", "domain", "feed"),
    ]

    rows = asyncio.run(enrich.enrich_indicators(indicators, _stub_call_tool(recorded)))

    # file_hash maps to the server's "file"; the other three names pass through.
    assert [server_type for _, server_type in recorded] == ["file", "ip_address", "domain"]
    for ind, row in zip(indicators, rows, strict=True):
        assert row["indicator"] == ind.indicator
        assert row["type"] == ind.type
        assert row["enrichment"]["indicator"] == ind.indicator


def test_per_indicator_error_isolation():
    recorded = []
    indicators = [
        Indicator("192.0.2.10", "ip_address", "feed"),
        Indicator("192.0.2.44", "ip_address", "feed"),
        Indicator("malicious.example", "domain", "feed"),
    ]
    payload = {"192.0.2.44": "Error: boom"}  # non-JSON -> becomes an error row

    rows = asyncio.run(enrich.enrich_indicators(indicators, _stub_call_tool(recorded, payload)))

    by_ind = {row["indicator"]: row for row in rows}
    assert by_ind["192.0.2.44"]["error"] == "Error: boom"
    assert "enrichment" not in by_ind["192.0.2.44"]
    assert "enrichment" in by_ind["192.0.2.10"]  # the others survived
    assert "enrichment" in by_ind["malicious.example"]


def test_delay_honored_between_lookups(monkeypatch):
    sleeps = []

    async def _fake_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr(enrich.asyncio, "sleep", _fake_sleep)

    indicators = [
        Indicator("192.0.2.1", "ip_address", "feed"),
        Indicator("192.0.2.2", "ip_address", "feed"),
        Indicator("192.0.2.3", "ip_address", "feed"),
    ]

    asyncio.run(enrich.enrich_indicators(indicators, _stub_call_tool([]), delay_seconds=15))
    assert sleeps == [15, 15]  # n-1 sleeps for n indicators, none before the first


def test_no_delay_by_default(monkeypatch):
    sleeps = []

    async def _fake_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr(enrich.asyncio, "sleep", _fake_sleep)

    indicators = [
        Indicator("192.0.2.1", "ip_address", "feed"),
        Indicator("192.0.2.2", "ip_address", "feed"),
    ]

    asyncio.run(enrich.enrich_indicators(indicators, _stub_call_tool([])))
    assert sleeps == []  # default delay_seconds=0: no pacing


def test_summarize_tallies_enriched_malicious_errors():
    rows = [
        {"indicator": "a", "type": "ip_address", "enrichment": {"consensus": {"malicious": True}}},
        {"indicator": "b", "type": "domain", "enrichment": {"consensus": {"malicious": False}}},
        {"indicator": "c", "type": "url", "enrichment": {"consensus": {}}},  # no malicious key
        {"indicator": "d", "type": "ip_address", "error": "Error: boom"},
    ]

    assert enrich.summarize(rows) == {"enriched": 4, "malicious": 1, "errors": 1}


def test_main_empty_store_returns_one(tmp_path, capsys):
    rc = enrich.main(["--store", str(tmp_path / "none.jsonl")])
    assert rc == 1
    err = capsys.readouterr().err
    assert "no indicators" in err  # message went to stderr, no server contacted


def test_main_happy_path_via_stubbed_drive_server(tmp_path, monkeypatch, capsys):
    store_path = tmp_path / "indicators.jsonl"
    records = [
        Indicator("192.0.2.44", "ip_address", "feed", tags=("c2",)),
        Indicator("malicious.example", "domain", "feed", tags=("phishing",)),
    ]
    from ingestion import store

    built, _ = store.merge({}, records)
    store.write(store_path, built)

    canned = [
        {"indicator": "192.0.2.44", "type": "ip_address", "enrichment": {"consensus": {}}},
        {"indicator": "malicious.example", "type": "domain", "enrichment": {"consensus": {}}},
    ]

    async def _fake_drive_server(indicators, server_path, delay_seconds):
        return canned

    monkeypatch.setattr(enrich, "_drive_server", _fake_drive_server)

    rc = enrich.main(["--store", str(store_path), "--server", "unused"])
    assert rc == 0
    out = capsys.readouterr().out
    assert '"enriched": 2' in out  # summary was printed without a real server
