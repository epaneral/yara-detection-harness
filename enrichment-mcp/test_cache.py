"""
Offline tests for the in-process TTL lookup cache.

These exercise the cache layer without a key or a network: the `_TTLCache`
data structure directly (with an injected clock, so expiry and eviction are
deterministic without real time passing), the read-through behavior of
`_vt_get` (a fresh hit skips the network; errors are never cached), and the
end-to-end payoff -- a direct lookup and a later investigate_sample run that
share an indicator hit VirusTotal only once. They complement test_client.py
(shared-client lifecycle + retry/backoff), where `_vt_get` is also the code
under test but caching is not the focus.

The module-level `server._cache` is cleared around every test by the autouse
fixture in conftest.py, so cache integration tests start from a clean, empty
cache without any local fixture here.
"""

import asyncio
import json

import httpx
import pytest
import server


def _response(status, *, json_body=None, headers=None):
    """Build an httpx.Response with a request attached (so raise_for_status works)."""
    request = httpx.Request("GET", "https://www.virustotal.com/api/v3/x")
    body = {} if json_body is None else json_body
    return httpx.Response(status, json=body, headers=headers or {}, request=request)


class _FakeClient:
    """Stand-in for the shared AsyncClient: replays queued responses/exceptions
    and counts how many GETs it received."""

    def __init__(self, outcomes):
        self._outcomes = list(outcomes)
        self.calls = 0

    async def get(self, url, headers=None):
        self.calls += 1
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


# --- _TTLCache unit tests ---------------------------------------------------
# These use a *local* cache with an injected mutable clock, never the module
# `server._cache`, so time and capacity are controlled precisely.
def test_cache_stores_and_returns_value():
    cache = server._TTLCache(ttl=10, max_entries=8)
    cache.set("k", {"v": 1})
    assert cache.get("k") == {"v": 1}  # a stored key returns its exact value
    assert cache.get("absent") is None  # a key never set returns None, not an error


def test_cache_expires_after_ttl():
    now = [1000.0]
    cache = server._TTLCache(ttl=10, max_entries=8, clock=lambda: now[0])
    cache.set("k", {"v": 1})  # expires at 1000 + 10 = 1010

    now[0] = 1009.0
    assert cache.get("k") == {"v": 1}  # still before expiry -- served from cache
    now[0] = 1010.0
    assert cache.get("k") is None  # expiry is clock() >= expires_at, so 1010 is expired


def test_cache_evicts_oldest_when_over_capacity():
    cache = server._TTLCache(ttl=10, max_entries=2)
    cache.set("k1", {"v": 1})
    cache.set("k2", {"v": 2})
    cache.set("k3", {"v": 3})  # pushes past max_entries=2

    assert cache.get("k1") is None  # k1 was the oldest, so it was evicted
    assert cache.get("k2") == {"v": 2}  # k2 and k3 (the two newest) survive
    assert cache.get("k3") == {"v": 3}


def test_cache_get_marks_recently_used():
    cache = server._TTLCache(ttl=10, max_entries=2)
    cache.set("k1", {"v": 1})
    cache.set("k2", {"v": 2})

    assert cache.get("k1") == {"v": 1}  # a get refreshes k1 to most-recently-used
    cache.set("k3", {"v": 3})  # now k2 is the oldest, so it is evicted

    assert cache.get("k2") is None  # k2 evicted -- get() did move k1 ahead of it
    assert cache.get("k1") == {"v": 1}  # k1 survived because get() marked it MRU
    assert cache.get("k3") == {"v": 3}


def test_cache_clear_empties():
    cache = server._TTLCache(ttl=10, max_entries=8)
    cache.set("k", {"v": 1})
    cache.clear()
    assert cache.get("k") is None  # clear() drops every entry


# --- _vt_get read-through integration ---------------------------------------
# `_vt_get` reads through the module `server._cache`; conftest clears it around
# each test, so these start empty. `_get_client` is monkeypatched to a fake so
# no socket is opened.
def test_vt_get_caches_successful_lookup(monkeypatch):
    # Only ONE response is queued: if the cache failed, the second call would
    # pop an empty list and raise IndexError -- so a clean pass proves caching.
    fake = _FakeClient([_response(200, json_body={"ok": True})])
    monkeypatch.setattr(server, "_get_client", lambda: fake)

    assert asyncio.run(server._vt_get("files/abc")) == {"ok": True}
    assert asyncio.run(server._vt_get("files/abc")) == {"ok": True}  # same path served from cache
    assert fake.calls == 1  # the network was hit exactly once


def test_vt_get_distinct_paths_not_shared(monkeypatch):
    fake = _FakeClient([_response(200, json_body={"n": 1}), _response(200, json_body={"n": 2})])
    monkeypatch.setattr(server, "_get_client", lambda: fake)

    assert asyncio.run(server._vt_get("files/a")) == {"n": 1}
    assert asyncio.run(server._vt_get("files/b")) == {"n": 2}
    assert fake.calls == 2  # different paths are different cache keys -- no cross-hit


def test_vt_get_does_not_cache_errors(monkeypatch):
    fake = _FakeClient([_response(404), _response(200, json_body={"ok": True})])
    monkeypatch.setattr(server, "_get_client", lambda: fake)

    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(server._vt_get("files/x"))  # a 404 raises and must NOT be cached
    assert asyncio.run(server._vt_get("files/x")) == {"ok": True}  # same path retried the network
    assert fake.calls == 2  # both attempts hit the network -- the error was not stored


# --- End-to-end cross-call dedup --------------------------------------------
# The headline requirement: overlapping indicators reuse the cache across tools.
def test_lookup_then_investigate_reuses_cache(monkeypatch):
    monkeypatch.setattr(server, "VT_API_KEY", "test-key-not-real")  # tools require a key
    # The direct lookup caches the IP's VT path; investigate_sample extracts the
    # same IP, so its lookup is a cache hit -- one queued response is enough.
    verdict = {
        "data": {"id": "192.0.2.44", "attributes": {"last_analysis_stats": {"malicious": 0}}}
    }
    fake = _FakeClient([_response(200, json_body=verdict)])
    monkeypatch.setattr(server, "_get_client", lambda: fake)

    asyncio.run(server.vt_lookup_ip_address(server.IpLookupInput(ip="192.0.2.44")))
    out = asyncio.run(
        server.investigate_sample(server.InvestigateInput(text="connect 192.0.2.44 now"))
    )

    assert fake.calls == 1  # investigate reused the cached verdict -- no second fetch
    report = json.loads(out)
    assert report["summary"]["looked_up"] == 1  # the text has exactly one indicator (the IP)
