"""
Offline tests for the shared HTTP client and the retry/backoff in _vt_get.

These exercise the transport layer directly -- the shared-client lifecycle
(_get_client / _close_client) and _vt_get's retry-on-429/5xx behavior -- with a
fake client so no real socket is opened and no network is touched. They
complement test_server.py (pure helpers) and test_tools.py (tools with _vt_get
itself stubbed): here _vt_get is the code under test, so it is NOT stubbed.
"""

import asyncio

import httpx
import pytest
import server

GOOD_HASH = "d41d8cd98f00b204e9800998ecf8427e"


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


@pytest.fixture(autouse=True)
def _reset_client():
    """Start each test with no shared client and close any real one it created,
    so a client never leaks between tests."""
    server._client = None
    yield
    if server._client is not None:
        asyncio.run(server._close_client())


def _record_sleep(monkeypatch):
    """Replace asyncio.sleep with a no-op recorder; return the list of waits."""
    sleeps = []

    async def _fake_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr(server.asyncio, "sleep", _fake_sleep)
    return sleeps


# --- Shared client lifecycle ------------------------------------------------
def test_get_client_reuses_one_instance():
    c1 = server._get_client()
    c2 = server._get_client()
    assert c1 is c2  # one pooled client, not a fresh one per call
    assert isinstance(c1, httpx.AsyncClient)


def test_close_client_resets_and_recreates():
    c1 = server._get_client()
    asyncio.run(server._close_client())
    assert server._client is None  # closed and dropped
    c2 = server._get_client()
    assert c2 is not c1  # a fresh client after close


def test_close_client_is_idempotent():
    # No client created yet -- closing must not raise.
    asyncio.run(server._close_client())
    assert server._client is None


def test_vt_get_routes_through_shared_client(monkeypatch):
    fake = _FakeClient([_response(200, json_body={"n": 1}), _response(200, json_body={"n": 2})])
    monkeypatch.setattr(server, "_get_client", lambda: fake)

    assert asyncio.run(server._vt_get("files/a")) == {"n": 1}
    assert asyncio.run(server._vt_get("files/b")) == {"n": 2}
    assert fake.calls == 2  # both requests went through the one shared client


# --- Retry / backoff --------------------------------------------------------
def test_vt_get_retries_429_then_succeeds(monkeypatch):
    sleeps = _record_sleep(monkeypatch)
    fake = _FakeClient([_response(429), _response(200, json_body={"ok": True})])
    monkeypatch.setattr(server, "_get_client", lambda: fake)

    assert asyncio.run(server._vt_get("files/x")) == {"ok": True}
    assert fake.calls == 2  # one retry after the 429
    assert len(sleeps) == 1


def test_vt_get_retries_transient_5xx_then_succeeds(monkeypatch):
    _record_sleep(monkeypatch)
    fake = _FakeClient([_response(503), _response(200, json_body={"ok": True})])
    monkeypatch.setattr(server, "_get_client", lambda: fake)

    assert asyncio.run(server._vt_get("files/x")) == {"ok": True}
    assert fake.calls == 2


def test_vt_get_honors_numeric_retry_after(monkeypatch):
    sleeps = _record_sleep(monkeypatch)
    fake = _FakeClient(
        [_response(429, headers={"Retry-After": "2"}), _response(200, json_body={"ok": True})]
    )
    monkeypatch.setattr(server, "_get_client", lambda: fake)

    asyncio.run(server._vt_get("files/x"))
    assert sleeps == [2.0]  # honored the header instead of the backoff default


def test_vt_get_caps_absurd_retry_after(monkeypatch):
    sleeps = _record_sleep(monkeypatch)
    fake = _FakeClient(
        [_response(429, headers={"Retry-After": "99999"}), _response(200, json_body={"ok": True})]
    )
    monkeypatch.setattr(server, "_get_client", lambda: fake)

    asyncio.run(server._vt_get("files/x"))
    assert sleeps == [server.RETRY_AFTER_MAX_SECONDS]  # a huge value can't stall us


def test_vt_get_uses_exponential_backoff_without_retry_after(monkeypatch):
    sleeps = _record_sleep(monkeypatch)
    fake = _FakeClient([_response(500), _response(502), _response(200, json_body={"ok": True})])
    monkeypatch.setattr(server, "_get_client", lambda: fake)

    asyncio.run(server._vt_get("files/x"))
    # attempt 0 -> BASE * 1, attempt 1 -> BASE * 2
    assert sleeps == [server.BACKOFF_BASE_SECONDS, server.BACKOFF_BASE_SECONDS * 2]


def test_vt_get_exhausts_retries_then_raises(monkeypatch):
    _record_sleep(monkeypatch)
    fake = _FakeClient([_response(429) for _ in range(server.MAX_RETRIES + 5)])
    monkeypatch.setattr(server, "_get_client", lambda: fake)

    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(server._vt_get("files/x"))
    assert fake.calls == server.MAX_RETRIES + 1  # initial attempt + MAX_RETRIES retries


def test_vt_get_does_not_retry_404(monkeypatch):
    sleeps = _record_sleep(monkeypatch)
    fake = _FakeClient([_response(404)])
    monkeypatch.setattr(server, "_get_client", lambda: fake)

    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(server._vt_get("files/x"))
    assert fake.calls == 1  # a 404 is terminal -- no retry
    assert sleeps == []


def test_lookup_maps_exhausted_429_to_rate_limit_line(monkeypatch):
    # End-to-end: a persistent 429 through the tool still degrades to the
    # existing actionable one-liner, never a stack trace.
    monkeypatch.setattr(server, "VT_API_KEY", "test-key-not-real")
    _record_sleep(monkeypatch)
    fake = _FakeClient([_response(429) for _ in range(server.MAX_RETRIES + 1)])
    monkeypatch.setattr(server, "_get_client", lambda: fake)

    out = asyncio.run(server.vt_lookup_file_hash(server.HashLookupInput(file_hash=GOOD_HASH)))
    assert "rate limit" in out
    assert "429" in out
