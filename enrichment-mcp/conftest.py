"""
Shared pytest fixtures for the enrichment MCP server tests.

`_clear_lookup_cache`: the server keeps a module-level lookup cache
(`server._cache`). Without a reset a verdict cached by one test would leak into
the next -- e.g. a retry test that drives the real `_vt_get` twice for the same
path would see a cache hit on the second call instead of the expected second
network attempt. This autouse fixture clears the cache around every test.

`_no_source_keys`: default every reputation source to *unconfigured* (empty API
key) so a stray key in the developer's environment can never make a test hit the
real network -- the "tests run with no key, network stubbed" convention enforced
at the fixture level. Tests that need a source live monkeypatch its key explicitly.
"""

import pytest
import server


@pytest.fixture(autouse=True)
def _clear_lookup_cache():
    server._cache.clear()
    yield
    server._cache.clear()


@pytest.fixture(autouse=True)
def _no_source_keys(monkeypatch):
    monkeypatch.setattr(server, "VT_API_KEY", "")
    monkeypatch.setattr(server, "URLHAUS_API_KEY", "")
