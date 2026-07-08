"""
Shared pytest fixtures for the enrichment MCP server tests.

The server keeps a module-level lookup cache (`server._cache`). Without a reset
a verdict cached by one test would leak into the next -- e.g. a retry test that
drives the real `_vt_get` twice for the same path would see a cache hit on the
second call instead of the expected second network attempt. This autouse fixture
clears the cache around every test so each starts from an empty, deterministic
state. Tests that stub `_vt_get` are unaffected (they never populate the cache).
"""

import pytest
import server


@pytest.fixture(autouse=True)
def _clear_lookup_cache():
    server._cache.clear()
    yield
    server._cache.clear()
