"""
Opt-in LIVE enrichment eval (needs an API key; hits the real reputation APIs).

Unlike the offline eval (test_eval.py + eval_harness.py, the CI gate), this makes
real network calls and checks a few *loose invariants* -- the eval analog of
smoke_test.py. It is NOT run by pytest and never gates CI: live verdicts drift,
rate limits apply, and fork PRs get no secrets. Run it by hand or on a schedule
with a key in the environment (or enrichment-mcp/.env):

    python enrichment-mcp/eval_live.py

Exits 0 if every invariant holds (or if no key is set, in which case it skips),
and 1 otherwise.
"""

import asyncio
import json

import eval_harness
import server

# EICAR antimalware test file SHA-256 -- a benign test signature, but universally
# flagged on VirusTotal, so it is a stable "known-malicious" fixture.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

# (label, indicator type, indicator, predicate over the consensus block)
INVARIANTS = [
    ("EICAR hash is flagged malicious", "file", EICAR_SHA256, lambda c: c["malicious"] is True),
    (
        "A major reputable domain is not malicious",
        "domain",
        "cloudflare.com",
        lambda c: c["malicious"] is False,
    ),
]


async def _run() -> list:
    results = []
    for label, kind, indicator, predicate in INVARIANTS:
        raw = await server.lookup_indicator(
            server.IndicatorLookupInput(indicator=indicator, type=kind)
        )
        if not raw.startswith("{"):
            results.append((label, False, raw.strip()))  # an actionable error line, not a verdict
            continue
        env = json.loads(raw)
        # Every source *verdict* (not an error / not_found entry) must keep the shape.
        shape_ok = all(
            frozenset(entry) == eval_harness.NORMALIZED_KEYS
            for entry in env["sources"].values()
            if "error" not in entry and "not_found" not in entry
        )
        ok = bool(predicate(env["consensus"])) and shape_ok
        detail = (
            f"consensus.malicious={env['consensus']['malicious']} "
            f"sources={list(env['sources'])} shape_ok={shape_ok}"
        )
        results.append((label, ok, detail))
    return results


async def _run_and_close() -> list:
    try:
        return await _run()
    finally:
        await server._close_client()  # we run outside the FastMCP lifespan, so close by hand


def main() -> int:
    if not (server.VT_API_KEY or server.URLHAUS_API_KEY):
        print("SKIP: no source key set (VT_API_KEY / URLHAUS_API_KEY). Nothing to check live.")
        return 0
    results = asyncio.run(_run_and_close())
    print("=== Live enrichment eval ===")
    failed = 0
    for label, ok, detail in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
        print(f"           {detail}")
        failed += not ok
    held = len(results) - failed
    print(f"\n{'PASS' if not failed else 'FAIL'}: {held}/{len(results)} invariants held.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
