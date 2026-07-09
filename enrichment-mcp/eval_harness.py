"""
Offline enrichment eval harness.

Measures the enrichment *pipeline* (extract -> per-source lookup -> normalize ->
consensus) against the labeled cases in eval_cases.py, deterministically and with
no API key or network: each source is stubbed to return the case's golden label.
Two dimensions:

  - Extraction: precision / recall / F1 of _extract_indicators vs. the ground-truth
    indicators.
  - Verdict:    does the fan-out's sample-level consensus match expected_malicious,
    and does every source verdict conform to the normalized shape.

`python eval_harness.py` prints a report and exits non-zero if any metric is below
its threshold. test_eval.py gates CI on the same thresholds. This complements
eval_live.py, which checks loose invariants against the real APIs with a key.
"""

import asyncio

import eval_cases
import httpx
import server

# Gate thresholds. Extraction is deterministic on these hand-labeled cases, so we
# hold it to an exact match; verdicts and shape must be perfect (the pipeline is
# fully stubbed, so any miss is a real regression, not source noise).
MIN_EXTRACTION_PRECISION = 1.0
MIN_EXTRACTION_RECALL = 1.0
MIN_VERDICT_ACCURACY = 1.0
MIN_SHAPE_CONFORMANCE = 1.0

# The exact key set every normalized verdict must carry (see server._verdict).
NORMALIZED_KEYS = frozenset(
    {
        "indicator",
        "type",
        "malicious",
        "suspicious",
        "harmless",
        "undetected",
        "reputation",
        "flagged_by",
        "permalink",
    }
)


def _vt_404() -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://www.virustotal.com/api/v3/x")
    response = httpx.Response(404, request=request)
    return httpx.HTTPStatusError("404", request=request, response=response)


def _make_vt_stub(label: str):
    """A _vt_get replacement returning a VT payload for the golden label."""

    async def _stub(path: str) -> dict:
        if label == "not_found":
            raise _vt_404()
        stats = {"malicious": 5} if label == "malicious" else {"malicious": 0, "harmless": 60}
        return {"data": {"id": path.split("/")[-1], "attributes": {"last_analysis_stats": stats}}}

    return _stub


def _make_urlhaus_stub(label: str):
    """A _urlhaus_query replacement returning a URLhaus response for the golden label.

    URLhaus is a blocklist: "malicious" -> a listed (query_status ok) response;
    anything else ("clean"/"not_found") -> no_results (absent from the blocklist).
    """

    async def _stub(endpoint: str, data: dict) -> dict:
        if label == "malicious":
            return {
                "query_status": "ok",
                "url_count": "3",
                "urlhaus_reference": "https://urlhaus.abuse.ch/eval/",
                "blacklists": {},
            }
        return {"query_status": "no_results"}

    return _stub


def extraction_metrics(cases: list) -> dict:
    """Precision / recall / F1 of _extract_indicators vs. each case's ground truth."""
    tp = fp = fn = 0
    per_case = []
    for case in cases:
        got = {(d["indicator"], d["type"]) for d in server._extract_indicators(case["text"])}
        exp = {(d["indicator"], d["type"]) for d in case["expected_indicators"]}
        c_tp, c_fp, c_fn = len(got & exp), len(got - exp), len(exp - got)
        tp, fp, fn = tp + c_tp, fp + c_fp, fn + c_fn
        per_case.append(
            {
                "name": case["name"],
                "ok": got == exp,
                "missed": sorted(exp - got),
                "spurious": sorted(got - exp),
            }
        )
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "per_case": per_case,
    }


async def consensus_for_case(case: dict) -> dict:
    """Run the fan-out for a case with its golden sources stubbed; return the
    sample-level verdict (malicious if any indicator is) and shape conformance.

    Temporarily configures + stubs both sources and restores them after, so it is
    safe to call from tests (whose keys are neutralized by conftest) and from main.
    """
    orig = (server.VT_API_KEY, server.URLHAUS_API_KEY, server._vt_get, server._urlhaus_query)
    server.VT_API_KEY = "eval-vt-key"
    server.URLHAUS_API_KEY = "eval-urlhaus-key"
    server._vt_get = _make_vt_stub(case["golden"]["virustotal"])
    server._urlhaus_query = _make_urlhaus_stub(case["golden"]["urlhaus"])
    try:
        any_malicious = False
        conforms = True
        for ind in case["expected_indicators"]:
            env = await server._fanout_lookup(ind["type"], ind["indicator"])
            any_malicious = any_malicious or env["consensus"]["malicious"]
            for entry in env["sources"].values():
                if "error" not in entry and "not_found" not in entry:
                    conforms = conforms and (frozenset(entry) == NORMALIZED_KEYS)
        return {"malicious": any_malicious, "conforms": conforms}
    finally:
        server.VT_API_KEY, server.URLHAUS_API_KEY, server._vt_get, server._urlhaus_query = orig


async def verdict_metrics(cases: list) -> dict:
    """Consensus accuracy and shape conformance over the cases carrying a golden."""
    graded = [c for c in cases if "golden" in c]
    correct = conform = 0
    per_case = []
    for case in graded:
        res = await consensus_for_case(case)
        v_ok = res["malicious"] == case["expected_malicious"]
        correct += v_ok
        conform += res["conforms"]
        per_case.append({"name": case["name"], "verdict_ok": v_ok, "conforms": res["conforms"]})
    total = len(graded)
    return {
        "verdict_accuracy": correct / total if total else 1.0,
        "shape_conformance": conform / total if total else 1.0,
        "total": total,
        "per_case": per_case,
    }


def format_report(extraction: dict, verdict: dict) -> str:
    """Render the two metric sets as a compact human-readable report."""
    lines = ["=== Enrichment eval ===", ""]
    lines.append("Extraction:")
    lines.append(
        f"  precision={extraction['precision']:.3f} recall={extraction['recall']:.3f} "
        f"f1={extraction['f1']:.3f}  (tp={extraction['tp']} fp={extraction['fp']} "
        f"fn={extraction['fn']})"
    )
    for c in extraction["per_case"]:
        flag = "ok" if c["ok"] else f"MISS missed={c['missed']} spurious={c['spurious']}"
        lines.append(f"    - {c['name']}: {flag}")
    lines.append("")
    lines.append("Verdict / consensus:")
    lines.append(
        f"  accuracy={verdict['verdict_accuracy']:.3f} shape_conformance="
        f"{verdict['shape_conformance']:.3f}  ({verdict['total']} graded cases)"
    )
    for c in verdict["per_case"]:
        flag = "ok" if (c["verdict_ok"] and c["conforms"]) else "MISS"
        lines.append(
            f"    - {c['name']}: verdict={'ok' if c['verdict_ok'] else 'WRONG'} "
            f"shape={'ok' if c['conforms'] else 'BAD'}  [{flag}]"
        )
    return "\n".join(lines)


def _below_threshold(extraction: dict, verdict: dict) -> list:
    """Return a list of (metric, value, threshold) that fall below their gate."""
    checks = [
        ("extraction precision", extraction["precision"], MIN_EXTRACTION_PRECISION),
        ("extraction recall", extraction["recall"], MIN_EXTRACTION_RECALL),
        ("verdict accuracy", verdict["verdict_accuracy"], MIN_VERDICT_ACCURACY),
        ("shape conformance", verdict["shape_conformance"], MIN_SHAPE_CONFORMANCE),
    ]
    return [(name, val, thr) for name, val, thr in checks if val < thr]


def main() -> int:
    extraction = extraction_metrics(eval_cases.CASES)
    verdict = asyncio.run(verdict_metrics(eval_cases.CASES))
    print(format_report(extraction, verdict))
    failures = _below_threshold(extraction, verdict)
    if failures:
        print("\nFAIL: below threshold:")
        for name, val, thr in failures:
            print(f"  {name}: {val:.3f} < {thr:.3f}")
        return 1
    print("\nPASS: all metrics meet thresholds.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
