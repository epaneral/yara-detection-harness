"""
CI gate for the offline enrichment eval (eval_harness.py + eval_cases.py).

Runs the same extraction and verdict/consensus metrics that
`python eval_harness.py` reports, and fails the build if any metric is below its
threshold -- plus a per-case breakdown so a regression names the offending case.
Fully offline: the harness stubs both sources, so no key and no network. This is
what makes the eval a *gate*, not just a runnable report.
"""

import asyncio

import eval_cases
import eval_harness
import pytest
import server


def test_extraction_meets_thresholds():
    m = eval_harness.extraction_metrics(eval_cases.CASES)
    assert m["recall"] >= eval_harness.MIN_EXTRACTION_RECALL, m["per_case"]
    assert m["precision"] >= eval_harness.MIN_EXTRACTION_PRECISION, m["per_case"]


@pytest.mark.parametrize("case", eval_cases.CASES, ids=lambda c: c["name"])
def test_extraction_per_case_exact(case):
    # A per-case exact match, so a regression fails with the case name, not just an
    # aggregate dip.
    got = {(d["indicator"], d["type"]) for d in server._extract_indicators(case["text"])}
    exp = {(d["indicator"], d["type"]) for d in case["expected_indicators"]}
    assert got == exp


def test_verdict_meets_thresholds():
    m = asyncio.run(eval_harness.verdict_metrics(eval_cases.CASES))
    assert m["verdict_accuracy"] >= eval_harness.MIN_VERDICT_ACCURACY, m["per_case"]
    assert m["shape_conformance"] >= eval_harness.MIN_SHAPE_CONFORMANCE, m["per_case"]


@pytest.mark.parametrize(
    "case", [c for c in eval_cases.CASES if "golden" in c], ids=lambda c: c["name"]
)
def test_verdict_per_case(case):
    # Consensus verdict matches expected, and every source verdict is shape-conformant.
    res = asyncio.run(eval_harness.consensus_for_case(case))
    assert res["malicious"] == case["expected_malicious"]
    assert res["conforms"] is True
