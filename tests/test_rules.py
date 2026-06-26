"""
Corpus-based regression harness for the YARA ruleset.

Four gates, all driven by tests/manifest.yml:

  1. compilation   - every .yar file compiles (a broken rule fails the build)
  2. recall        - each malicious sample is caught by its expected rule(s)
  3. false-positive- benign near-misses produce no matches; the aggregate FP
                     rate across the benign corpus must stay <= FP_THRESHOLD
  4. integrity     - the manifest and ruleset stay in sync: no orphan rule
                     (defined but unexercised), no expected_rules naming a
                     non-existent rule, and every referenced sample path exists

The manifest is the single source of truth: add a sample there and it is
automatically covered.
"""

import pathlib

import pytest
import yaml
import yara

REPO = pathlib.Path(__file__).resolve().parents[1]
RULES_DIR = REPO / "rules"
MANIFEST = REPO / "tests" / "manifest.yml"

# Build gate: fraction of benign samples allowed to match any rule.
# Held at 0.0 for the skeleton - any false positive fails CI.
FP_THRESHOLD = 0.0


def load_manifest():
    data = yaml.safe_load(MANIFEST.read_text())
    return data["samples"]


def compiled_rules():
    """Compile every rule file into one namespaced ruleset."""
    filepaths = {p.stem: str(p) for p in sorted(RULES_DIR.glob("*.yar"))}
    assert filepaths, "no .yar files found under rules/"
    return yara.compile(filepaths=filepaths)


def matches_for(rules, sample_path):
    data = (REPO / sample_path).read_bytes()
    return sorted(m.rule for m in rules.match(data=data))


SAMPLES = load_manifest()
MALICIOUS = [s for s in SAMPLES if s["label"] == "malicious"]
BENIGN = [s for s in SAMPLES if s["label"] == "benign"]

# Every rule name the manifest claims should fire, across all samples.
EXPECTED_RULES = {name for s in SAMPLES for name in (s.get("expected_rules") or [])}


def defined_rules():
    """Identifiers of every rule that actually compiles from rules/."""
    return {r.identifier for r in compiled_rules()}


# --- Gate 1: compilation ---------------------------------------------------
@pytest.mark.parametrize("rule_file", sorted(RULES_DIR.glob("*.yar")), ids=lambda p: p.name)
def test_rule_file_compiles(rule_file):
    yara.compile(str(rule_file))


# --- Gate 2: recall (true positives) ---------------------------------------
@pytest.mark.parametrize("sample", MALICIOUS, ids=lambda s: s["path"])
def test_positive_is_detected(sample):
    rules = compiled_rules()
    fired = matches_for(rules, sample["path"])
    missing = set(sample["expected_rules"]) - set(fired)
    assert not missing, f"{sample['path']} missed expected rule(s) {sorted(missing)}; fired={fired}"


# --- Gate 3: false positives ------------------------------------------------
@pytest.mark.parametrize("sample", BENIGN, ids=lambda s: s["path"])
def test_benign_does_not_match(sample):
    rules = compiled_rules()
    fired = matches_for(rules, sample["path"])
    assert not fired, f"FALSE POSITIVE on {sample['path']}: {fired}"


def test_aggregate_fp_rate_within_threshold():
    rules = compiled_rules()
    tripped = [s["path"] for s in BENIGN if matches_for(rules, s["path"])]
    fp_rate = len(tripped) / len(BENIGN) if BENIGN else 0.0
    assert fp_rate <= FP_THRESHOLD, (
        f"FP rate {fp_rate:.1%} exceeds threshold {FP_THRESHOLD:.1%}; offenders={tripped}"
    )


# --- Gate 4: manifest <-> ruleset integrity --------------------------------
def test_every_defined_rule_is_covered():
    """No rule ships without a malicious sample exercising it."""
    orphans = defined_rules() - EXPECTED_RULES
    assert not orphans, (
        f"orphan rule(s) not exercised by any sample: {sorted(orphans)}; "
        "add a malicious sample to tests/manifest.yml that expects each"
    )


def test_expected_rules_reference_real_rules():
    """Every name in the manifest's expected_rules resolves to a compiled rule."""
    unknown = EXPECTED_RULES - defined_rules()
    assert not unknown, f"manifest names unknown rule(s) (typo or removed rule?): {sorted(unknown)}"


@pytest.mark.parametrize("sample", SAMPLES, ids=lambda s: s["path"])
def test_manifest_paths_exist(sample):
    path = REPO / sample["path"]
    assert path.is_file(), f"manifest references missing sample file: {sample['path']}"
