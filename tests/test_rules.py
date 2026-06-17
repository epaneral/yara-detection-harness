"""
Corpus-based regression harness for the YARA ruleset.

Three gates, all driven by tests/manifest.yml:

  1. compilation   - every .yar file compiles (a broken rule fails the build)
  2. recall        - each malicious sample is caught by its expected rule(s)
  3. false-positive- benign near-misses produce no matches; the aggregate FP
                     rate across the benign corpus must stay <= FP_THRESHOLD

The manifest is the single source of truth: add a sample there and it is
automatically covered.
"""

import pathlib
import yara
import yaml
import pytest

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


# --- Gate 1: compilation ---------------------------------------------------
@pytest.mark.parametrize("rule_file", sorted(RULES_DIR.glob("*.yar")),
                         ids=lambda p: p.name)
def test_rule_file_compiles(rule_file):
    yara.compile(str(rule_file))


# --- Gate 2: recall (true positives) ---------------------------------------
@pytest.mark.parametrize("sample", MALICIOUS, ids=lambda s: s["path"])
def test_positive_is_detected(sample):
    rules = compiled_rules()
    fired = matches_for(rules, sample["path"])
    missing = set(sample["expected_rules"]) - set(fired)
    assert not missing, (
        f"{sample['path']} missed expected rule(s) {sorted(missing)}; "
        f"fired={fired}"
    )


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
        f"FP rate {fp_rate:.1%} exceeds threshold {FP_THRESHOLD:.1%}; "
        f"offenders={tripped}"
    )
