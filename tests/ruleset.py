"""Shared harness primitives: locate the ruleset + corpus, compile, and scan.

Imported by both the pytest harness (`test_rules.py`) and the retro-hunt CLI
(`retrohunt.py`) so compilation and corpus scanning have one source of truth.
"""

import pathlib

import yaml
import yara

REPO = pathlib.Path(__file__).resolve().parents[1]
RULES_DIR = REPO / "rules"
MANIFEST = REPO / "tests" / "manifest.yml"


def load_manifest() -> list[dict]:
    """The manifest's `samples` list (each: path, label, expected_rules)."""
    return yaml.safe_load(MANIFEST.read_text())["samples"]


def compile_ruleset() -> yara.Rules:
    """Compile every rule file under rules/ into one namespaced ruleset."""
    filepaths = {p.stem: str(p) for p in sorted(RULES_DIR.glob("*.yar"))}
    assert filepaths, "no .yar files found under rules/"
    return yara.compile(filepaths=filepaths)


def matches_for(rules: yara.Rules, sample_path: str) -> list[str]:
    """Sorted names of the rules in `rules` that match the corpus sample at `sample_path`."""
    data = (REPO / sample_path).read_bytes()
    return sorted(m.rule for m in rules.match(data=data))
