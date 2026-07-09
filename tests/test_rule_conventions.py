"""
Rule-convention checks (plyara-based) — the house style the yaraQA gate can't know.

The `yaraqa` CI job gates *generic* YARA quality and performance. These checks gate
*this repo's* documented conventions (see CLAUDE.md) by parsing each rule's source with
[plyara](https://github.com/plyara/plyara) and asserting:

  * every rule declares the full meta block (author/description/family/severity/attack/
    reference/date), non-empty;
  * the `attack` field lists well-formed MITRE ATT&CK technique IDs (`Txxxx[.xxx]`);
  * `severity` is drawn from a controlled vocabulary;
  * regex strings anchor on a concrete atom rather than a leading `.*`/`.+` wildcard;
  * each rule combines at least two string primitives (single-feature rules cause FPs).

Parametrized over every rule in rules/, so a new rule is covered automatically — the same
manifest-free "add it and it's checked" property the detection harness has. The required
schema and vocabulary are single explicit constants, tunable like `FP_THRESHOLD`.
"""

import pathlib
import re

import plyara
import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
RULES_DIR = REPO / "rules"

# House-style meta schema every rule must declare (each present and non-empty).
REQUIRED_META_KEYS = (
    "author",
    "description",
    "family",
    "severity",
    "attack",
    "reference",
    "date",
)
ALLOWED_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
# MITRE ATT&CK technique id: Txxxx with an optional .xxx sub-technique.
_ATTACK_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def _parse_rules():
    """Parse every rule file with plyara; return [(rule_dict, file_name), ...].

    A fresh Plyara() per file — the parser carries state across parse calls.
    """
    parsed = []
    for path in sorted(RULES_DIR.glob("*.yar")):
        for rule in plyara.Plyara().parse_string(path.read_text()):
            parsed.append((rule, path.name))
    return parsed


RULES = _parse_rules()


def _meta(rule):
    """Flatten plyara's list-of-single-key-dicts metadata into one dict."""
    flat = {}
    for entry in rule.get("metadata", []):
        flat.update(entry)
    return flat


def _rule_id(rule_and_file):
    rule, name = rule_and_file
    return f"{name}:{rule['rule_name']}"


def test_rules_parse_and_exist():
    """Guard against an empty/failed parse silently making every check vacuous."""
    assert RULES, "plyara parsed no rules from rules/*.yar"


@pytest.mark.parametrize("rule_and_file", RULES, ids=_rule_id)
def test_required_meta_present(rule_and_file):
    rule, _ = rule_and_file
    meta = _meta(rule)
    missing = [k for k in REQUIRED_META_KEYS if not str(meta.get(k, "")).strip()]
    assert not missing, f"{rule['rule_name']}: missing/empty meta {missing}"


@pytest.mark.parametrize("rule_and_file", RULES, ids=_rule_id)
def test_attack_ids_are_valid_mitre(rule_and_file):
    rule, _ = rule_and_file
    ids = [t.strip() for t in _meta(rule).get("attack", "").split(",") if t.strip()]
    assert ids, f"{rule['rule_name']}: empty attack field"
    bad = [t for t in ids if not _ATTACK_ID_RE.match(t)]
    assert not bad, f"{rule['rule_name']}: malformed MITRE technique id(s) {bad}"


@pytest.mark.parametrize("rule_and_file", RULES, ids=_rule_id)
def test_severity_in_vocabulary(rule_and_file):
    rule, _ = rule_and_file
    sev = _meta(rule).get("severity", "")
    assert sev in ALLOWED_SEVERITIES, (
        f"{rule['rule_name']}: severity '{sev}' not in {sorted(ALLOWED_SEVERITIES)}"
    )


@pytest.mark.parametrize("rule_and_file", RULES, ids=_rule_id)
def test_regex_strings_anchor_on_atom(rule_and_file):
    """No regex may open with a leading `.*`/`.+`: anchor on a concrete atom instead."""
    rule, _ = rule_and_file
    offenders = []
    for s in rule.get("strings", []):
        if s.get("type") != "regex":
            continue
        # plyara keeps the enclosing slashes in `value`; drop the opener and any `^`
        # anchor, then look at the first real token.
        body = s["value"].lstrip("/").lstrip("^")
        if body.startswith((".*", ".+")):
            offenders.append(s["name"])
    assert not offenders, (
        f"{rule['rule_name']}: regex string(s) open with a leading wildcard "
        f"(anchor on a concrete atom instead): {offenders}"
    )


@pytest.mark.parametrize("rule_and_file", RULES, ids=_rule_id)
def test_rule_combines_two_primitives(rule_and_file):
    """Conservative floor for 'combination over presence': at least two strings defined.

    Full two-primitives-must-co-occur analysis of the condition is left to review; this
    catches the degenerate single-feature rule that the near-miss corpus warns against.
    """
    rule, _ = rule_and_file
    n = len(rule.get("strings", []))
    assert n >= 2, f"{rule['rule_name']}: only {n} string(s); rules combine >=2 primitives"
