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
  * each rule's condition requires >= 2 distinct string primitives to co-occur --
    AND-joined refs or an of-quantifier resolving to >= 2; presence-of-one conditions
    (`any of them`, `$a or $b`) fail even with a populated strings section.

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


# --- condition analysis for test_rule_combines_two_primitives -------------------------
# Token-level helpers over plyara's `condition_terms` (a flat token list: parens are
# their own tokens, string refs/wildcards single tokens, e.g. `2 of ($k*)` ->
# ["2", "of", "(", "$k*", ")"]). Format verified against the pinned plyara==2.2.8.

# A string-primitive reference: $name/$prefix* (match), #name (count), @name (offset),
# !name (length). `!=` doesn't match ('=' is not an identifier char); keywords don't.
_STRING_REF_RE = re.compile(r"^[$#@!][A-Za-z0-9_]*\*?$")


def _base_id(token):
    """Base identifier of a string-ref token: '$cred*' -> 'cred', '#a' -> 'a'."""
    return token.lstrip("$#@!").rstrip("*")


def _strip_outer_parens(terms):
    """Peel parens enclosing the entire term list: ( X ) -> X."""
    while len(terms) >= 2 and terms[0] == "(" and terms[-1] == ")":
        depth = 0
        for t in terms[:-1]:
            depth += {"(": 1, ")": -1}.get(t, 0)
            if depth == 0:  # the opening paren closes before the end: not an outer pair
                return terms
        terms = terms[1:-1]
    return terms


def _split_depth0(terms, keyword):
    """Split a token list on parenthesis-depth-0 occurrences of `keyword` ('and'/'or')."""
    segments, current, depth = [], [], 0
    for t in terms:
        if t == "(":
            depth += 1
        elif t == ")":
            depth -= 1
        if depth == 0 and t == keyword:
            segments.append(current)
            current = []
        else:
            current.append(t)
    segments.append(current)
    return segments


def _of_quantifier_count(seg, string_names):
    """`seg`'s minimum distinct-string count if it is exactly an of-quantifier, else None.

    Resolves `all|any|N of them` and `all|any|N of ( $set... )` (wildcard or enumerated):
    'all' -> size of the set it ranges over, 'any' -> 1, literal N -> N. No satisfiability
    check (`3 of` over a 2-string set is the recall gate's problem, not this one's).
    """
    if len(seg) < 3 or seg[1] != "of":
        return None
    head, target = seg[0], seg[2:]
    inner = _strip_outer_parens(target)
    if target == ["them"]:
        pool = len(string_names)
    elif target[0] == "(" and target[-1] == ")" and inner != target:
        pool = 0
        for ref in (t for t in inner if _STRING_REF_RE.match(t)):
            if ref.endswith("*"):
                pool += sum(1 for n in string_names if n.startswith(ref[:-1]))
            else:
                pool += 1
    else:
        return None
    if head == "all":
        return pool
    if head == "any":
        return 1
    if head.isdigit():
        return int(head)
    return None


def _conjunct_min_primitives(seg, string_names):
    """Minimum string primitives one top-level AND-conjunct guarantees to be present.

    `not ...` asserts absence -> 0; an of-quantifier -> its resolved count; otherwise 1
    if every depth-0 or-branch references some string (a branch like `filesize < 1MB`
    would let the conjunct hold with no string at all -> 0).
    """
    seg = _strip_outer_parens(seg)
    if not seg or seg[0] == "not":
        return 0
    count = _of_quantifier_count(seg, string_names)
    if count is not None:
        return count
    branches = _split_depth0(seg, "or")
    if all(any(_STRING_REF_RE.match(t) or t == "them" for t in b) for b in branches):
        return 1
    return 0


@pytest.mark.parametrize("rule_and_file", RULES, ids=_rule_id)
def test_rule_combines_two_primitives(rule_and_file):
    """Two primitives must CO-OCCUR in the condition, not merely exist in `strings:`.

    Token-level heuristic over `condition_terms` -- deliberately not boolean SAT:

      * >= 2 strings defined (the cheap floor this test used to stop at);
      * no `or` at parenthesis depth 0: a top-level disjunction means one branch alone
        can fire the rule. An or-of-conjunctions (`($a and $b) or ($c and $d)`) does
        co-occur but fails here BY DESIGN -- house style is one rule per variant; split
        the rule or extend this check if that shape is ever genuinely needed;
      * the top-level AND-conjuncts together guarantee >= 2 present string primitives
        (plain ref = 1, all-branches-reference or-group = 1, `all of them`/`N of ...`
        = resolved count, `not ...` = 0);
      * the referenced primitives are not all the same string (`$a and $a` or
        `$a and #a > 0` is one primitive), unless a >= 2 of-quantifier already
        guarantees plurality (YARA `of` ranges over distinct strings by construction).

    Known accepted blind spot: or-branches sharing refs across conjuncts
    (`($a or $b) and $a`) overcount. Failures here are over-strict by intent --
    they ask a human to look, never wave a presence-of-one condition through.
    """
    rule, _ = rule_and_file
    name = rule["rule_name"]
    string_names = [s["name"] for s in rule.get("strings", [])]
    assert len(string_names) >= 2, (
        f"{name}: only {len(string_names)} string(s); rules combine >=2 primitives"
    )

    terms = _strip_outer_parens(rule["condition_terms"])
    assert len(_split_depth0(terms, "or")) == 1, (
        f"{name}: top-level 'or' makes the condition presence-of-one, not co-occurrence"
    )

    counts = [_conjunct_min_primitives(c, string_names) for c in _split_depth0(terms, "and")]
    assert sum(counts) >= 2, (
        f"{name}: condition guarantees only {sum(counts)} co-occurring string primitive(s); "
        f"require two (e.g. `$a and $b`, `2 of them`, `all of them`)"
    )

    distinct = {_base_id(t) for t in terms if _STRING_REF_RE.match(t)}
    assert len(distinct) >= 2 or max(counts) >= 2, (
        f"{name}: every condition reference resolves to the same primitive "
        f"{sorted(distinct)}; two *distinct* primitives must co-occur"
    )


# Self-test of the checker: conditions with >= 2 strings DEFINED that are still
# presence-of-one (exactly what the old len(strings) floor waved through) must be
# rejected, and the accepted co-occurrence shapes must pass.
_DEGENERATE_CONDITIONS = [
    "$pw",  # single ref
    "any of them",  # presence-of-any-one
    "1 of them",  # same, spelled with a count
    "$pw or $mail",  # top-level or
    "($pw and $mail) or $tg",  # $tg alone satisfies it
    "$pw and $pw",  # one primitive, twice
    "$pw and #pw > 3",  # one primitive, referenced two ways
]
_COOCCURRING_CONDITIONS = [
    "$pw and $mail",
    "2 of them",
    "all of them",
    "2 of ($pw, $mail)",
    "$pw and ($mail or $tg)",
]


def _inline_rule(condition):
    src = f'rule t {{ strings: $pw = "x" $mail = "y" $tg = "z" condition: {condition} }}'
    [rule] = plyara.Plyara().parse_string(src)
    return rule, "<inline>"


@pytest.mark.parametrize("condition", _DEGENERATE_CONDITIONS)
def test_two_primitive_check_rejects_degenerate_conditions(condition):
    with pytest.raises(AssertionError):
        test_rule_combines_two_primitives(_inline_rule(condition))


@pytest.mark.parametrize("condition", _COOCCURRING_CONDITIONS)
def test_two_primitive_check_accepts_cooccurrence_shapes(condition):
    test_rule_combines_two_primitives(_inline_rule(condition))
