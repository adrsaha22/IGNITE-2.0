"""Weighted quality gates for detection candidates.

Each check returns pass / warn / fail / skip and carries a weight. The weighted
result is the candidate's quality score (0-100). Failed checks are sent back to
the model for repair during generation.

Only genuine defects fail: malformed SPL, data-modifying commands, ATT&CK IDs
that do not exist, invalid Sigma, or Splunk's own parser rejecting the query.
Missing optional detail (no Sigma rule, too few response steps) is a warning,
so the score reflects it without forcing a repair loop.

Like the rest of IGNITE, these are checks on the rule's text and structure.
Passing them is not evidence that the rule detects the attack; only the
Splunk test search touches real data, and only when it is run.
"""

from __future__ import annotations

import fnmatch
import re
import uuid
from dataclasses import asdict, dataclass
from typing import Any

from api.services import attack
from api.services.sigma_tools import HAVE_PYSIGMA, parse_sigma, sigma_to_spl

PASS, WARN, FAIL, SKIP = "pass", "warn", "fail", "skip"

SEVERITIES = {"informational", "low", "medium", "high", "critical"}

DANGEROUS_COMMANDS = {
    "delete", "collect", "outputlookup", "outputcsv", "sendemail", "script", "run",
    "mcollect", "meventcollect", "tscollect", "sendalert", "dbxoutput",
}
KNOWN_COMMANDS = {
    "search", "where", "stats", "eventstats", "streamstats", "tstats", "table", "fields",
    "rename", "eval", "rex", "regex", "dedup", "sort", "head", "tail", "top", "rare",
    "timechart", "chart", "bin", "bucket", "lookup", "inputlookup", "join", "append",
    "appendpipe", "appendcols", "transaction", "fillnull", "mvexpand", "makemv", "spath",
    "convert", "fieldformat", "datamodel", "from", "multisearch", "union", "iplocation",
    "addinfo", "return", "format", "foreach", "map", "untable", "xyseries", "strcat",
    "makeresults", "metadata", "rest", "tojson", "fit", "apply", "anomalydetection",
    "cluster", "eventcount", "geostats", "nomv", "reverse", "selfjoin", "set", "sistats",
    "trendline", "xmlkv", "kv", "extract", "filldown", "accum", "delta", "autoregress",
    "mstats", "pivot", "outlier", "predict", "typer", "tags", "loadjob", "savedsearch",
    "mvcombine", "addtotals", "addcoltotals", "localize", "uniq", "abstract", "highlight",
}

SIGMA_LEVELS = {"informational", "low", "medium", "high", "critical"}
SIGMA_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}
GENERIC_FPS = {
    "none", "unknown", "n/a", "na", "legitimate activity", "legitimate use", "false positives",
}

GRADES = [(85, "Ready"), (70, "Good"), (50, "Needs work"), (0, "Poor")]

_TID_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_TACTIC_TAG = re.compile(r"^attack\.([a-z][a-z_-]+)$", re.IGNORECASE)
_MATCH_ALL = re.compile(r'([A-Za-z_][\w.]*)\s*=\s*"?\*"?(?=\s|\)|$)')


@dataclass
class Check:
    name: str
    status: str
    detail: str
    weight: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ------------------------------------------------------------------ SPL lint


def split_pipeline(spl: str) -> list[str]:
    """Split SPL on top-level pipes (ignores pipes in quotes and subsearches)."""
    segments: list[str] = []
    buf: list[str] = []
    depth, quote, prev = 0, None, ""
    for ch in spl:
        if quote:
            if ch == quote and prev != "\\":
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth = max(0, depth - 1)
        elif ch == "|" and depth == 0:
            segments.append("".join(buf))
            buf = []
            prev = ch
            continue
        buf.append(ch)
        prev = ch
    segments.append("".join(buf))
    return [s.strip() for s in segments]


def _balance_problems(spl: str) -> list[str]:
    problems: list[str] = []
    stack: list[str] = []
    quote, prev = None, ""
    pairs = {")": "(", "]": "["}
    for ch in spl:
        if quote:
            if ch == quote and prev != "\\":
                quote = None
        elif ch == '"':
            quote = ch
        elif ch in "([":
            stack.append(ch)
        elif ch in ")]":
            if not stack or stack.pop() != pairs[ch]:
                problems.append(f"Unbalanced '{ch}'.")
        prev = ch
    if quote:
        problems.append("Unclosed double quote.")
    if stack:
        problems.append(f"Unclosed '{stack[-1]}'.")
    if spl.count("`") % 2:
        problems.append("Unbalanced backtick (macro).")
    return problems


def lint_spl(spl: str) -> tuple[list[str], list[str]]:
    """Return (errors, warnings) for an SPL string without needing Splunk."""
    errors: list[str] = []
    warnings: list[str] = []
    if not spl or not spl.strip():
        return ["SPL query is empty."], []

    errors += _balance_problems(spl)
    segments = split_pipeline(spl)
    starts_with_pipe = spl.strip().startswith("|")
    commands = segments[1:]  # segment 0 is the base search ('' if the query starts with '|')

    if starts_with_pipe and segments and segments[0]:
        errors.append("Unexpected text before the leading pipe.")
    first_word = segments[0].split(" ", 1)[0].lower() if segments[0] else ""
    if not starts_with_pipe and first_word in KNOWN_COMMANDS - {"search"}:
        warnings.append(f"Query starts with '{first_word}' but has no leading pipe.")

    for seg in commands:
        if not seg:
            errors.append("Empty pipeline segment ('||' or a trailing pipe).")
            continue
        cmd = seg.split(None, 1)[0].lower()
        if cmd.startswith("`"):
            continue  # macro
        if cmd in DANGEROUS_COMMANDS:
            errors.append(f"Command '{cmd}' modifies data or sends output — not allowed in detections.")
        elif cmd not in KNOWN_COMMANDS:
            warnings.append(f"Unrecognised command '{cmd}' — verify it exists in your Splunk.")

    base = segments[0]
    for match in _MATCH_ALL.finditer(base):
        if match.group(1).lower() not in ("index", "source", "sourcetype"):
            warnings.append(f'`{match.group(1)}="*"` matches every value and filters nothing.')

    if len(segments) == 1 and not starts_with_pipe:
        warnings.append("No aggregation (stats/table) — alerts will contain raw events.")
    return errors, warnings


# -------------------------------------------------------------------- checks


def _tactic_key(value: str) -> str:
    return str(value).strip().lower().replace(" ", "-").replace("_", "-")


def check_structure(candidate: dict) -> Check:
    w = 1
    if not str(candidate.get("spl", "")).strip():
        return Check("Output format", FAIL, "The candidate has no SPL query.", w)
    missing = [
        label
        for key, label in (
            ("name", "name"),
            ("purpose", "purpose"),
            ("severity", "severity"),
            ("sigma_rule", "Sigma rule"),
            ("response_actions", "response actions"),
            ("benign_near_matches", "false positives"),
        )
        if not candidate.get(key)
    ]
    if missing:
        return Check("Output format", WARN, f"Missing: {', '.join(missing)}.", w)
    if str(candidate.get("severity", "")).lower() not in SEVERITIES:
        return Check("Output format", WARN, f"Severity must be one of {sorted(SEVERITIES)}.", w)
    return Check("Output format", PASS, "All expected fields are present.", w)


def check_mitre(candidate: dict) -> Check:
    """Uses the verified mappings already attached to the candidate."""
    w = 2
    mappings = candidate.get("attack_mappings") or []
    if not mappings:
        return Check("ATT&CK mapping", WARN, "No ATT&CK technique was mapped.", w)
    invalid = [m["id"] for m in mappings if not m.get("reference_verified")]
    if invalid:
        return Check(
            "ATT&CK mapping",
            FAIL,
            f"Not current techniques in the bundled ATT&CK dataset: {', '.join(invalid)}.",
            w,
        )
    unsupported = [m["id"] for m in mappings if not m.get("mapping_supported")]
    if unsupported:
        return Check(
            "ATT&CK mapping",
            WARN,
            f"IDs verified, but no evidence links this rule to {', '.join(unsupported)}.",
            w,
        )
    names = ", ".join(f"{m['id']} {m.get('name', '')}".strip() for m in mappings)
    return Check("ATT&CK mapping", PASS, f"Verified with evidence: {names}.", w)


def check_tactics(candidate: dict, doc: dict | None) -> Check:
    w = 0.5
    tags = [str(t) for t in (doc or {}).get("tags", []) or []]
    given = {
        _tactic_key(m.group(1)) for t in tags if (m := _TACTIC_TAG.match(t)) and not _TID_TAG.match(t)
    }
    expected = {
        _tactic_key(tactic)
        for m in candidate.get("attack_mappings") or []
        if m.get("reference_verified")
        for tactic in m.get("tactics", [])
    }
    if not expected:
        return Check("ATT&CK tactics", SKIP, "No verified technique to compare tactics against.", w)
    if not given:
        return Check("ATT&CK tactics", SKIP, "The Sigma rule has no attack.<tactic> tags.", w)
    wrong = given - expected
    if wrong:
        return Check(
            "ATT&CK tactics",
            WARN,
            f"Tactics {', '.join(sorted(wrong))} don't belong to the mapped techniques "
            f"(expected {', '.join(sorted(expected))}).",
            w,
        )
    return Check("ATT&CK tactics", PASS, f"Tactics match ATT&CK: {', '.join(sorted(given))}.", w)


def check_sigma_structure(doc: dict | None, errors: list[str]) -> Check:
    w = 2
    if errors:
        return Check("Sigma structure", FAIL, " ".join(errors), w)
    problems = []
    logsource = (doc or {}).get("logsource")
    if not isinstance(logsource, dict) or not any(
        k in logsource for k in ("product", "category", "service")
    ):
        problems.append("logsource needs at least one of product, category or service.")
    if doc.get("level") and str(doc["level"]).lower() not in SIGMA_LEVELS:
        problems.append(f"level '{doc['level']}' is not a valid Sigma level.")
    if doc.get("status") and str(doc["status"]).lower() not in SIGMA_STATUS:
        problems.append(f"status '{doc['status']}' is not a valid Sigma status.")
    if problems:
        return Check("Sigma structure", FAIL, " ".join(problems), w)
    return Check("Sigma structure", PASS, "Required Sigma sections are present and valid.", w)


def _condition_identifiers(condition: str) -> list[str]:
    condition = condition.split("|")[0]  # ignore legacy aggregation expressions
    tokens = re.findall(r"[A-Za-z0-9_*]+", condition)
    reserved = {"and", "or", "not", "of", "them", "all", "any"}
    return [t for t in tokens if t.lower() not in reserved and not t.isdigit()]


def check_sigma_condition(doc: dict) -> Check:
    w = 1
    detection = doc.get("detection")
    if not isinstance(detection, dict):
        return Check("Sigma condition", SKIP, "No detection block to check.", w)
    cond = detection.get("condition")
    conds = cond if isinstance(cond, list) else [cond] if cond else []
    if not conds:
        return Check("Sigma condition", FAIL, "detection.condition is missing.", w)
    names = [k for k in detection if k not in ("condition", "timeframe")]
    undefined = sorted(
        {
            ident
            for c in conds
            for ident in _condition_identifiers(str(c))
            if not any(fnmatch.fnmatch(n, ident) for n in names)
        }
    )
    if undefined:
        return Check(
            "Sigma condition", FAIL, f"Condition references undefined selections: {', '.join(undefined)}.", w
        )
    return Check("Sigma condition", PASS, f"Condition uses defined selections ({', '.join(names)}).", w)


def check_sigma_metadata(doc: dict) -> Check:
    w = 0.5
    try:
        uuid.UUID(str(doc.get("id", "")))
    except ValueError:
        return Check("Sigma metadata", WARN, "The Sigma rule id should be a UUID.", w)
    return Check("Sigma metadata", PASS, "The Sigma rule id is a valid UUID.", w)


def check_sigma_tags(candidate: dict, doc: dict) -> Check:
    w = 1
    sigma_ids = {
        m.group(1).upper() for t in doc.get("tags", []) or [] if (m := _TID_TAG.match(str(t)))
    }
    rule_ids = {str(m["id"]).upper() for m in candidate.get("attack_mappings") or []}
    if not sigma_ids:
        return Check("Sigma ATT&CK tags", WARN, "Sigma tags have no attack.tXXXX technique tags.", w)
    if rule_ids and not (rule_ids & sigma_ids):
        return Check(
            "Sigma ATT&CK tags",
            FAIL,
            f"Sigma tags {sorted(sigma_ids)} don't match the ATT&CK mapping {sorted(rule_ids)}.",
            w,
        )
    return Check("Sigma ATT&CK tags", PASS, "Sigma tags match the ATT&CK mapping.", w)


def check_sigma_conversion(candidate: dict) -> Check:
    w = 2
    if not HAVE_PYSIGMA:
        return Check("Sigma converts to SPL", SKIP, "pySigma is not installed on the backend.", w)
    spl, err = sigma_to_spl(candidate.get("sigma_rule", ""))
    if spl:
        return Check("Sigma converts to SPL", PASS, "The pySigma Splunk backend converted the rule.", w)
    return Check("Sigma converts to SPL", FAIL, f"pySigma could not convert the rule: {err}", w)


def check_spl_lint(candidate: dict) -> Check:
    w = 2
    errors, warnings = lint_spl(candidate.get("spl", ""))
    if errors:
        return Check("SPL structure", FAIL, " ".join(errors), w)
    if warnings:
        return Check("SPL structure", WARN, " ".join(warnings), w)
    return Check("SPL structure", PASS, "Structure looks correct.", w)


def check_spl_scope(candidate: dict) -> Check:
    w = 1
    spl = str(candidate.get("spl", "")).strip()
    base = split_pipeline(spl)[0] if spl else ""
    low = spl.lower()
    if spl.startswith("|") and any(c in low for c in ("tstats", "datamodel", "from ", "inputlookup", "mstats")):
        return Check("SPL scope", PASS, "Uses a data model or accelerated search.", w)
    if base.lstrip().startswith("`"):
        return Check("SPL scope", PASS, "The base search uses a macro.", w)
    if re.search(r"\bindex\s*=\s*\*", base, re.IGNORECASE):
        return Check("SPL scope", WARN, "index=* searches every index; set a specific index.", w)
    if re.search(r"\b(index|sourcetype|source)\s*=", base, re.IGNORECASE):
        return Check("SPL scope", PASS, "The base search is scoped by index, sourcetype or source.", w)
    return Check("SPL scope", WARN, "The base search has no index or sourcetype; it may be slow and noisy.", w)


def check_false_positives(candidate: dict) -> Check:
    w = 0.5
    fps = [str(f).strip() for f in candidate.get("benign_near_matches") or []]
    if not fps:
        return Check("False positives", WARN, "No benign near-matches were listed.", w)
    weak = [f for f in fps if f.lower().strip(". ") in GENERIC_FPS or len(f) < 15]
    if len(weak) == len(fps):
        return Check("False positives", WARN, "False positives are too generic to help tune the rule.", w)
    return Check("False positives", PASS, f"{len(fps)} specific false-positive scenario(s).", w)


def check_response(candidate: dict) -> Check:
    w = 0.5
    acts = [a for a in candidate.get("response_actions") or [] if str(a).strip()]
    if not acts:
        return Check("Response actions", WARN, "No response actions were listed.", w)
    if len(acts) < 3:
        return Check(
            "Response actions", WARN, f"Only {len(acts)} step(s); include triage, containment and recovery.", w
        )
    return Check("Response actions", PASS, f"{len(acts)} response steps.", w)


def check_splunk_parse(candidate: dict, splunk: Any) -> Check:
    w = 2
    if splunk is None:
        return Check("Splunk parser", SKIP, "Splunk is not connected.", w)
    try:
        ok, msg = splunk.parse_spl(candidate.get("spl", ""))
    except Exception as exc:
        # An unreachable Splunk is not a defect in the rule.
        return Check("Splunk parser", SKIP, f"Could not run the parser: {exc}", w)
    return Check("Splunk parser", PASS if ok else FAIL, msg, w)


def check_test_search(candidate: dict, splunk: Any, earliest: str, noisy_threshold: int) -> Check:
    w = 1
    if splunk is None:
        return Check("Test search", SKIP, "Splunk is not connected.", w)
    try:
        res = splunk.test_search(candidate.get("spl", ""), earliest=earliest)
    except Exception as exc:
        return Check("Test search", WARN, str(exc), w)
    n = res["result_count"]
    if n == 0:
        return Check(
            "Test search",
            PASS,
            f"0 results in {earliest}. Quiet on current data (or the data source isn't onboarded).",
            w,
        )
    if n >= noisy_threshold:
        return Check("Test search", WARN, f"{n} results in {earliest}. Likely too noisy; tune before going live.", w)
    return Check("Test search", PASS, f"{n} results in {earliest}. Review them before going live.", w)


def run_all(
    candidate: dict,
    splunk: Any = None,
    run_test: bool = False,
    test_earliest: str = "-24h",
    noisy_threshold: int = 50,
) -> list[Check]:
    checks = [check_structure(candidate), check_mitre(candidate)]

    sigma_text = str(candidate.get("sigma_rule") or "").strip()
    doc, errors = parse_sigma(sigma_text) if sigma_text else (None, [])
    checks.append(check_tactics(candidate, doc if not errors else None))

    if not sigma_text:
        checks.append(Check("Sigma structure", SKIP, "No Sigma rule was supplied.", 2))
    else:
        checks.append(check_sigma_structure(doc, errors))
        if doc is not None and not errors:
            checks += [
                check_sigma_condition(doc),
                check_sigma_metadata(doc),
                check_sigma_tags(candidate, doc),
                check_sigma_conversion(candidate),
            ]

    checks += [
        check_spl_lint(candidate),
        check_spl_scope(candidate),
        check_false_positives(candidate),
        check_response(candidate),
        check_splunk_parse(candidate, splunk),
    ]
    if run_test:
        checks.append(check_test_search(candidate, splunk, test_earliest, noisy_threshold))
    return checks


def failures(checks: list[Check]) -> list[str]:
    return [f"{c.name}: {c.detail}" for c in checks if c.status == FAIL]


# ------------------------------------------------------------------- scoring


def quality_score(checks: list[Check]) -> int:
    """Weighted score: pass = full weight, warn = half, fail = 0; skipped checks don't count.

    Any failure caps the score at 49, so a rule with a real defect can never
    read as "Good".
    """
    counted = [c for c in checks if c.status != SKIP]
    total = sum(c.weight for c in counted)
    if not total:
        return 0
    earned = sum(c.weight * (1 if c.status == PASS else 0.5 if c.status == WARN else 0) for c in counted)
    score = round(100 * earned / total)
    return min(score, 49) if any(c.status == FAIL for c in counted) else score


def grade(score: int) -> str:
    return next(label for threshold, label in GRADES if score >= threshold)


def summarize(checks: list[Check]) -> dict[str, Any]:
    """The validation block stored on a candidate or library rule."""
    score = quality_score(checks)
    splunk_check = next((c for c in checks if c.name == "Splunk parser"), None)
    return {
        "checks": [c.to_dict() for c in checks],
        "passed": not any(c.status == FAIL for c in checks),
        "quality_score": score,
        "quality_grade": grade(score),
        "failures": failures(checks),
        "splunk_parser": (
            "not_configured"
            if splunk_check is None or splunk_check.status == SKIP
            else "passed" if splunk_check.status == PASS else "failed"
        ),
    }


def attach_tactics(candidate: dict) -> None:
    """Ensure each verified mapping carries its dataset tactics (used by the tactic check)."""
    for mapping in candidate.get("attack_mappings") or []:
        if mapping.get("reference_verified") and not mapping.get("tactics"):
            technique = attack.load_dataset().get(str(mapping.get("id", "")))
            if technique:
                mapping["tactics"] = list(technique.tactics)
