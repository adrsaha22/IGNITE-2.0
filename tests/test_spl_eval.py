"""Tests for the local SPL subset evaluator.

The evaluator's value depends entirely on it being honest: it must match what
it claims to match, and refuse — loudly — what it cannot interpret.
"""

import pytest

from api.services import spl_eval
from api.services.spl_eval import MatchOutcome, evaluate, parse_rule

PS_RULE = 'index=sysmon EventCode=1 Image="*powershell.exe*" CommandLine="*DownloadString*"'


def _event(**fields):
    return dict(fields)


# --- matching ------------------------------------------------------------


def test_matching_event_is_reported_as_a_match():
    events = [
        _event(
            EventCode=1,
            Image="C:\\Windows\\powershell.exe",
            CommandLine="powershell -c IEX(New-Object Net.WebClient).DownloadString('x')",
        )
    ]
    report = evaluate(PS_RULE, events)
    assert report.supported
    assert report.results[0].outcome is MatchOutcome.MATCH


def test_non_matching_event_is_reported_as_no_match():
    events = [
        _event(EventCode=1, Image="C:\\Windows\\notepad.exe", CommandLine="notepad readme.txt")
    ]
    report = evaluate(PS_RULE, events)
    assert report.results[0].outcome is MatchOutcome.NO_MATCH
    assert "did not match" in report.results[0].reason


def test_wildcards_match_case_insensitively():
    events = [
        _event(EventCode=1, Image="C:\\WINDOWS\\POWERSHELL.EXE", CommandLine="X downloadstring Y")
    ]
    assert evaluate(PS_RULE, events).results[0].outcome is MatchOutcome.MATCH


def test_exact_value_without_wildcard_must_match_fully():
    report = evaluate('EventCode=1', [_event(EventCode=1), _event(EventCode=11)])
    assert report.results[0].outcome is MatchOutcome.MATCH
    assert report.results[1].outcome is MatchOutcome.NO_MATCH


def test_negation_operator_is_applied():
    report = evaluate('Image!="*powershell.exe*"', [
        _event(Image="C:\\notepad.exe"),
        _event(Image="C:\\powershell.exe"),
    ])
    assert report.results[0].outcome is MatchOutcome.MATCH
    assert report.results[1].outcome is MatchOutcome.NO_MATCH


@pytest.mark.parametrize(
    "rule,value,expected",
    [
        ("Count>5", 10, MatchOutcome.MATCH),
        ("Count>5", 3, MatchOutcome.NO_MATCH),
        ("Count>=5", 5, MatchOutcome.MATCH),
        ("Count<5", 3, MatchOutcome.MATCH),
        ("Count<=5", 6, MatchOutcome.NO_MATCH),
    ],
)
def test_numeric_comparisons(rule, value, expected):
    assert evaluate(rule, [_event(Count=value)]).results[0].outcome is expected


def test_non_numeric_value_fails_a_numeric_comparison():
    """A string operand must not silently satisfy a numeric test."""
    assert evaluate("Count>5", [_event(Count="abc")]).results[0].outcome is MatchOutcome.NO_MATCH


# --- missing fields ------------------------------------------------------


def test_missing_field_is_reported_separately_from_a_mismatch():
    report = evaluate(PS_RULE, [_event(EventCode=1, Image="C:\\powershell.exe")])
    result = report.results[0]
    assert result.outcome is MatchOutcome.NO_MATCH
    assert "CommandLine" in result.missing_fields
    assert "Missing field" in result.reason


def test_missing_field_observation_is_flagged():
    report = evaluate("Image=x", [_event(Other="y")])
    observation = report.results[0].observations[0]
    assert observation.missing is True
    assert observation.actual is None


def test_field_values_are_reported_for_explanation():
    report = evaluate('Image="*powershell*"', [_event(Image="C:\\powershell.exe")])
    observation = report.results[0].observations[0]
    assert observation.actual == "C:\\powershell.exe"
    assert observation.expected == "*powershell*"
    assert observation.matched is True


# --- unsupported constructs ---------------------------------------------


def test_transforming_commands_are_reported_not_applied():
    report = evaluate(f"{PS_RULE} | stats count by host", [_event(EventCode=1)])
    assert any("stats" in note for note in report.unsupported)


def test_subsearch_is_reported_as_unsupported():
    report = evaluate('index=a [ search index=b ] Image=x', [_event(Image="x")])
    assert any("subsearch" in note for note in report.unsupported)


def test_macro_is_reported_as_unsupported():
    report = evaluate('`my_macro` Image=x', [_event(Image="x")])
    assert any("macro" in note for note in report.unsupported)


def test_in_operator_is_reported_as_unsupported():
    report = evaluate('Image IN ("a","b") EventCode=1', [_event(EventCode=1)])
    assert any("IN operator" in note for note in report.unsupported)


def test_or_alternatives_are_evaluated():
    """A top-level OR must satisfy the group if any alternative matches."""
    report = evaluate('Image="a" OR Image="b"', [_event(Image="a"), _event(Image="c")])
    assert report.results[0].outcome is MatchOutcome.MATCH
    assert report.results[1].outcome is MatchOutcome.NO_MATCH


def test_and_of_or_group_is_evaluated():
    """The common generated shape: a filter AND a group of OR'd indicators."""
    rule = 'EventCode=1 (CommandLine="*IEX*" OR CommandLine="*DownloadString*")'

    matches = evaluate(rule, [_event(EventCode=1, CommandLine="x DownloadString y")])
    assert matches.results[0].outcome is MatchOutcome.MATCH

    # The AND term still has to hold.
    wrong_event_code = evaluate(rule, [_event(EventCode=4688, CommandLine="IEX")])
    assert wrong_event_code.results[0].outcome is MatchOutcome.NO_MATCH

    # None of the OR alternatives present.
    no_indicator = evaluate(rule, [_event(EventCode=1, CommandLine="notepad")])
    assert no_indicator.results[0].outcome is MatchOutcome.NO_MATCH


def test_not_is_still_flagged_as_unmodelled():
    report = evaluate('Image="a" NOT Image="b"', [_event(Image="a")])
    assert any("NOT" in note for note in report.unsupported)


def test_rule_with_no_testable_conditions_is_unsupported():
    report = evaluate("index=sysmon | stats count", [_event(EventCode=1)])
    assert report.supported is False
    assert report.error
    assert report.results == []


def test_source_selectors_are_not_applied_to_events():
    """index=/sourcetype= choose the data source, not fields on an event."""
    report = evaluate('index=sysmon EventCode=1', [_event(EventCode=1)])
    assert report.results[0].outcome is MatchOutcome.MATCH
    assert "index" not in report.referenced_fields


# --- determinism and bounds ---------------------------------------------


def test_evaluation_is_deterministic():
    events = [_event(EventCode=1, Image="C:\\powershell.exe", CommandLine="DownloadString")]
    first = evaluate(PS_RULE, events)
    second = evaluate(PS_RULE, events)
    assert [r.outcome for r in first.results] == [r.outcome for r in second.results]


def test_event_count_is_bounded():
    events = [_event(EventCode=1) for _ in range(500)]
    report = evaluate("EventCode=1", events)
    assert len(report.results) <= spl_eval.MAX_EVENTS


def test_oversized_query_is_refused():
    report = evaluate("Image=x " * 20000, [_event(Image="x")])
    assert report.supported is False


def test_non_dict_events_are_skipped():
    report = evaluate("EventCode=1", [_event(EventCode=1), "not an event", None])
    assert len(report.results) == 1


def test_empty_event_list_yields_no_results():
    report = evaluate(PS_RULE, [])
    assert report.supported is True
    assert report.results == []


# --- referenced fields ---------------------------------------------------


def test_referenced_fields_are_reported():
    report = evaluate(PS_RULE, [_event(EventCode=1)])
    assert set(report.referenced_fields) == {"EventCode", "Image", "CommandLine"}


# --- parse_rule ----------------------------------------------------------


def test_parse_rule_returns_and_groups():
    """Bare conditions each become their own single-alternative AND group."""
    groups, _, _ = parse_rule('Image="a" EventCode=1')
    assert len(groups) == 2
    assert groups[0][0].field == "Image"
    assert groups[0][0].expected == "a"


def test_parse_rule_groups_or_alternatives_together():
    groups, _, _ = parse_rule('EventCode=1 (Image="a" OR Image="b")')
    # One AND term, plus one group holding both alternatives.
    assert len(groups) == 2
    assert any(len(group) == 2 for group in groups)


# --- sample sets ---------------------------------------------------------


def test_sample_sets_are_well_formed():
    for key, sample in spl_eval.SAMPLE_EVENT_SETS.items():
        assert sample["label"]
        assert sample["description"]
        assert sample["events"], f"{key} has no events"
        for event in sample["events"]:
            assert event["_expect"] in ("match", "no_match")


def test_powershell_samples_behave_as_labelled():
    """The bundled samples must behave as their labels claim.

    The `match` events cover different download cradles (DownloadString and
    Invoke-WebRequest), so they are checked against the pattern each one
    actually represents rather than a single narrow rule.
    """
    events = {
        event["_id"]: event
        for event in spl_eval.SAMPLE_EVENT_SETS["powershell_download"]["events"]
    }

    cases = [
        ("ps-match-1", 'Image="*powershell.exe*" CommandLine="*DownloadString*"'),
        ("ps-match-2", 'Image="*powershell.exe*" CommandLine="*Invoke-WebRequest*"'),
    ]
    for event_id, rule in cases:
        report = evaluate(rule, [events[event_id]])
        assert report.results[0].outcome is MatchOutcome.MATCH, event_id

    # The benign events must not match a download-cradle rule.
    benign = [event for event in events.values() if event["_expect"] == "no_match"]
    report = evaluate('Image="*powershell.exe*" CommandLine="*Download*"', benign)
    assert all(result.outcome is MatchOutcome.NO_MATCH for result in report.results)


def test_external_validator_is_a_seam_not_a_fake():
    validator = spl_eval.ExternalValidator()
    assert validator.available is False
    with pytest.raises(NotImplementedError):
        validator.validate("index=a")


# --- unevaluable rules must not produce a verdict ------------------------


def test_not_makes_a_rule_unevaluable_rather_than_wrong():
    """Regression: `Image="x" NOT Image="x"` previously returned `match`.

    NOT changes which events match, so reporting match/no_match without
    modelling it would be confidently incorrect.
    """
    report = evaluate('Image="x" NOT Image="x"', [_event(Image="x")])
    assert report.results[0].outcome is MatchOutcome.UNEVALUABLE
    assert "NOT" in report.results[0].reason


def test_unevaluable_is_reported_for_every_event():
    report = evaluate('Image="a" NOT User="b"', [_event(Image="a"), _event(Image="z")])
    assert all(r.outcome is MatchOutcome.UNEVALUABLE for r in report.results)


def test_unevaluable_is_neither_a_match_nor_a_no_match():
    """An unevaluable event must not be counted as a pass or a failure."""
    report = evaluate('Image="a" NOT User="b"', [_event(Image="a")])
    outcomes = [r.outcome for r in report.results]
    assert MatchOutcome.MATCH not in outcomes
    assert MatchOutcome.NO_MATCH not in outcomes


def test_rules_without_not_still_produce_verdicts():
    report = evaluate('EventCode=1 (Image="a" OR Image="b")', [_event(EventCode=1, Image="b")])
    assert report.results[0].outcome is MatchOutcome.MATCH


# --- multivalue fields ----------------------------------------------------


def test_multivalue_field_matches_if_any_value_matches():
    """Splunk treats a multivalue field as matching when any value matches."""
    report = evaluate('Image="a"', [_event(Image=["a", "b"])])
    assert report.results[0].outcome is MatchOutcome.MATCH


def test_multivalue_field_no_match_when_no_value_matches():
    report = evaluate('Image="z"', [_event(Image=["a", "b"])])
    assert report.results[0].outcome is MatchOutcome.NO_MATCH


def test_multivalue_negation_requires_no_value_to_match():
    assert (
        evaluate('Image!="a"', [_event(Image=["a", "b"])]).results[0].outcome
        is MatchOutcome.NO_MATCH
    )
    assert (
        evaluate('Image!="z"', [_event(Image=["a", "b"])]).results[0].outcome
        is MatchOutcome.MATCH
    )


def test_multivalue_wildcard_matches_any_member():
    report = evaluate('Image="*powershell*"', [_event(Image=["cmd.exe", "powershell.exe"])])
    assert report.results[0].outcome is MatchOutcome.MATCH
