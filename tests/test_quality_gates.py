"""Tests for the weighted quality checks, Sigma conversion and the repair loop."""

import json
from unittest.mock import MagicMock, patch

import pytest

from api.services import llm, rule_generator, validators
from api.services.sigma_tools import HAVE_PYSIGMA, sigma_to_spl

SIGMA = """title: PowerShell Download Cradle
id: 0b5b3c8e-7d55-4c3a-9a1f-2f3f6c1d9e10
status: experimental
description: Detects PowerShell download cradles.
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\\\powershell.exe'
    CommandLine|contains: 'DownloadString'
  condition: selection
falsepositives:
  - Admin scripts that download updates from internal servers
level: high
tags:
  - attack.execution
  - attack.t1059.001
"""


def _mapping(tid="T1059.001", verified=True, evidence="powershell.exe in scenario"):
    return {
        "id": tid,
        "name": "PowerShell" if verified else "",
        "reference_verified": verified,
        "mapping_supported": verified and bool(evidence),
        "status": "supported" if verified else "unknown_id",
        "evidence": evidence,
        "tactics": ["execution"] if verified else [],
    }


def _candidate(**overrides):
    base = {
        "name": "PowerShell download cradle",
        "purpose": "Detects PowerShell downloading a payload.",
        "spl": 'index=sysmon EventCode=1 Image="*\\\\powershell.exe" CommandLine="*DownloadString*" '
        "| stats count by host user CommandLine",
        "sigma_rule": SIGMA,
        "severity": "high",
        "attack_mappings": [_mapping()],
        "benign_near_matches": ["Software deployment scripts fetching installers over HTTP"],
        "response_actions": ["Isolate the host", "Collect the script block log", "Reset credentials"],
    }
    base.update(overrides)
    return base


def _status(checks, name):
    return next(c.status for c in checks if c.name == name)


# --- scoring ---------------------------------------------------------------


def test_complete_rule_passes_and_scores_ready():
    checks = validators.run_all(_candidate())
    summary = validators.summarize(checks)
    assert summary["passed"], summary["failures"]
    assert summary["quality_score"] >= 85
    assert summary["quality_grade"] == "Ready"


def test_any_failure_caps_the_score_at_49():
    checks = validators.run_all(_candidate(spl="index=sysmon | delete"))
    summary = validators.summarize(checks)
    assert not summary["passed"]
    assert summary["quality_score"] <= 49


def test_skipped_checks_do_not_count():
    checks = [validators.Check("a", validators.PASS, "", 1), validators.Check("b", validators.SKIP, "", 5)]
    assert validators.quality_score(checks) == 100


def test_warnings_earn_half_weight():
    checks = [validators.Check("a", validators.PASS, "", 1), validators.Check("b", validators.WARN, "", 1)]
    assert validators.quality_score(checks) == 75


# --- individual gates --------------------------------------------------------


@pytest.mark.parametrize("command", ["delete", "outputlookup", "sendemail", "collect"])
def test_data_modifying_commands_fail(command):
    checks = validators.run_all(_candidate(spl=f"index=sysmon EventCode=1 | {command} foo"))
    assert _status(checks, "SPL structure") == validators.FAIL


def test_unbalanced_quotes_fail():
    checks = validators.run_all(_candidate(spl='index=sysmon Image="powershell.exe'))
    assert _status(checks, "SPL structure") == validators.FAIL


def test_match_everything_wildcard_warns():
    checks = validators.run_all(_candidate(spl='index=sysmon Image="*" | stats count by host'))
    assert _status(checks, "SPL structure") == validators.WARN


def test_unscoped_search_warns():
    checks = validators.run_all(_candidate(spl='EventCode=1 Image="x" | stats count by host'))
    assert _status(checks, "SPL scope") == validators.WARN


def test_invented_technique_fails():
    checks = validators.run_all(_candidate(attack_mappings=[_mapping("T9999", verified=False)]))
    assert _status(checks, "ATT&CK mapping") == validators.FAIL


def test_mapping_without_evidence_warns():
    checks = validators.run_all(_candidate(attack_mappings=[_mapping(evidence="")]))
    assert _status(checks, "ATT&CK mapping") == validators.WARN


def test_missing_sigma_is_a_warning_not_a_failure():
    checks = validators.run_all(_candidate(sigma_rule=""))
    assert _status(checks, "Output format") == validators.WARN
    assert _status(checks, "Sigma structure") == validators.SKIP
    assert validators.summarize(checks)["passed"]


def test_invalid_sigma_yaml_fails():
    checks = validators.run_all(_candidate(sigma_rule="title: [unclosed"))
    assert _status(checks, "Sigma structure") == validators.FAIL


def test_sigma_condition_referencing_undefined_selection_fails():
    broken = SIGMA.replace("condition: selection", "condition: selection and filter")
    checks = validators.run_all(_candidate(sigma_rule=broken))
    assert _status(checks, "Sigma condition") == validators.FAIL


def test_sigma_tags_must_match_the_mapping():
    other = SIGMA.replace("attack.t1059.001", "attack.t1003")
    checks = validators.run_all(_candidate(sigma_rule=other))
    assert _status(checks, "Sigma ATT&CK tags") == validators.FAIL


def test_wrong_tactic_tag_warns():
    other = SIGMA.replace("attack.execution", "attack.exfiltration")
    checks = validators.run_all(_candidate(sigma_rule=other))
    assert _status(checks, "ATT&CK tactics") == validators.WARN


def test_generic_false_positives_warn():
    checks = validators.run_all(_candidate(benign_near_matches=["none"]))
    assert _status(checks, "False positives") == validators.WARN


def test_splunk_checks_skip_without_splunk():
    checks = validators.run_all(_candidate(), run_test=True)
    assert _status(checks, "Splunk parser") == validators.SKIP
    assert _status(checks, "Test search") == validators.SKIP


def test_splunk_parser_rejection_fails():
    splunk = MagicMock()
    splunk.parse_spl.return_value = (False, "Unknown search command 'foo'.")
    checks = validators.run_all(_candidate(), splunk=splunk)
    assert _status(checks, "Splunk parser") == validators.FAIL


def test_noisy_test_search_warns():
    splunk = MagicMock()
    splunk.parse_spl.return_value = (True, "ok")
    splunk.test_search.return_value = {"result_count": 500, "sample": []}
    checks = validators.run_all(_candidate(), splunk=splunk, run_test=True, noisy_threshold=50)
    assert _status(checks, "Test search") == validators.WARN


@pytest.mark.skipif(not HAVE_PYSIGMA, reason="pySigma not installed")
def test_sigma_converts_to_spl():
    spl, err = sigma_to_spl(SIGMA)
    assert err is None
    assert "DownloadString" in spl


# --- the repair loop -------------------------------------------------------------


def _provider(text: str):
    mock = MagicMock()
    mock.status_code = 200
    mock.json.return_value = {"candidates": [{"content": {"parts": [{"text": text}]}}]}
    return mock


def _payload(spl: str) -> str:
    return json.dumps(
        {
            "candidates": [
                {
                    "name": "Cradle",
                    "spl": spl,
                    "attack_mappings": [{"id": "T1059.001", "evidence": "powershell"}],
                }
            ]
        }
    )


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setattr(llm, "GEMINI_API_KEY", "test-key-not-real")
    monkeypatch.setattr(llm, "LLM_RETRY_DELAY", 0)
    monkeypatch.setattr(rule_generator, "MAX_REPAIR_ATTEMPTS", 2)


def test_failing_candidate_is_sent_back_with_its_failures(configured):
    bad = _provider(_payload("index=sysmon EventCode=1 | delete"))
    good = _provider(_payload('index=sysmon EventCode=1 Image="*powershell.exe" | stats count by host'))

    with patch.object(llm.requests, "post", side_effect=[bad, good]) as post:
        result = rule_generator.generate_candidates("powershell download")

    assert post.call_count == 2
    repair_prompt = str(post.call_args_list[1].kwargs["json"])
    assert "delete" in repair_prompt and "quality checks" in repair_prompt
    assert result.candidates[0].validation["passed"]
    assert result.candidates[0].provenance["repair_attempts"] == 1


def test_repairs_are_bounded_and_failures_stay_visible(configured):
    bad = _provider(_payload("index=sysmon EventCode=1 | delete"))
    with patch.object(llm.requests, "post", return_value=bad) as post:
        result = rule_generator.generate_candidates("powershell download")

    assert post.call_count == 3  # first answer + 2 repairs
    assert result.ok
    assert not result.candidates[0].validation["passed"]
    assert result.candidates[0].validation["failures"]


def test_failed_repair_keeps_the_previous_answer(configured):
    import requests as requests_lib

    bad = _provider(_payload("index=sysmon EventCode=1 | delete"))
    with patch.object(llm.requests, "post", side_effect=[bad, requests_lib.Timeout()]):
        result = rule_generator.generate_candidates("powershell download")

    assert result.ok
    assert result.candidates[0].spl.endswith("delete")
    assert "Repair attempt 1 failed" in result.candidates[0].provenance["repair_note"]


def test_clean_first_answer_is_not_repaired(configured):
    good = _provider(_payload('index=sysmon EventCode=1 Image="*powershell.exe" | stats count by host'))
    with patch.object(llm.requests, "post", return_value=good) as post:
        result = rule_generator.generate_candidates("powershell download")
    assert post.call_count == 1
    assert result.candidates[0].provenance["repair_attempts"] == 0
    assert result.candidates[0].provenance["validation"]["quality_checks"] == "run"


def test_generation_is_grounded_in_reference_detections(configured):
    good = _provider(_payload('index=sysmon EventCode=1 Image="*powershell.exe" | stats count by host'))
    with patch.object(llm.requests, "post", return_value=good) as post:
        result = rule_generator.generate_candidates("powershell encoded command execution")

    grounding = result.candidates[0].provenance["grounding"]
    assert grounding["references"], "the bundled sample should yield at least one reference"
    assert "Reference detections" in str(post.call_args.kwargs["json"])
