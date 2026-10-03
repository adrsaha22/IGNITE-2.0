"""Tests for LLM-backed rule generation and ATT&CK verification.

The provider is mocked everywhere; no test needs an API key or network access.
These tests exist mainly to pin down what the system must never do: fabricate
rules, trust model-supplied validation, or silently fall back to templates.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from api.services import attack, llm, rule_generator
from api.services.rule_generator import parse_candidates, static_check


@pytest.fixture(autouse=True)
def configured(monkeypatch):
    monkeypatch.setattr(llm, "GEMINI_API_KEY", "test-key-not-real")
    monkeypatch.setattr(llm, "LLM_RETRY_DELAY", 0)


def _provider(text: str, status: int = 200):
    mock = MagicMock()
    mock.status_code = status
    mock.json.return_value = {"candidates": [{"content": {"parts": [{"text": text}]}}]}
    return mock


GOOD_RESPONSE = json.dumps(
    {
        "candidates": [
            {
                "name": "PowerShell download cradle",
                "purpose": "Detects in-memory payload download via PowerShell.",
                "spl": 'index=sysmon EventCode=1 Image="*powershell.exe*" CommandLine="*DownloadString*"',
                "hypothesis": "Attackers use DownloadString to stage payloads.",
                "behaviors": ["process creation", "remote download"],
                "attack_mappings": [
                    {"id": "T1059.001", "evidence": "Scenario shows powershell.exe execution"}
                ],
                "log_source": {"index": "sysmon", "fields": ["Image", "CommandLine"]},
                "assumptions": ["Sysmon EventCode 1 is collected"],
                "expected_positive_characteristics": ["CommandLine contains DownloadString"],
                "benign_near_matches": ["Admin scripts using Invoke-WebRequest for updates"],
                "blind_spots": ["Obfuscated or encoded command lines"],
                "required_telemetry": ["Sysmon process creation"],
                "references": ["MITRE ATT&CK T1059.001"],
            }
        ]
    }
)


# --- the provider is actually invoked ------------------------------------


def test_generation_calls_the_configured_provider():
    """Generation must reach the LLM, not a template lookup."""
    with patch.object(llm.requests, "post", return_value=_provider(GOOD_RESPONSE)) as post:
        result = rule_generator.generate_candidates("powershell download attack")

    assert post.call_count == 1
    assert result.ok
    assert result.candidates[0].spl


def test_generation_records_model_and_prompt_provenance():
    with patch.object(llm.requests, "post", return_value=_provider(GOOD_RESPONSE)):
        result = rule_generator.generate_candidates("powershell attack")

    provenance = result.candidates[0].provenance
    assert provenance["generator"] == "llm"
    assert provenance["provider"] == "google-gemini"
    assert provenance["model"]
    assert provenance["prompt_version"] == rule_generator.PROMPT_VERSION
    assert provenance["attack_dataset_version"]


def test_provenance_separates_validation_stages():
    """Each validation stage is reported independently, never conflated."""
    with patch.object(llm.requests, "post", return_value=_provider(GOOD_RESPONSE)):
        result = rule_generator.generate_candidates("powershell attack")

    validation = result.candidates[0].provenance["validation"]
    assert validation["static_checks"] == "run"
    assert validation["local_sample_test"] == "not_run"
    assert validation["splunk_syntax_validation"] == "not_configured"
    assert validation["real_telemetry_validation"] == "not_run"


def test_scenario_reaches_the_prompt():
    """The scenario must drive generation, not just select a template."""
    with patch.object(llm.requests, "post", return_value=_provider(GOOD_RESPONSE)) as post:
        rule_generator.generate_candidates("certutil staged a payload over HTTP")

    sent = str(post.call_args.kwargs["json"])
    assert "certutil staged a payload" in sent


# --- failures are explicit, never silently substituted -------------------


def test_missing_key_is_reported_not_faked(monkeypatch):
    monkeypatch.setattr(llm, "GEMINI_API_KEY", "")
    result = rule_generator.generate_candidates("attack")

    assert result.ok is False
    assert result.status == "not_configured"
    assert result.candidates == []


def test_provider_failure_returns_no_candidates():
    """A provider outage must not yield rules from anywhere else."""
    import requests as requests_lib

    with patch.object(llm.requests, "post", side_effect=requests_lib.Timeout()):
        result = rule_generator.generate_candidates("attack")

    assert result.ok is False
    assert result.status == "timeout"
    assert result.candidates == []


def test_rate_limit_is_distinct():
    mock = MagicMock()
    mock.status_code = 429
    with patch.object(llm.requests, "post", return_value=mock):
        result = rule_generator.generate_candidates("attack")

    assert result.status == "rate_limited"
    assert result.candidates == []


def test_malformed_json_yields_no_candidates():
    with patch.object(llm.requests, "post", return_value=_provider("this is not json")):
        result = rule_generator.generate_candidates("attack")

    assert result.ok is False
    assert result.status == "malformed"
    assert result.candidates == []
    assert "nothing has been substituted" in result.message


def test_no_fallback_rules_are_ever_returned():
    """The strongest guarantee: failure yields zero candidates, full stop."""
    failures = [_provider("garbage"), _provider(json.dumps({"candidates": []}))]
    for response in failures:
        with patch.object(llm.requests, "post", return_value=response):
            result = rule_generator.generate_candidates("powershell attack")
        assert result.candidates == []
        assert result.ok is False


# --- parsing --------------------------------------------------------------


def test_markdown_fence_is_tolerated():
    fenced = f"```json\n{GOOD_RESPONSE}\n```"
    candidates, error = parse_candidates(fenced)
    assert not error
    assert len(candidates) == 1


def test_candidate_without_spl_is_rejected():
    payload = json.dumps({"candidates": [{"name": "no query here"}]})
    candidates, error = parse_candidates(payload)
    assert candidates == []
    assert error


def test_candidate_count_is_bounded(monkeypatch):
    monkeypatch.setattr(rule_generator, "LLM_MAX_CANDIDATES", 2)
    many = json.dumps(
        {"candidates": [{"name": f"r{i}", "spl": f"index=a Image=\"{i}\""} for i in range(10)]}
    )
    with patch.object(llm.requests, "post", return_value=_provider(many)):
        result = rule_generator.generate_candidates("attack")

    assert len(result.candidates) == 2


# --- ATT&CK verification --------------------------------------------------


def test_invented_technique_id_is_not_trusted():
    """A hallucinated ID must be flagged, never presented as verified."""
    payload = json.dumps(
        {
            "candidates": [
                {
                    "name": "r",
                    "spl": 'index=a Image="x"',
                    "attack_mappings": [{"id": "T9999.999", "evidence": "made up"}],
                }
            ]
        }
    )
    with patch.object(llm.requests, "post", return_value=_provider(payload)):
        result = rule_generator.generate_candidates("attack")

    mapping = result.candidates[0].attack_mappings[0]
    assert mapping["reference_verified"] is False
    assert mapping["mapping_supported"] is False
    assert mapping["status"] == "unknown_id"


def test_technique_name_comes_from_the_dataset_not_the_model():
    """Even if the model supplies a wrong name, the canonical one is used."""
    payload = json.dumps(
        {
            "candidates": [
                {
                    "name": "r",
                    "spl": 'index=a Image="x"',
                    "attack_mappings": [
                        {"id": "T1059.001", "name": "Totally Wrong Name", "evidence": "e"}
                    ],
                }
            ]
        }
    )
    with patch.object(llm.requests, "post", return_value=_provider(payload)):
        result = rule_generator.generate_candidates("attack")

    assert result.candidates[0].attack_mappings[0]["name"] == "PowerShell"


def test_mapping_without_evidence_needs_review():
    """A real ID alone does not prove the detection covers the technique."""
    payload = json.dumps(
        {
            "candidates": [
                {
                    "name": "r",
                    "spl": 'index=a Image="x"',
                    "attack_mappings": [{"id": "T1059.001", "evidence": ""}],
                }
            ]
        }
    )
    with patch.object(llm.requests, "post", return_value=_provider(payload)):
        result = rule_generator.generate_candidates("attack")

    mapping = result.candidates[0].attack_mappings[0]
    assert mapping["reference_verified"] is True
    assert mapping["mapping_supported"] is False
    assert mapping["status"] == "needs_review"


def test_revoked_technique_is_rejected():
    """T1064 was revoked by MITRE and must not be presented as current."""
    verdict = attack.verify_mapping("T1064", "some evidence")
    assert verdict.reference_verified is False
    assert verdict.status == "unknown_id"


def test_dataset_excludes_revoked_techniques():
    provenance = attack.dataset_provenance()
    assert provenance["available"] is True
    assert provenance["revoked_excluded"] > 0
    assert provenance["version"]


def test_malformed_technique_id_is_reported():
    verdict = attack.verify_mapping("not-an-id", "e")
    assert verdict.status == "malformed_id"


def test_duplicate_mappings_are_collapsed():
    verdicts = attack.verify_mappings(
        [{"id": "T1059.001", "evidence": "a"}, {"id": "T1059.001", "evidence": "b"}]
    )
    assert len(verdicts) == 1


# --- static checks are ours, not the model's ------------------------------


def test_model_supplied_validation_claims_are_discarded():
    """A model claiming its rule is validated must not affect our output."""
    payload = json.dumps(
        {
            "candidates": [
                {
                    "name": "r",
                    "spl": 'index=a Image="*"',
                    "validated": True,
                    "score": 100,
                    "splunk_tested": True,
                    "production_ready": True,
                }
            ]
        }
    )
    with patch.object(llm.requests, "post", return_value=_provider(payload)):
        result = rule_generator.generate_candidates("attack")

    candidate = result.candidates[0]
    serialised = json.dumps(candidate.provenance)
    # The model's self-assessment is not carried anywhere.
    assert "production_ready" not in serialised
    assert candidate.provenance["validation"]["splunk_syntax_validation"] == "not_configured"
    # Our own check still flags the match-everything wildcard.
    assert any("matches every value" in f for f in candidate.static_findings)


def test_static_check_flags_match_everything_wildcard():
    findings = static_check('index=sysmon Image="*" EventCode=1')
    assert any("matches every value" in f for f in findings)


def test_static_check_flags_unbalanced_quotes_and_parens():
    assert any("quotes" in f for f in static_check('index=a Image="b'))
    assert any("parentheses" in f for f in static_check('index=a (Image="b"'))


def test_static_check_flags_missing_data_source():
    assert any("index, source or sourcetype" in f for f in static_check('Image="a"'))


def test_static_check_passes_a_reasonable_query():
    findings = static_check('index=sysmon EventCode=1 Image="*powershell.exe*"')
    assert findings == []


# --- no secret leakage ----------------------------------------------------


def test_api_key_never_appears_in_generation_output():
    with patch.object(llm.requests, "post", return_value=_provider(GOOD_RESPONSE)):
        result = rule_generator.generate_candidates("attack")

    blob = json.dumps(
        {
            "provenance": result.provenance,
            "candidates": [c.provenance for c in result.candidates],
            "message": result.message,
        }
    )
    assert "test-key-not-real" not in blob


def test_provenance_reports_the_model_that_answered(monkeypatch):
    """Failover can switch models mid-request.

    Provenance must name the model that actually produced the candidates, not
    the configured primary — otherwise the audit trail is wrong.
    """
    monkeypatch.setattr(llm, "GEMINI_MODEL", "exhausted-model")
    monkeypatch.setattr(llm, "LLM_FALLBACK_MODELS", ["exhausted-model", "fresh-model"])

    def fake_post(url, **kwargs):
        model = url.split("/models/")[1].split(":")[0]
        mock = MagicMock()
        if model == "exhausted-model":
            mock.status_code = 429
            mock.json.return_value = {}
        else:
            mock.status_code = 200
            mock.json.return_value = {
                "candidates": [{"content": {"parts": [{"text": GOOD_RESPONSE}]}}]
            }
        return mock

    with patch.object(llm.requests, "post", side_effect=fake_post):
        result = rule_generator.generate_candidates("powershell attack")

    assert result.ok
    assert result.candidates[0].provenance["model"] == "fresh-model"
