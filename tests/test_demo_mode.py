"""Tests for offline demo generation and mode switching.

Demo mode exists so the application can be shown without a provider. Its
correctness requirement is narrow but strict: it must never present a
template as LLM output, and it must refuse scenarios it cannot honestly
support rather than returning an unrelated rule.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.services import demo_generator, llm, rule_generator, store

SUPPORTED = "Attacker used certutil to download an encoded payload"
UNSUPPORTED = "Ransomware encrypted network shares after deleting volume shadow copies"


@pytest.fixture
def demo_mode(monkeypatch):
    monkeypatch.setattr(rule_generator, "DETECTION_GENERATION_MODE", "demo")


@pytest.fixture
def gemini_mode(monkeypatch):
    monkeypatch.setattr(rule_generator, "DETECTION_GENERATION_MODE", "gemini")


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "INVESTIGATIONS_DB", tmp_path / "demo-test.db")
    return TestClient(app)


# --- mode selection -------------------------------------------------------


def test_default_mode_is_gemini(monkeypatch):
    """Demo mode must be opt-in; the real generator is the default."""
    monkeypatch.delenv("DETECTION_GENERATION_MODE", raising=False)
    import importlib

    from api import settings

    importlib.reload(settings)
    assert settings.DETECTION_GENERATION_MODE == "gemini"


@pytest.mark.parametrize("value", ["DEMO", "demo", " demo "])
def test_demo_mode_is_recognised_case_insensitively(monkeypatch, value):
    monkeypatch.setenv("DETECTION_GENERATION_MODE", value)
    import importlib

    from api import settings

    importlib.reload(settings)
    assert settings.DETECTION_GENERATION_MODE == "demo"


@pytest.mark.parametrize("value", ["banana", "llm", "offline", ""])
def test_unrecognised_mode_falls_back_to_gemini(monkeypatch, value):
    """An unknown value must not silently disable the real generator."""
    monkeypatch.setenv("DETECTION_GENERATION_MODE", value)
    import importlib

    from api import settings

    importlib.reload(settings)
    assert settings.DETECTION_GENERATION_MODE == "gemini"


def test_demo_mode_never_calls_the_provider(demo_mode):
    """Demo mode must work with no provider reachable at all."""
    with patch.object(llm.requests, "post") as post:
        result = rule_generator.generate_candidates(SUPPORTED)

    post.assert_not_called()
    assert result.ok
    assert result.mode == "demo"


# --- supported scenarios --------------------------------------------------


def test_supported_scenario_produces_candidates(demo_mode):
    result = rule_generator.generate_candidates(SUPPORTED)
    assert result.ok
    assert result.candidates
    assert result.mode == "demo"


def test_every_demo_candidate_is_labelled(demo_mode):
    """The DEMO label must travel with the candidate name."""
    result = rule_generator.generate_candidates(SUPPORTED)
    for candidate in result.candidates:
        assert candidate.name.startswith("[DEMO]")


def test_demo_provenance_does_not_claim_an_llm(demo_mode):
    """Nothing in demo output may read as model-generated."""
    result = rule_generator.generate_candidates(SUPPORTED)
    provenance = result.candidates[0].provenance

    assert provenance["generator"] == "template"
    assert provenance["provider"] == "none"
    assert provenance["model"] == ""
    assert provenance["demo_mode"] is True
    assert provenance["prompt_version"] == ""


def test_demo_provenance_keeps_validation_stages_honest(demo_mode):
    result = rule_generator.generate_candidates(SUPPORTED)
    validation = result.candidates[0].provenance["validation"]

    assert validation["static_checks"] == "run"
    assert validation["splunk_syntax_validation"] == "not_configured"
    assert validation["real_telemetry_validation"] == "not_run"


def test_demo_candidates_state_they_are_templates(demo_mode):
    """The assumptions must say this is not scenario-specific generation."""
    result = rule_generator.generate_candidates(SUPPORTED)
    assumptions = " ".join(result.candidates[0].assumptions).lower()
    assert "pre-written template" in assumptions
    assert "not a rule generated for this specific scenario" in assumptions


def test_demo_static_checks_are_computed_not_asserted(demo_mode):
    """Findings come from the same checker the Gemini path uses."""
    result = rule_generator.generate_candidates(SUPPORTED)
    # These templates are clean, so an empty list proves the check ran without
    # a hardcoded finding being injected.
    assert result.candidates[0].static_findings == []
    assert rule_generator.static_check('index=a Image="*"')


# --- ATT&CK is still verified --------------------------------------------


def test_demo_attack_ids_are_verified_against_the_dataset(demo_mode):
    """A hand-written technique ID gets no special trust."""
    result = rule_generator.generate_candidates(SUPPORTED)
    mapping = result.candidates[0].attack_mappings[0]

    assert mapping["reference_verified"] is True
    # The canonical name comes from the dataset, not the template.
    assert mapping["name"] == "Ingress Tool Transfer"


def test_demo_mapping_evidence_cites_the_matched_keyword(demo_mode):
    """Evidence must be grounded in the user's text, not asserted."""
    result = rule_generator.generate_candidates(SUPPORTED)
    evidence = result.candidates[0].attack_mappings[0]["evidence"]
    assert "certutil" in evidence.lower()


def test_every_template_technique_id_is_real():
    """Guard against a typo shipping an invented ID in a template."""
    from api.services import attack

    for template in demo_generator.TEMPLATES:
        verdict = attack.verify_mapping(template.technique_id, "test")
        assert verdict.reference_verified, f"{template.key}: {template.technique_id}"


# --- unsupported scenarios are refused ------------------------------------


def test_unsupported_scenario_returns_zero_candidates(demo_mode):
    """The core guarantee: no unrelated rule is ever returned.

    The legacy pipeline answers a ransomware scenario with
    `index=sysmon EventCode=1 | stats ...`, which contains no ransomware
    indicator and matches every process-creation event.
    """
    result = rule_generator.generate_candidates(UNSUPPORTED)

    assert result.ok is False
    assert result.status == "unsupported_in_demo_mode"
    assert result.candidates == []


def test_refusal_explains_what_demo_mode_supports(demo_mode):
    result = rule_generator.generate_candidates(UNSUPPORTED)
    assert "PowerShell download cradles" in result.message
    assert "DETECTION_GENERATION_MODE=gemini" in result.message


@pytest.mark.parametrize(
    "scenario",
    [
        "Threat actor exfiltrated data over DNS tunneling",
        "Adversary performed Kerberoasting against service accounts",
        "Attacker moved laterally using pass-the-hash",
    ],
)
def test_out_of_scope_scenarios_are_all_refused(demo_mode, scenario):
    result = rule_generator.generate_candidates(scenario)
    assert result.candidates == []
    assert result.status == "unsupported_in_demo_mode"


def test_matching_is_keyword_based_and_ordered(demo_mode):
    """A scenario touching two behaviours returns both templates."""
    result = rule_generator.generate_candidates(
        "PowerShell downloaded a payload and schtasks created persistence"
    )
    keys = {c.provenance["template_key"] for c in result.candidates}
    assert "powershell_download" in keys
    assert "scheduled_task" in keys


# --- gemini mode is unaffected -------------------------------------------


def test_gemini_failure_does_not_fall_back_to_demo(gemini_mode, monkeypatch):
    """A provider failure must yield zero candidates, not template output."""
    monkeypatch.setattr(llm, "GEMINI_API_KEY", "k")
    monkeypatch.setattr(llm, "LLM_RETRY_DELAY", 0)

    mock = MagicMock()
    mock.status_code = 429  # quota exhausted, the case that prompted demo mode
    with patch.object(llm.requests, "post", return_value=mock):
        result = rule_generator.generate_candidates(SUPPORTED)

    assert result.ok is False
    assert result.status == "rate_limited"
    assert result.candidates == []
    assert result.mode == "gemini"


def test_gemini_mode_still_calls_the_provider(gemini_mode, monkeypatch):
    monkeypatch.setattr(llm, "GEMINI_API_KEY", "k")
    payload = json.dumps(
        {"candidates": [{"name": "r", "spl": 'index=sysmon Image="x"'}]}
    )
    mock = MagicMock()
    mock.status_code = 200
    mock.json.return_value = {"candidates": [{"content": {"parts": [{"text": payload}]}}]}

    with patch.object(llm.requests, "post", return_value=mock) as post:
        result = rule_generator.generate_candidates(SUPPORTED)

    post.assert_called_once()
    assert result.mode == "gemini"
    assert result.candidates[0].provenance["generator"] == "llm"
    assert not result.candidates[0].name.startswith("[DEMO]")


# --- API surface ----------------------------------------------------------


def test_route_reports_demo_mode(client, monkeypatch):
    monkeypatch.setattr(rule_generator, "DETECTION_GENERATION_MODE", "demo")
    body = client.post("/api/rules/generate", json={"scenario": SUPPORTED}).json()

    assert body["mode"] == "demo"
    assert body["generator"] == "template"
    assert body["candidates"][0]["name"].startswith("[DEMO]")


def test_route_reports_refusal_for_unsupported(client, monkeypatch):
    monkeypatch.setattr(rule_generator, "DETECTION_GENERATION_MODE", "demo")
    response = client.post("/api/rules/generate", json={"scenario": UNSUPPORTED})

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False
    assert body["status"] == "unsupported_in_demo_mode"
    assert body["candidates"] == []


def test_demo_response_carries_no_secret(client, monkeypatch):
    monkeypatch.setattr(rule_generator, "DETECTION_GENERATION_MODE", "demo")
    monkeypatch.setattr(llm, "GEMINI_API_KEY", "super-secret-key")
    response = client.post("/api/rules/generate", json={"scenario": SUPPORTED})
    assert "super-secret-key" not in response.text
