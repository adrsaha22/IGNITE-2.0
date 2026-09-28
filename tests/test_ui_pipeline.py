"""Tests for the UI pipeline adapter and result formatting.

Network and model calls are mocked; no test asserts on real model output.
"""

import json

import pytest

from ui import pipeline

POWERSHELL = (
    "Attacker used PowerShell to download a payload from GitHub via DownloadString "
    "and created a scheduled task with schtasks for persistence"
)
VAGUE = "lateral movement via unknown vector"


@pytest.fixture(scope="module")
def ps_analysis():
    return pipeline.run_analysis(POWERSHELL)


@pytest.fixture(scope="module")
def vague_analysis():
    return pipeline.run_analysis(VAGUE)


# --- shape -----------------------------------------------------------------


def test_analysis_has_expected_keys(ps_analysis):
    for key in (
        "description",
        "generated_at",
        "sigma",
        "mitre_id",
        "mitre_name",
        "entities",
        "ranked",
        "best",
        "autonomous",
    ):
        assert key in ps_analysis


def test_best_rule_is_highest_scoring(ps_analysis):
    scores = [r["score"] for r in ps_analysis["ranked"]]
    assert scores == sorted(scores, reverse=True)
    assert ps_analysis["best"]["score"] == scores[0]


def test_every_candidate_is_labelled(ps_analysis):
    for rule in ps_analysis["ranked"]:
        assert rule["origin"] in {
            pipeline.BEHAVIOR_LABEL,
            pipeline.MITRE_LABEL,
            pipeline.SIGMA_LABEL,
        }
        assert isinstance(rule["has_conditions"], bool)


def test_autonomous_engine_runs_for_known_attack(ps_analysis):
    auto = ps_analysis["autonomous"]
    assert auto["available"] is True
    assert auto["error"] is None
    assert auto["rule"].strip()
    assert auto["validation"]
    assert auto["quality"]


# --- MITRE naming is resolved, not invented --------------------------------


def test_technique_names_come_from_attack_data():
    assert pipeline.technique_name("T1059.001") == "PowerShell"
    assert pipeline.technique_name("T1105") == "Ingress Tool Transfer"


def test_unknown_technique_returns_empty_not_fabricated():
    assert pipeline.technique_name("T9999.999") == ""


def test_mapped_techniques_all_resolve(ps_analysis):
    auto = ps_analysis["autonomous"]
    for tid in auto["techniques"]:
        assert auto["technique_names"][tid], f"{tid} should resolve to a real name"


# --- empty / missing data renders cleanly ----------------------------------


def test_vague_input_yields_empty_entity_lists(vague_analysis):
    entities = vague_analysis["entities"]
    assert entities["tools"] == []
    assert entities["indicators"] == []


def test_vague_input_maps_no_techniques(vague_analysis):
    assert vague_analysis["autonomous"]["techniques"] == []


def test_unknown_mitre_id_is_reported(vague_analysis):
    assert vague_analysis["mitre_id"] == "Unknown"


# --- contradiction surfacing ----------------------------------------------


def test_valid_with_issues_is_surfaced(vague_analysis):
    """The validator marks the vague rule valid while listing an issue.

    That contradiction must appear in the warnings rather than being hidden
    behind the boolean flag.
    """
    validation = vague_analysis["autonomous"]["validation"]
    assert validation["valid"] is True
    assert validation["issues"], "expected the validator to list an issue here"

    warnings = pipeline.validation_warnings(vague_analysis)
    assert any("Marked valid" in w for w in warnings)


def test_conditionless_rule_is_flagged(vague_analysis):
    """A rule whose condition group is empty must be flagged as too broad."""
    assert vague_analysis["autonomous"]["rule_has_conditions"] is False
    warnings = pipeline.validation_warnings(vague_analysis)
    assert any("no field conditions" in w for w in warnings)


def test_empty_sigma_corpus_is_reported(ps_analysis):
    warnings = pipeline.validation_warnings(ps_analysis)
    assert any("data/sigma" in w for w in warnings)


def test_unknown_technique_is_warned(vague_analysis):
    warnings = pipeline.validation_warnings(vague_analysis)
    assert any("did not match any known keyword" in w for w in warnings)


# --- export ---------------------------------------------------------------


def test_export_is_json_serialisable(ps_analysis):
    payload = pipeline.export_payload(ps_analysis)
    json.dumps(payload)  # must not raise


def test_export_carries_current_analysis(ps_analysis):
    payload = pipeline.export_payload(ps_analysis)
    assert payload["metadata"]["attack_description"] == POWERSHELL
    assert payload["best_rule"]["spl"] == ps_analysis["best"]["rule"]
    assert payload["best_rule"]["score"] == ps_analysis["best"]["score"]


def test_export_does_not_claim_external_validation(ps_analysis):
    payload = pipeline.export_payload(ps_analysis)
    assert "not validated" in payload["metadata"]["rule_status"]


def test_export_includes_warnings(vague_analysis):
    payload = pipeline.export_payload(vague_analysis)
    assert payload["warnings"]


def test_exports_from_two_runs_do_not_share_results(ps_analysis, vague_analysis):
    """Guards against a stale result being exported for a different input."""
    a = pipeline.export_payload(ps_analysis)
    b = pipeline.export_payload(vague_analysis)
    assert a["metadata"]["attack_description"] != b["metadata"]["attack_description"]
    assert a["best_rule"]["spl"] != b["best_rule"]["spl"]


def test_export_technique_names_are_paired(ps_analysis):
    payload = pipeline.export_payload(ps_analysis)
    for entry in payload["mitre"]["mapped_techniques"]:
        assert entry["id"].startswith("T")
        assert entry["name"]


# --- autonomous engine failure is contained -------------------------------


def test_engine_failure_does_not_break_analysis(monkeypatch):
    """A crash inside the autonomous engine must not lose the Sigma/entity work."""
    monkeypatch.setattr(
        pipeline,
        "map_attack_to_techniques",
        lambda _: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    result = pipeline.run_analysis(POWERSHELL)

    assert result["autonomous"]["available"] is False
    assert "boom" in result["autonomous"]["error"]
    # The rest of the pipeline still produced usable output.
    assert result["ranked"]
    assert result["entities"]["tools"]


def test_engine_failure_still_exports(monkeypatch):
    monkeypatch.setattr(
        pipeline,
        "map_attack_to_techniques",
        lambda _: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    payload = pipeline.export_payload(pipeline.run_analysis(POWERSHELL))
    json.dumps(payload)
    assert payload["autonomous_engine"]["available"] is False
