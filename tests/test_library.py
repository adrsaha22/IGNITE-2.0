"""Tests for the rule library, review workflow, audit log, exports and coverage.

Governance rules are enforced by the backend, so they are tested at the API.
"""

import sqlite3
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from api import settings
from api.main import app
from api.services import library, splunk_client, store

GOOD_SPL = 'index=sysmon EventCode=1 Image="*\\\\powershell.exe" CommandLine="*DownloadString*" | stats count by host'

CANDIDATE = {
    "name": "PowerShell download cradle",
    "purpose": "Detects PowerShell downloading a remote payload.",
    "spl": GOOD_SPL,
    "severity": "high",
    "attack_mappings": [{"id": "T1059.001", "evidence": "powershell.exe in the scenario"}],
    "benign_near_matches": ["Software deployment scripts fetching installers"],
    "response_actions": ["Isolate the host", "Pull the script block log", "Reset the user's credentials"],
    # A client-supplied score must be ignored.
    "validation": {"quality_score": 100, "passed": True},
}

FAILING = {**CANDIDATE, "name": "Broken rule", "spl": "index=sysmon EventCode=1 | delete"}


@pytest.fixture
def client():
    return TestClient(app)


def _save(client, candidate=CANDIDATE):
    response = client.post("/api/library/rules", json={"candidate": candidate, "scenario": "ps cradle"})
    assert response.status_code == 201, response.text
    return response.json()


# --- saving -------------------------------------------------------------------


def test_saved_candidate_is_a_draft_rescored_by_the_server(client):
    rule = _save(client, FAILING)
    assert rule["status"] == "draft"
    assert rule["version"] == 1
    assert rule["validation"]["passed"] is False
    assert rule["validation"]["quality_score"] <= 49


def test_attack_mappings_are_reverified_on_save(client):
    rule = _save(client, {**CANDIDATE, "attack_mappings": [{"id": "T9999.999", "evidence": "x"}]})
    assert rule["attack_mappings"][0]["reference_verified"] is False


def test_candidate_without_spl_is_rejected(client):
    response = client.post("/api/library/rules", json={"candidate": {"name": "x"}})
    assert response.status_code == 422


def test_listing_filters_by_status(client):
    _save(client)
    assert len(client.get("/api/library/rules").json()) == 1
    assert client.get("/api/library/rules?status=approved").json() == []
    assert client.get("/api/library/rules?status=bogus").status_code == 422


# --- review workflow ---------------------------------------------------------


def test_clean_rule_can_be_approved(client):
    rule = _save(client)
    response = client.post(f"/api/library/rules/{rule['id']}/review", json={"decision": "approve"})
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "approved"
    assert body["review"]["override"] is False
    assert body["review"]["by"]


def test_failing_rule_needs_an_override_justification(client):
    rule = _save(client, FAILING)
    response = client.post(f"/api/library/rules/{rule['id']}/review", json={"decision": "approve"})
    assert response.status_code == 422
    assert "override" in response.json()["detail"]

    response = client.post(
        f"/api/library/rules/{rule['id']}/review",
        json={"decision": "approve", "override_justification": "Accepted for a contained lab test only."},
    )
    assert response.status_code == 200
    assert response.json()["review"]["override"] is True
    audit = client.get("/api/audit?action=approved").json()
    assert audit[0]["detail"].startswith("OVERRIDE")


def test_reject_needs_a_note(client):
    rule = _save(client)
    assert client.post(f"/api/library/rules/{rule['id']}/review", json={"decision": "reject"}).status_code == 422
    response = client.post(
        f"/api/library/rules/{rule['id']}/review",
        json={"decision": "reject", "note": "Duplicates an existing detection."},
    )
    assert response.json()["status"] == "rejected"


def test_editing_an_approved_rule_returns_it_to_draft(client):
    rule = _save(client)
    client.post(f"/api/library/rules/{rule['id']}/review", json={"decision": "approve"})
    response = client.patch(
        f"/api/library/rules/{rule['id']}",
        json={"expected_version": 1, "severity": "critical", "note": "raise severity"},
    )
    body = response.json()
    assert body["status"] == "draft"
    assert body["version"] == 2
    assert body["review"] is None
    assert [v["version"] for v in body["versions"]] == [2, 1]


def test_edit_reruns_the_checks(client):
    rule = _save(client)
    body = client.patch(
        f"/api/library/rules/{rule['id']}",
        json={"expected_version": 1, "spl": "index=sysmon | outputlookup x.csv"},
    ).json()
    assert body["validation"]["passed"] is False


def test_stale_edit_is_rejected(client):
    rule = _save(client)
    client.patch(f"/api/library/rules/{rule['id']}", json={"expected_version": 1, "severity": "low"})
    response = client.patch(f"/api/library/rules/{rule['id']}", json={"expected_version": 1, "severity": "high"})
    assert response.status_code == 409


def test_previous_versions_are_retrievable(client):
    rule = _save(client)
    client.patch(f"/api/library/rules/{rule['id']}", json={"expected_version": 1, "title": "Renamed"})
    old = client.get(f"/api/library/rules/{rule['id']}/versions/1").json()
    assert old["title"] == CANDIDATE["name"]


# --- deployment --------------------------------------------------------------------


def test_only_approved_rules_deploy(client, monkeypatch):
    monkeypatch.setattr(settings, "SPLUNK_URL", "https://splunk.example:8089")
    monkeypatch.setattr(settings, "SPLUNK_TOKEN", "t")
    rule = _save(client)
    response = client.post(f"/api/library/rules/{rule['id']}/deploy", json={"mode": "shadow"})
    assert response.status_code == 409


def test_deploy_requires_splunk(client):
    rule = _save(client)
    client.post(f"/api/library/rules/{rule['id']}/review", json={"decision": "approve"})
    response = client.post(f"/api/library/rules/{rule['id']}/deploy", json={"mode": "shadow"})
    assert response.status_code == 409
    assert "not configured" in response.json()["detail"]


def test_shadow_deploy_records_the_deployment(client, monkeypatch):
    monkeypatch.setattr(settings, "SPLUNK_URL", "https://splunk.example:8089")
    monkeypatch.setattr(settings, "SPLUNK_TOKEN", "secret-token")
    rule = _save(client)
    client.post(f"/api/library/rules/{rule['id']}/review", json={"decision": "approve"})

    created = MagicMock(status_code=201)
    with patch.object(splunk_client.requests.Session, "request", return_value=created) as request:
        response = client.post(
            f"/api/library/rules/{rule['id']}/deploy", json={"mode": "shadow", "actions": "email"}
        )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["deployment"]["mode"] == "shadow"
    sent = request.call_args.kwargs["data"]
    assert sent["actions"] == ""  # alert actions fire only in live mode
    assert sent["is_scheduled"] == 1
    assert "secret-token" not in response.text


def test_editing_a_deployed_rule_marks_the_deployment_stale(client, monkeypatch):
    monkeypatch.setattr(settings, "SPLUNK_URL", "https://splunk.example:8089")
    monkeypatch.setattr(settings, "SPLUNK_TOKEN", "t")
    rule = _save(client)
    client.post(f"/api/library/rules/{rule['id']}/review", json={"decision": "approve"})
    with patch.object(splunk_client.requests.Session, "request", return_value=MagicMock(status_code=201)):
        client.post(f"/api/library/rules/{rule['id']}/deploy", json={"mode": "disabled"})
    with patch.object(splunk_client.requests.Session, "request", return_value=MagicMock(status_code=200)):
        body = client.patch(
            f"/api/library/rules/{rule['id']}", json={"expected_version": 1, "severity": "low"}
        ).json()
    assert body["deployment"]["stale"] is True


@pytest.mark.parametrize("payload", [{"mode": "yolo"}, {"mode": "live", "cron": "rm -rf"}, {"mode": "live", "earliest": "yesterday"}])
def test_deploy_input_is_validated(client, payload):
    rule = _save(client)
    assert client.post(f"/api/library/rules/{rule['id']}/deploy", json=payload).status_code == 422


# --- audit log ---------------------------------------------------------------------


def test_every_action_is_audited(client):
    rule = _save(client)
    client.patch(f"/api/library/rules/{rule['id']}", json={"expected_version": 1, "severity": "low"})
    client.post(f"/api/library/rules/{rule['id']}/review", json={"decision": "approve"})
    client.get(f"/api/library/rules/{rule['id']}/export/markdown")
    client.delete(f"/api/library/rules/{rule['id']}")
    actions = [entry["action"] for entry in client.get("/api/audit").json()]
    assert actions == ["deleted", "exported", "approved", "edited", "saved"]


def test_audit_log_is_append_only(client):
    _save(client)
    with sqlite3.connect(store.INVESTIGATIONS_DB) as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM audit_log")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE audit_log SET actor = 'someone else'")


def test_audit_csv_export(client):
    _save(client)
    response = client.get("/api/audit/export.csv")
    assert response.status_code == 200
    assert response.text.splitlines()[0] == "seq,at,actor,action,rule_id,rule_title,detail"
    assert "saved" in response.text


def test_operator_name_is_recorded(client, monkeypatch):
    monkeypatch.setattr(settings, "OPERATOR_NAME", "analyst.one")
    _save(client)
    assert client.get("/api/audit").json()[0]["actor"] == "analyst.one"


# --- exports -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fmt, expected",
    [
        ("contentctl", "mitre_attack_id"),
        ("savedsearches", "[IGNITE - PowerShell download cradle]"),
        ("markdown", "## Quality checks"),
        ("json", '"attack_mappings"'),
    ],
)
def test_exports(client, fmt, expected):
    rule = _save(client)
    response = client.get(f"/api/library/rules/{rule['id']}/export/{fmt}")
    assert response.status_code == 200
    assert expected in response.text
    assert "attachment" in response.headers["content-disposition"]


def test_unknown_export_format(client):
    rule = _save(client)
    assert client.get(f"/api/library/rules/{rule['id']}/export/pdf").status_code == 422


# --- coverage ----------------------------------------------------------------------


def _technique(coverage, tid):
    for tactic in coverage["tactics"]:
        for technique in tactic["techniques"]:
            if technique["id"] == tid:
                return technique
    raise AssertionError(f"{tid} not in matrix")


def test_coverage_reflects_rule_lifecycle(client):
    rule = _save(client)
    assert _technique(client.get("/api/coverage").json(), "T1059")["level"] == "draft"

    client.post(f"/api/library/rules/{rule['id']}/review", json={"decision": "approve"})
    coverage = client.get("/api/coverage").json()
    assert _technique(coverage, "T1059")["level"] == "approved"
    assert coverage["summary"]["covered"] >= 1


def test_rejected_rules_do_not_count_as_coverage(client):
    rule = _save(client)
    client.post(f"/api/library/rules/{rule['id']}/review", json={"decision": "reject", "note": "not needed"})
    level = _technique(client.get("/api/coverage").json(), "T1059")["level"]
    assert level in (None, "reference")


def test_coverage_matrix_has_attack_tactics(client):
    coverage = client.get("/api/coverage").json()
    keys = [t["key"] for t in coverage["tactics"]]
    assert keys[:2] == ["reconnaissance", "resource-development"]
    assert coverage["summary"]["techniques"] > 150


# --- approved rules feed retrieval ---------------------------------------------------


def test_approved_rules_become_references(client):
    rule = _save(client)
    assert library.approved_examples() == []
    client.post(f"/api/library/rules/{rule['id']}/review", json={"decision": "approve"})
    examples = library.approved_examples()
    assert examples[0]["meta"]["source"] == "approved"
    assert examples[0]["output"]["spl_query"] == GOOD_SPL


# --- platform -----------------------------------------------------------------------


def test_platform_status_never_contains_secrets(client, monkeypatch):
    monkeypatch.setattr(settings, "SPLUNK_URL", "https://splunk.example:8089")
    monkeypatch.setattr(settings, "SPLUNK_TOKEN", "splunk-secret-token")
    response = client.get("/api/platform/status")
    assert response.status_code == 200
    assert "splunk-secret-token" not in response.text
    body = response.json()
    assert body["splunk"]["configured"] is True
    assert body["splunk"]["auth"] == "token"
    assert body["knowledge"]["location"] in ("bundled_sample", "built")
    assert set(body["library"]) >= {"draft", "approved", "rejected", "deployed"}
