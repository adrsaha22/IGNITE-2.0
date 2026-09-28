"""Tests for the FastAPI layer.

The detection modules are exercised for real where cheap, and mocked where the
test is about failure handling. No test requires a running model server.
"""

import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.routes import detection as routes
from api.services import detection as service

POWERSHELL = (
    "Attacker used PowerShell to download a payload from GitHub via DownloadString "
    "and created a scheduled task with schtasks for persistence"
)
VAGUE = "lateral movement via unknown vector"


@pytest.fixture
def client():
    # Clear the AI status cache so tests do not leak state into each other.
    routes._ai_cache["value"] = None
    routes._ai_cache["at"] = 0.0
    return TestClient(app)


# --- health ---------------------------------------------------------------


def test_health_reports_loaded_corpora(client):
    response = client.get("/api/health")
    assert response.status_code == 200

    body = response.json()
    assert body["status"] == "ok"
    # The real ATT&CK bundle is loaded.
    assert body["mitre_techniques_loaded"] > 800
    # data/sigma is empty in this repository, and that is reported honestly.
    assert body["sigma_corpus_available"] is False
    assert "available" in body["ai"]


def test_root_points_at_docs(client):
    assert client.get("/").status_code == 200


# --- analyze --------------------------------------------------------------


def test_analyze_returns_real_results(client):
    response = client.post("/api/analyze", json={"description": POWERSHELL})
    assert response.status_code == 200

    body = response.json()
    assert body["description"] == POWERSHELL
    assert body["primary_technique"]["id"] == "T1059.001"
    assert body["primary_technique"]["name"] == "PowerShell"
    assert body["candidates"]
    assert body["best"]["spl"]


def test_candidate_scores_carry_their_own_scale(client):
    """The rule scorer can exceed 100, so the scale must be reported with it."""
    body = client.post("/api/analyze", json={"description": POWERSHELL}).json()
    best = body["best"]
    assert best["score_max"] == 125
    assert best["score"] <= best["score_max"]


def test_technique_names_are_resolved_not_invented(client):
    body = client.post("/api/analyze", json={"description": POWERSHELL}).json()
    names = {t["id"]: t["name"] for t in body["autonomous"]["techniques"]}
    assert names["T1059.001"] == "PowerShell"
    assert names["T1105"] == "Ingress Tool Transfer"


def test_tactics_are_null_because_pipeline_does_not_map_them(client):
    body = client.post("/api/analyze", json={"description": POWERSHELL}).json()
    for technique in body["autonomous"]["techniques"]:
        assert technique["tactic"] is None


def test_rule_status_never_claims_external_validation(client):
    body = client.post("/api/analyze", json={"description": POWERSHELL}).json()
    assert "not validated" in body["rule_status"]


def test_empty_sigma_corpus_is_warned(client):
    body = client.post("/api/analyze", json={"description": POWERSHELL}).json()
    assert any("data/sigma" in w for w in body["warnings"])
    assert body["sigma_references"] == []


def test_vague_input_returns_empty_collections_not_errors(client):
    response = client.post("/api/analyze", json={"description": VAGUE})
    assert response.status_code == 200

    body = response.json()
    assert body["entities"]["tools"] == []
    assert body["autonomous"]["techniques"] == []
    assert body["primary_technique"]["id"] == "Unknown"
    # The unmapped technique is reported rather than silently ignored.
    assert any("did not match any known keyword" in w for w in body["warnings"])


def test_contradictory_validation_is_passed_through(client):
    """valid=true alongside issues must reach the client intact."""
    body = client.post("/api/analyze", json={"description": VAGUE}).json()
    validation = body["autonomous"]["validation"]
    assert validation["valid"] is True
    assert validation["issues"]
    assert any("Marked valid" in w for w in body["warnings"])


# --- input validation ----------------------------------------------------


@pytest.mark.parametrize("payload", [{"description": ""}, {"description": "   "}, {}])
def test_invalid_input_is_rejected(client, payload):
    assert client.post("/api/analyze", json=payload).status_code == 422


def test_oversized_input_is_rejected(client):
    assert client.post("/api/analyze", json={"description": "x" * 9000}).status_code == 422


# --- exception handling --------------------------------------------------


def test_pipeline_exception_returns_500_without_stack_trace(client, monkeypatch):
    def boom(_):
        raise RuntimeError("internal detail that must not leak")

    monkeypatch.setattr(service, "run_analysis", boom)

    response = client.post("/api/analyze", json={"description": POWERSHELL})
    assert response.status_code == 500

    detail = response.json()["detail"]
    assert "internal detail that must not leak" not in detail
    assert "Traceback" not in detail
    assert "detection pipeline failed" in detail.lower()


def test_malformed_module_output_does_not_crash_the_route(client, monkeypatch):
    """A module returning an unexpected shape must surface as a clean 500."""
    monkeypatch.setattr(
        service.pipeline, "run_analysis", lambda _: {"unexpected": "shape"}
    )
    response = client.post("/api/analyze", json={"description": POWERSHELL})
    assert response.status_code == 500
    assert "Traceback" not in response.json()["detail"]


# --- AI endpoints (no model server required) -----------------------------


def test_ai_status_reports_unavailable_when_server_is_down(client):
    body = client.get("/api/ai/status").json()
    assert body["available"] is False
    assert body["detail"]


def test_ai_analyze_returns_200_when_model_unreachable(client, monkeypatch):
    """An AI outage is a normal degraded state, not a client error."""
    monkeypatch.setattr(
        "modules.ai_summary.summarize_attack",
        lambda _: "AI analysis unavailable: Connection refused",
    )

    response = client.post("/api/ai/analyze", json={"description": POWERSHELL})
    assert response.status_code == 200

    body = response.json()
    assert body["available"] is False
    # The underlying detail is preserved for the technical-details section.
    assert "Connection refused" in body["error"]
    assert body["text"] is None
    assert response.headers.get("X-AI-Available") == "false"


def test_ai_analyze_passes_through_a_successful_summary(client, monkeypatch):
    monkeypatch.setattr(
        "modules.ai_summary.summarize_attack", lambda _: "Behaviours: PowerShell download."
    )

    body = client.post("/api/ai/analyze", json={"description": POWERSHELL}).json()
    assert body["available"] is True
    assert body["text"] == "Behaviours: PowerShell download."


def test_ai_exception_is_contained(client, monkeypatch):
    def boom(_):
        raise RuntimeError("model client exploded")

    monkeypatch.setattr("modules.ai_summary.summarize_attack", boom)

    body = client.post("/api/ai/analyze", json={"description": POWERSHELL}).json()
    assert body["available"] is False
    # The raw exception text is not returned to the user.
    assert "model client exploded" not in (body["error"] or "")


def test_ai_status_is_cached_between_calls(client, monkeypatch):
    """Ordinary renders must not repeatedly probe the model server."""
    calls = {"n": 0}

    def counting_status():
        calls["n"] += 1
        return service.AIStatus(available=False, detail="stub", checked_at="now")

    monkeypatch.setattr(service, "ai_status", counting_status)
    routes._ai_cache["value"] = None
    routes._ai_cache["at"] = 0.0

    client.get("/api/ai/status")
    client.get("/api/ai/status")
    client.get("/api/ai/status")
    assert calls["n"] == 1, "status should be served from cache"

    # An explicit refresh bypasses the cache.
    client.get("/api/ai/status?refresh=true")
    assert calls["n"] == 2


def test_detection_works_while_ai_is_unavailable(client, monkeypatch):
    monkeypatch.setattr(
        "modules.ai_summary.summarize_attack", lambda _: "AI analysis unavailable: refused"
    )
    assert client.post("/api/analyze", json={"description": POWERSHELL}).status_code == 200


# --- export ---------------------------------------------------------------


def test_export_returns_the_current_analysis(client):
    response = client.post("/api/export", json={"description": POWERSHELL})
    assert response.status_code == 200

    body = response.json()
    assert body["metadata"]["attack_description"] == POWERSHELL
    assert "not validated" in body["metadata"]["rule_status"]


# --- CORS -----------------------------------------------------------------


def test_cors_allows_the_dev_frontend_only(client):
    allowed = client.options(
        "/api/analyze",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:5173"

    blocked = client.options(
        "/api/analyze",
        headers={
            "Origin": "https://evil.example.com",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert blocked.headers.get("access-control-allow-origin") != "https://evil.example.com"
