"""Route tests for the Copilot, Testing Lab and investigations endpoints.

No test reaches the network: the provider is mocked throughout.
"""

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.services import llm, store


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "INVESTIGATIONS_DB", tmp_path / "api-test.db")
    return TestClient(app)


def _provider(status=200, text="Summary:\nIt detects PowerShell downloads."):
    mock = MagicMock()
    mock.status_code = status
    mock.json.return_value = {"candidates": [{"content": {"parts": [{"text": text}]}}]}
    return mock


# ----------------------------------------------------------- Copilot


def test_copilot_status_reports_unconfigured(client, monkeypatch):
    monkeypatch.setattr(llm, "GEMINI_API_KEY", "")
    body = client.get("/api/copilot/status").json()
    assert body["configured"] is False
    assert body["message"]


def test_copilot_status_never_returns_the_key(client, monkeypatch):
    monkeypatch.setattr(llm, "GEMINI_API_KEY", "super-secret-key")
    response = client.get("/api/copilot/status")
    assert "super-secret-key" not in response.text
    assert response.json()["configured"] is True


def test_copilot_ask_returns_a_parsed_answer(client, monkeypatch):
    monkeypatch.setattr(llm, "GEMINI_API_KEY", "k")
    with patch.object(llm.requests, "post", return_value=_provider()):
        response = client.post(
            "/api/copilot/ask",
            json={"action": "explain_rule", "context": {"rule": "index=sysmon"}},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["ai_generated"] is True
    assert body["sections"][0]["heading"] == "Summary"


def test_copilot_ask_never_leaks_the_key(client, monkeypatch):
    monkeypatch.setattr(llm, "GEMINI_API_KEY", "super-secret-key")
    with patch.object(llm.requests, "post", return_value=_provider()):
        response = client.post("/api/copilot/ask", json={"action": "explain_rule"})
    assert "super-secret-key" not in response.text


def test_copilot_unavailable_returns_200_with_explanation(client, monkeypatch):
    """An unavailable Copilot is a degraded state, not a client error."""
    monkeypatch.setattr(llm, "GEMINI_API_KEY", "")
    response = client.post("/api/copilot/ask", json={"action": "explain_rule"})

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False
    assert body["status"] == "not_configured"
    assert body["text"] == ""


def test_copilot_rate_limit_is_surfaced(client, monkeypatch):
    monkeypatch.setattr(llm, "GEMINI_API_KEY", "k")
    mock = MagicMock()
    mock.status_code = 429
    with patch.object(llm.requests, "post", return_value=mock):
        body = client.post("/api/copilot/ask", json={"action": "explain_rule"}).json()
    assert body["status"] == "rate_limited"


def test_copilot_rejects_an_unknown_action(client):
    response = client.post("/api/copilot/ask", json={"action": "rm_rf"})
    assert response.status_code == 422


def test_copilot_rejects_oversized_question(client):
    response = client.post(
        "/api/copilot/ask", json={"action": "ask", "question": "x" * 5000}
    )
    assert response.status_code == 422


def test_copilot_context_is_restricted_to_known_fields(client, monkeypatch):
    """Unknown context keys must not be forwarded to the provider."""
    monkeypatch.setattr(llm, "GEMINI_API_KEY", "k")
    with patch.object(llm.requests, "post", return_value=_provider()) as post:
        client.post(
            "/api/copilot/ask",
            json={
                "action": "explain_rule",
                "context": {"rule": "index=a", "api_token": "leak-me"},
            },
        )
    assert "leak-me" not in str(post.call_args.kwargs["json"])


# -------------------------------------------------------- Testing Lab


def test_sample_sets_are_served(client):
    body = client.get("/api/testlab/samples").json()
    assert len(body) >= 3
    assert all(sample["events"] for sample in body)


def test_run_test_reports_matches_and_non_matches(client):
    response = client.post(
        "/api/testlab/run",
        json={
            "rule": 'Image="*powershell.exe*"',
            "events": [
                {"_id": "a", "Image": "C:\\powershell.exe"},
                {"_id": "b", "Image": "C:\\notepad.exe"},
            ],
        },
    )
    body = response.json()
    assert body["supported"] is True
    assert body["matched_count"] == 1
    assert body["total_count"] == 2


def test_run_test_labels_the_validation_mode(client):
    """Local sample testing must never be presented as Splunk validation."""
    body = client.post(
        "/api/testlab/run",
        json={"rule": 'Image="x"', "events": [{"Image": "x"}]},
    ).json()
    assert body["validation_mode"] == "local_sample"
    assert "not by Splunk" in body["disclaimer"]


def test_run_test_reports_unsupported_constructs(client):
    body = client.post(
        "/api/testlab/run",
        json={"rule": 'Image="x" | stats count by host', "events": [{"Image": "x"}]},
    ).json()
    assert any("stats" in note for note in body["unsupported"])


def test_run_test_reports_missing_fields(client):
    body = client.post(
        "/api/testlab/run",
        json={"rule": 'Image="x" CommandLine="y"', "events": [{"Image": "x"}]},
    ).json()
    assert "CommandLine" in body["results"][0]["missing_fields"]


def test_run_test_rejects_an_empty_rule(client):
    assert client.post("/api/testlab/run", json={"rule": "", "events": []}).status_code == 422


# ------------------------------------------------------ Investigations


def test_investigation_lifecycle(client):
    created = client.post(
        "/api/investigations",
        json={"title": "PowerShell staging", "notes": "n", "payload": {"a": 1}},
    )
    assert created.status_code == 201
    investigation_id = created.json()["id"]

    assert client.get(f"/api/investigations/{investigation_id}").json()["title"] == (
        "PowerShell staging"
    )

    patched = client.patch(
        f"/api/investigations/{investigation_id}", json={"title": "Renamed"}
    )
    assert patched.json()["title"] == "Renamed"
    assert patched.json()["payload"] == {"a": 1}

    duplicated = client.post(f"/api/investigations/{investigation_id}/duplicate")
    assert duplicated.status_code == 201
    assert duplicated.json()["id"] != investigation_id

    assert client.delete(f"/api/investigations/{investigation_id}").status_code == 204
    assert client.get(f"/api/investigations/{investigation_id}").status_code == 404


def test_listing_supports_search(client):
    client.post("/api/investigations", json={"title": "PowerShell", "payload": {}})
    client.post("/api/investigations", json={"title": "Certutil", "payload": {}})

    assert len(client.get("/api/investigations").json()) == 2
    assert len(client.get("/api/investigations?q=power").json()) == 1


def test_unknown_investigation_returns_404(client):
    assert client.get("/api/investigations/nope").status_code == 404
    assert client.patch("/api/investigations/nope", json={"title": "x"}).status_code == 404
    assert client.delete("/api/investigations/nope").status_code == 404
    assert client.post("/api/investigations/nope/duplicate").status_code == 404


def test_investigation_requires_a_title(client):
    assert client.post("/api/investigations", json={"payload": {}}).status_code == 422
    assert (
        client.post("/api/investigations", json={"title": "", "payload": {}}).status_code
        == 422
    )


def test_detection_endpoints_still_work(client):
    """Regression: the existing pipeline is unaffected by the new routes."""
    assert client.get("/api/health").status_code == 200
    response = client.post(
        "/api/analyze",
        json={"description": "Attacker used PowerShell DownloadString to fetch a payload"},
    )
    assert response.status_code == 200
    assert response.json()["primary_technique"]["id"] == "T1059.001"


# --- route registration regressions --------------------------------------
#
# A server started before a route existed serves 404 for it, which presents as
# a frontend bug. These assert the routes are actually mounted on the app.


def test_generation_route_is_mounted_at_the_expected_path(client):
    """Regression: /api/rules/generate returned 404 from a stale process.

    The OpenAPI spec is the authoritative view of what a running process
    actually serves, which is exactly how the stale server was identified.
    """
    paths = client.get("/openapi.json").json()["paths"]
    assert "/api/rules/generate" in paths
    assert "/api/attack/dataset" in paths


def test_generation_route_accepts_the_expected_request(client, monkeypatch):
    """The route must accept {scenario: str} and not 404 or 405."""
    from api.services import rule_generator

    monkeypatch.setattr(
        rule_generator,
        "generate_candidates",
        lambda _: rule_generator.GenerationResult(ok=False, status="not_configured", message="x"),
    )
    response = client.post("/api/rules/generate", json={"scenario": "powershell attack"})

    assert response.status_code == 200
    assert response.json()["status"] == "not_configured"


def test_generation_route_rejects_a_blank_scenario(client):
    assert client.post("/api/rules/generate", json={"scenario": "   "}).status_code == 422
    assert client.post("/api/rules/generate", json={}).status_code == 422


def test_unknown_api_path_still_returns_404(client):
    """Sanity: a genuinely missing route 404s, so the check above is meaningful."""
    assert client.post("/api/rules/does-not-exist", json={}).status_code == 404


def test_openapi_advertises_the_generation_route(client):
    """The OpenAPI spec is how a stale process is detected in the field."""
    spec = client.get("/openapi.json").json()
    assert "/api/rules/generate" in spec["paths"]
    assert "post" in spec["paths"]["/api/rules/generate"]


def test_legacy_analyze_route_is_still_mounted(client):
    """The legacy endpoint is preserved; it simply has no primary-flow callers."""
    assert "/api/analyze" in client.get("/openapi.json").json()["paths"]
