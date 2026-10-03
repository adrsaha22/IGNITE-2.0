"""Tests for choosing the AI provider from the dashboard.

Keys come only from the environment; the dashboard just picks among
configured providers, or Demo (no AI).
"""

from unittest.mock import MagicMock, patch

import pytest
import requests
from fastapi.testclient import TestClient

from api.main import app
from api.services import ai_switch, llm, rule_generator


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(llm, "LLM_PROVIDER", "gemini")
    monkeypatch.setattr(llm, "GEMINI_API_KEY", "gemini-secret")
    monkeypatch.setattr(llm, "ANTHROPIC_API_KEY", "")
    monkeypatch.setattr(llm, "OPENAI_API_KEY", "openai-secret")
    monkeypatch.setattr(ai_switch, "_ENV_PROVIDER", "gemini")
    monkeypatch.setattr(ai_switch, "_ENV_MODE", "gemini")
    monkeypatch.setattr(rule_generator, "DETECTION_GENERATION_MODE", "gemini")
    # Ollama is "down" unless a test says otherwise.
    monkeypatch.setattr(ai_switch.requests, "get", MagicMock(side_effect=requests.ConnectionError()))
    return TestClient(app)


def _option(body, provider):
    return next(o for o in body["options"] if o["id"] == provider)


def test_lists_every_choice_without_secrets(client):
    response = client.get("/api/ai/providers")
    body = response.json()
    assert [o["id"] for o in body["options"]] == ["gemini", "anthropic", "openai", "ollama", "ellm", "demo"]
    assert body["active"] == "gemini"
    assert "gemini-secret" not in response.text and "openai-secret" not in response.text


def test_provider_without_key_is_flagged_and_cannot_be_chosen(client):
    anthropic = _option(client.get("/api/ai/providers").json(), "anthropic")
    assert anthropic["configured"] is False
    assert "ANTHROPIC_API_KEY" in anthropic["message"]

    response = client.put("/api/ai/provider", json={"provider": "anthropic"})
    assert response.status_code == 409
    assert llm.LLM_PROVIDER == "gemini"


def test_switching_changes_the_active_provider(client):
    body = client.put("/api/ai/provider", json={"provider": "openai"}).json()
    assert body["active"] == "openai"
    assert body["overridden"] is True
    assert llm.LLM_PROVIDER == "openai"
    assert llm.provider_status()["provider"] == "openai"


def test_demo_turns_ai_off(client):
    client.put("/api/ai/provider", json={"provider": "demo"})
    assert rule_generator.DETECTION_GENERATION_MODE == "demo"
    assert llm.is_configured() is False
    assert "Demo" in llm.status_message(llm.LLMStatus.NOT_CONFIGURED)
    status = client.get("/api/copilot/status").json()
    assert status["configured"] is False


def test_demo_generation_uses_templates_and_calls_no_provider(client):
    client.put("/api/ai/provider", json={"provider": "demo"})
    with patch.object(llm.requests, "post") as post:
        result = rule_generator.generate_candidates("powershell DownloadString cradle")
    post.assert_not_called()
    assert result.mode == "demo"


def test_leaving_demo_turns_ai_back_on(client):
    client.put("/api/ai/provider", json={"provider": "demo"})
    client.put("/api/ai/provider", json={"provider": "gemini"})
    assert rule_generator.DETECTION_GENERATION_MODE == "gemini"
    assert llm.is_configured() is True


def test_choice_survives_a_restart(client, monkeypatch):
    client.put("/api/ai/provider", json={"provider": "openai"})
    # Simulate a fresh process: back to .env defaults, then restore.
    monkeypatch.setattr(llm, "LLM_PROVIDER", "gemini")
    ai_switch.restore_saved_choice()
    assert llm.LLM_PROVIDER == "openai"


def test_reset_returns_to_env_default(client):
    client.put("/api/ai/provider", json={"provider": "demo"})
    body = client.post("/api/ai/provider/reset").json()
    assert body["active"] == "gemini"
    assert body["overridden"] is False
    llm.LLM_PROVIDER = "openai"  # a stale process value must not come back after restore
    ai_switch.restore_saved_choice()
    assert llm.LLM_PROVIDER == "openai"  # nothing saved, so nothing re-applied


def test_changes_are_audited(client):
    client.put("/api/ai/provider", json={"provider": "demo"})
    entry = client.get("/api/audit?action=ai_provider_changed").json()[0]
    assert entry["detail"] == "Google Gemini -> Demo (no AI)"


def test_unknown_provider_is_rejected(client):
    assert client.put("/api/ai/provider", json={"provider": "skynet"}).status_code == 422


def test_ollama_reports_a_missing_model(client, monkeypatch):
    monkeypatch.setattr(llm, "OLLAMA_MODEL", "llama3.1")
    tags = MagicMock()
    tags.json.return_value = {"models": [{"name": "qwen2.5-coder:7b-instruct"}]}
    monkeypatch.setattr(ai_switch.requests, "get", MagicMock(return_value=tags))
    ollama = _option(client.get("/api/ai/providers").json(), "ollama")
    assert ollama["ready"] is False
    assert "ollama pull llama3.1" in ollama["message"]
    assert "qwen2.5-coder:7b-instruct" in ollama["message"]


def test_demo_sends_nothing_off_the_network(client):
    client.put("/api/ai/provider", json={"provider": "demo"})
    assert llm.provider_status()["data_leaves_network"] is False


# --- ELLM (OpenAI-compatible endpoint) ----------------------------------------


def test_ellm_without_url_and_model_is_not_selectable(client, monkeypatch):
    monkeypatch.setattr(llm, "ELLM_BASE_URL", "")
    monkeypatch.setattr(llm, "ELLM_MODEL", "")
    ellm = _option(client.get("/api/ai/providers").json(), "ellm")
    assert ellm["label"] == "ELLM"
    assert ellm["configured"] is False
    assert "ELLM_BASE_URL" in ellm["message"]
    assert client.put("/api/ai/provider", json={"provider": "ellm"}).status_code == 409


def test_ellm_can_be_chosen_and_calls_its_endpoint(client, monkeypatch):
    from types import SimpleNamespace

    import openai

    monkeypatch.setattr(llm, "ELLM_BASE_URL", "http://llm.internal:8080/v1")
    monkeypatch.setattr(llm, "ELLM_MODEL", "corp-model")
    monkeypatch.setattr(llm, "ELLM_API_KEY", "")  # internal endpoint without a key
    body = client.put("/api/ai/provider", json={"provider": "ellm"}).json()
    assert body["active"] == "ellm"

    choice = SimpleNamespace(finish_reason="stop", message=SimpleNamespace(content="Summary:\nok"))
    with patch.object(openai, "OpenAI") as client_cls:
        client_cls.return_value.chat.completions.create.return_value = SimpleNamespace(choices=[choice])
        result = llm.generate("explain_rule", "", {"rule": "index=sysmon"})

    assert result.ok and result.model == "corp-model"
    assert client_cls.call_args.kwargs["base_url"] == "http://llm.internal:8080/v1"
    sent = client_cls.return_value.chat.completions.create.call_args.kwargs
    assert sent["model"] == "corp-model"
    assert "max_tokens" in sent  # broadly supported by compatible servers
