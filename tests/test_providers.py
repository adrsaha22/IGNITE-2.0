"""Tests for the Anthropic, OpenAI and Ollama providers and knowledge retrieval.

SDK clients are mocked; nothing reaches the network.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import anthropic
import httpx
import openai
import pytest
import requests

from api.services import knowledge, llm


def _text_block(text):
    return SimpleNamespace(type="text", text=text)


def _anthropic_response(text="Summary:\nIt detects PowerShell.", stop_reason="end_turn"):
    return SimpleNamespace(content=[SimpleNamespace(type="thinking", thinking=""), _text_block(text)], stop_reason=stop_reason)


def _status_error(cls, status):
    request = httpx.Request("POST", "https://api.example/v1")
    return cls("error", response=httpx.Response(status, request=request), body=None)


@pytest.fixture
def use_anthropic(monkeypatch):
    monkeypatch.setattr(llm, "LLM_PROVIDER", "anthropic")
    monkeypatch.setattr(llm, "ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setattr(llm, "ANTHROPIC_MODEL", "claude-opus-5-5")


# --- configuration ------------------------------------------------------------


def test_status_names_the_active_provider_key(monkeypatch):
    monkeypatch.setattr(llm, "LLM_PROVIDER", "anthropic")
    monkeypatch.setattr(llm, "ANTHROPIC_API_KEY", "")
    assert not llm.is_configured()
    assert "ANTHROPIC_API_KEY" in llm.status_message(llm.LLMStatus.NOT_CONFIGURED)


def test_provider_status_carries_no_secret(use_anthropic):
    status = llm.provider_status()
    assert "sk-ant-test" not in str(status)
    assert status["model"] == "claude-opus-5-5"
    assert status["data_leaves_network"] is True


def test_ollama_needs_no_key(monkeypatch):
    monkeypatch.setattr(llm, "LLM_PROVIDER", "ollama")
    assert llm.is_configured()
    assert llm.provider_status()["data_leaves_network"] is False


# --- Anthropic -----------------------------------------------------------------


def test_anthropic_answer_is_parsed(use_anthropic):
    with patch.object(anthropic, "Anthropic") as client_cls:
        client_cls.return_value.beta.messages.create.return_value = _anthropic_response()
        result = llm.generate("explain_rule", "", {"rule": "index=sysmon"})

    assert result.ok
    assert result.sections[0].heading == "Summary"
    kwargs = client_cls.return_value.beta.messages.create.call_args.kwargs
    assert kwargs["model"] == "claude-opus-5-5"
    assert kwargs["fallbacks"] == "default"
    assert "temperature" not in kwargs  # rejected by current Claude models
    assert kwargs["max_tokens"] >= 16000  # room for thinking before the answer


def test_anthropic_model_without_fallback_support_uses_plain_create(use_anthropic, monkeypatch):
    monkeypatch.setattr(llm, "ANTHROPIC_MODEL", "claude-haiku-4-5")
    with patch.object(anthropic, "Anthropic") as client_cls:
        client_cls.return_value.messages.create.return_value = _anthropic_response()
        result = llm.generate("explain_rule", "", {"rule": "x"})
    assert result.ok
    client_cls.return_value.beta.messages.create.assert_not_called()


def test_anthropic_refusal_is_blocked(use_anthropic):
    with patch.object(anthropic, "Anthropic") as client_cls:
        client_cls.return_value.beta.messages.create.return_value = _anthropic_response("", "refusal")
        result = llm.generate("explain_rule", "", {"rule": "x"})
    assert result.status is llm.LLMStatus.BLOCKED
    assert result.text == ""


@pytest.mark.parametrize(
    "error, status",
    [
        (lambda: _status_error(anthropic.AuthenticationError, 401), llm.LLMStatus.UNAUTHORIZED),
        (lambda: _status_error(anthropic.RateLimitError, 429), llm.LLMStatus.RATE_LIMITED),
        (lambda: _status_error(anthropic.InternalServerError, 500), llm.LLMStatus.PROVIDER_ERROR),
        (lambda: anthropic.APITimeoutError(request=httpx.Request("POST", "https://x")), llm.LLMStatus.TIMEOUT),
        (lambda: anthropic.APIConnectionError(request=httpx.Request("POST", "https://x")), llm.LLMStatus.UNREACHABLE),
    ],
)
def test_anthropic_errors_map_to_statuses(use_anthropic, error, status):
    with patch.object(anthropic, "Anthropic") as client_cls:
        client_cls.return_value.beta.messages.create.side_effect = error()
        result = llm.generate("explain_rule", "", {"rule": "x"})
    assert result.status is status
    assert "sk-ant-test" not in result.message


# --- OpenAI -----------------------------------------------------------------------


def test_openai_answer_is_parsed(monkeypatch):
    monkeypatch.setattr(llm, "LLM_PROVIDER", "openai")
    monkeypatch.setattr(llm, "OPENAI_API_KEY", "sk-test")
    choice = SimpleNamespace(finish_reason="stop", message=SimpleNamespace(content="Summary:\nok"))
    with patch.object(openai, "OpenAI") as client_cls:
        client_cls.return_value.chat.completions.create.return_value = SimpleNamespace(choices=[choice])
        result = llm.generate("explain_rule", "", {"rule": "x"})
    assert result.ok
    assert result.model == llm.OPENAI_MODEL


def test_openai_content_filter_is_blocked(monkeypatch):
    monkeypatch.setattr(llm, "LLM_PROVIDER", "openai")
    monkeypatch.setattr(llm, "OPENAI_API_KEY", "sk-test")
    choice = SimpleNamespace(finish_reason="content_filter", message=SimpleNamespace(content=""))
    with patch.object(openai, "OpenAI") as client_cls:
        client_cls.return_value.chat.completions.create.return_value = SimpleNamespace(choices=[choice])
        result = llm.generate("explain_rule", "", {"rule": "x"})
    assert result.status is llm.LLMStatus.BLOCKED


# --- Ollama -------------------------------------------------------------------------


def test_ollama_answer_is_parsed(monkeypatch):
    monkeypatch.setattr(llm, "LLM_PROVIDER", "ollama")
    response = MagicMock(status_code=200)
    response.json.return_value = {"message": {"content": "Summary:\nlocal answer"}}
    with patch.object(llm.requests, "post", return_value=response) as post:
        result = llm.generate("explain_rule", "", {"rule": "x"})
    assert result.ok
    assert post.call_args.args[0].endswith("/api/chat")


def test_ollama_down_is_unreachable(monkeypatch):
    monkeypatch.setattr(llm, "LLM_PROVIDER", "ollama")
    with patch.object(llm.requests, "post", side_effect=requests.ConnectionError()):
        result = llm.generate("explain_rule", "", {"rule": "x"})
    assert result.status is llm.LLMStatus.UNREACHABLE
    assert "Ollama" in result.message


# --- knowledge retrieval -----------------------------------------------------------


def test_bundled_sample_is_used_until_a_dataset_is_built():
    stats = knowledge.dataset_stats()
    assert stats["location"] == "bundled_sample"
    assert stats["counts"]["train"] > 0


def test_retrieval_ranks_relevant_detections_first():
    results = knowledge.get_retriever().search("powershell encoded command", k=2)
    assert results
    assert "powershell" in results[0]["output"]["title"].lower()


def test_technique_ids_boost_matching_references():
    retriever = knowledge.ExampleRetriever(
        [
            {"id": "a", "input": "generic text", "output": {"title": "A", "mitre": {"technique_ids": ["T1003"]}}},
            {"id": "b", "input": "generic text", "output": {"title": "B", "mitre": {"technique_ids": ["T1059.001"]}}},
        ]
    )
    assert retriever.search("generic", technique_ids=["T1059.001"], k=1)[0]["id"] == "b"


def test_approved_rules_outrank_equal_public_references():
    examples = [
        {"id": "pub", "input": "lsass dump", "output": {"title": "Pub", "mitre": {"technique_ids": []}}, "meta": {"source": "sigma"}},
        {"id": "ours", "input": "lsass dump", "output": {"title": "Ours", "mitre": {"technique_ids": []}}, "meta": {"source": "approved"}},
    ]
    assert knowledge.ExampleRetriever(examples).search("lsass dump", k=1)[0]["id"] == "ours"


def test_split_is_stable_per_technique():
    assert knowledge.split_for("T1059") == knowledge.split_for("T1059")
    assert {knowledge.split_for(f"T{n:04d}") for n in range(1000, 1200)} == {"train", "val", "test"}


# --- ESCU loader handles both file layouts --------------------------------


@pytest.mark.parametrize(
    "layout",
    [
        # Current ESCU: ATT&CK IDs and risk score outside `tags`.
        "mitre_attack_id:\n  - T1059.001\nfinding:\n  entity:\n    field: dest\n    score: 64\n",
        # Older ESCU: everything under `tags`.
        "tags:\n  mitre_attack_id:\n    - T1059.001\n  risk_score: 64\n",
    ],
)
def test_escu_loader_reads_both_layouts(tmp_path, layout):
    detections = tmp_path / "detections" / "endpoint"
    detections.mkdir(parents=True)
    (detections / "rule.yml").write_text(
        "name: PowerShell Download\nid: abc\nstatus: production\n"
        "description: Detects a download cradle.\n"
        "data_source:\n  - Sysmon EventID 1\n"
        "search: '| tstats count from datamodel=Endpoint.Processes'\n" + layout,
        encoding="utf-8",
    )
    records = knowledge.load_escu(tmp_path, product="windows")
    assert len(records) == 1
    assert records[0]["technique_ids"] == ["T1059.001"]
    assert records[0]["severity"] == "high"


# --- lighter request for local models ----------------------------------------


def test_ollama_generation_uses_json_mode_and_a_larger_context(monkeypatch):
    import json as json_lib

    from api.services import rule_generator

    monkeypatch.setattr(llm, "LLM_PROVIDER", "ollama")
    payload = json_lib.dumps(
        {"candidates": [{"name": "r", "spl": 'index=sysmon Image="*powershell.exe" | stats count by host'}]}
    )
    response = MagicMock(status_code=200)
    response.json.return_value = {"message": {"content": payload}}
    with patch.object(llm.requests, "post", return_value=response) as post:
        result = rule_generator.generate_candidates("powershell download")

    body = post.call_args.kwargs["json"]
    assert body["format"] == "json"
    assert body["options"]["num_ctx"] >= 8192
    assert "at most 1 candidates" in body["messages"][1]["content"]
    assert result.ok


def test_hosted_providers_keep_the_full_request(monkeypatch):
    import json as json_lib

    from api.services import rule_generator

    monkeypatch.setattr(llm, "LLM_PROVIDER", "gemini")
    monkeypatch.setattr(llm, "GEMINI_API_KEY", "k")
    payload = json_lib.dumps({"candidates": [{"name": "r", "spl": 'index=a Image="x" | stats count'}]})
    response = MagicMock(status_code=200)
    response.json.return_value = {"candidates": [{"content": {"parts": [{"text": payload}]}}]}
    with patch.object(llm.requests, "post", return_value=response) as post:
        rule_generator.generate_candidates("powershell download")
    assert f"at most {rule_generator.LLM_MAX_CANDIDATES} candidates" in str(post.call_args.kwargs["json"])
