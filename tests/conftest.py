"""Shared fixtures.

Every test gets its own SQLite file, the bundled sample knowledge base and
an empty Sigma corpus, so no test reads or writes the real
data/investigations.db (generation reads approved library rules for retrieval).
"""

import pytest

from api import settings
from api.services import knowledge, llm, rule_generator, store


@pytest.fixture(autouse=True, scope="session")
def no_local_sigma_corpus(tmp_path_factory):
    """Hide any downloaded Sigma corpus, including from module-scoped fixtures."""
    empty = tmp_path_factory.mktemp("sigma-rules")
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("IGNITE_SIGMA_PATH", str(empty))
        yield


@pytest.fixture(autouse=True)
def isolated_database(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "INVESTIGATIONS_DB", tmp_path / "ignite-test.db")
    # Use the bundled sample knowledge base, whatever has been built locally.
    monkeypatch.setattr(settings, "KNOWLEDGE_PROCESSED_DIR", tmp_path / "knowledge-processed")
    # The dashboard AI switch changes these at runtime; restore them per test.
    monkeypatch.setattr(llm, "LLM_PROVIDER", llm.LLM_PROVIDER)
    monkeypatch.setattr(llm, "AI_DISABLED", False)
    monkeypatch.setattr(rule_generator, "DETECTION_GENERATION_MODE", rule_generator.DETECTION_GENERATION_MODE)
    knowledge.reset_cache()
    yield
    knowledge.reset_cache()
