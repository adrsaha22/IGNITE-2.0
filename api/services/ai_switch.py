"""Runtime choice of AI provider, made from the dashboard.

Keys and models stay in the backend .env; the dashboard only chooses which
configured provider is active, or "demo" (no AI: offline templates, Assistant
off). The choice is stored in SQLite so it survives restarts, every change is
audited, and "reset" returns to the .env default (IGNITE_LLM_PROVIDER /
DETECTION_GENERATION_MODE).

A provider without its key cannot be selected; the response says which .env
variable to set. .env is read at start-up, so a newly added key needs an API
restart.
"""

from __future__ import annotations

import logging
from typing import Any

import requests

from api import settings
from api.services import library, llm, rule_generator, store

logger = logging.getLogger(__name__)

DEMO = "demo"
CHOICES = (*settings.LLM_PROVIDERS, DEMO)

LABELS = {
    "gemini": "Google Gemini",
    "anthropic": "Anthropic Claude",
    "openai": "OpenAI",
    "ollama": "Ollama (local)",
    "ellm": "ELLM",
    DEMO: "Demo (no AI)",
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS app_settings (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
"""
_KEY = "ai_choice"

# The .env defaults, captured once so "reset" can restore them.
_ENV_PROVIDER = settings.LLM_PROVIDER
_ENV_MODE = settings.DETECTION_GENERATION_MODE


def env_default() -> str:
    return DEMO if _ENV_MODE == "demo" else _ENV_PROVIDER


def active() -> str:
    return DEMO if rule_generator.DETECTION_GENERATION_MODE == "demo" else llm.LLM_PROVIDER


def _apply(choice: str) -> None:
    """Point generation and the Assistant at the chosen provider."""
    if choice == DEMO:
        rule_generator.DETECTION_GENERATION_MODE = "demo"
        llm.AI_DISABLED = True
    else:
        rule_generator.DETECTION_GENERATION_MODE = "gemini"  # the LLM path
        llm.AI_DISABLED = False
        llm.LLM_PROVIDER = choice


def _read_saved() -> str | None:
    with store._connect() as conn:
        conn.executescript(_SCHEMA)
        row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (_KEY,)).fetchone()
    return row["value"] if row else None


def _write_saved(choice: str | None) -> None:
    with store._connect() as conn:
        conn.executescript(_SCHEMA)
        if choice is None:
            conn.execute("DELETE FROM app_settings WHERE key = ?", (_KEY,))
        else:
            conn.execute(
                "INSERT INTO app_settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (_KEY, choice),
            )


def restore_saved_choice() -> None:
    """Apply the dashboard choice saved before the last restart, if any."""
    try:
        saved = _read_saved()
    except Exception:
        logger.exception("Saved AI choice could not be read; using .env default")
        return
    if saved in CHOICES and (saved == DEMO or _key_present(saved)):
        _apply(saved)
        logger.info("AI provider restored from dashboard choice: %s", saved)


def _key_present(provider: str) -> bool:
    key = {
        "gemini": llm.GEMINI_API_KEY,
        "anthropic": llm.ANTHROPIC_API_KEY,
        "openai": llm.OPENAI_API_KEY,
    }.get(provider)
    if provider == "ollama":
        return True
    if provider == "ellm":
        return bool(llm.ELLM_BASE_URL and llm.ELLM_MODEL)
    return bool(key and key.strip())


def _ollama_check() -> tuple[bool, str]:
    """Whether the local server is up and has the configured model."""
    try:
        response = requests.get(f"{settings.OLLAMA_BASE_URL}/api/tags", timeout=1.5)
        response.raise_for_status()
        names = {m.get("name", "") for m in response.json().get("models", [])}
    except Exception:
        return False, f"Ollama is not running at {settings.OLLAMA_BASE_URL}."
    model = llm.OLLAMA_MODEL
    if model in names or f"{model}:latest" in names:
        return True, ""
    installed = ", ".join(sorted(names)) or "none"
    return False, (
        f"Model '{model}' is not installed. Run `ollama pull {model}` or set OLLAMA_MODEL "
        f"in .env to one you have ({installed})."
    )


def options() -> dict[str, Any]:
    models = {
        "gemini": llm.GEMINI_MODEL,
        "anthropic": llm.ANTHROPIC_MODEL,
        "openai": llm.OPENAI_MODEL,
        "ollama": llm.OLLAMA_MODEL,
        "ellm": llm.ELLM_MODEL or "model not set",
        DEMO: "offline templates",
    }
    key_vars = {"gemini": "GEMINI_API_KEY", "anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}
    items = []
    for choice in CHOICES:
        configured, ready, message = True, True, ""
        if choice in key_vars and not _key_present(choice):
            configured = ready = False
            message = f"Add {key_vars[choice]} to .env and restart the API."
        elif choice == "ellm" and not _key_present("ellm"):
            configured = ready = False
            message = "Set ELLM_BASE_URL and ELLM_MODEL (and ELLM_API_KEY if needed) in .env, then restart the API."
        elif choice == "ellm":
            message = f"OpenAI-compatible endpoint at {llm.ELLM_BASE_URL}."
        elif choice == "ollama":
            ready, message = _ollama_check()
            if ready:
                message = (
                    "Runs on this machine; nothing leaves it. On a CPU expect a few minutes "
                    "per generation (one candidate, lighter request)."
                )
        elif choice == DEMO:
            message = "No AI. Covers 3 scenarios with labelled templates; the Assistant is off."
        items.append(
            {
                "id": choice,
                "label": LABELS[choice],
                "model": models[choice],
                "configured": configured,
                "ready": ready,
                "message": message,
                "local": choice in ("ollama", DEMO),
                "key_env": key_vars.get(choice, ""),
            }
        )
    current = active()
    return {
        "active": current,
        "env_default": env_default(),
        "overridden": current != env_default(),
        "options": items,
    }


class SwitchError(Exception):
    pass


def select(choice: str) -> dict[str, Any]:
    if choice not in CHOICES:
        raise SwitchError(f"Unknown provider '{choice}'.")
    if choice != DEMO and not _key_present(choice):
        if choice == "ellm":
            raise SwitchError("ELLM is not configured. Set ELLM_BASE_URL and ELLM_MODEL in .env and restart the API.")
        var = {"gemini": "GEMINI_API_KEY", "anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}[choice]
        raise SwitchError(f"{LABELS[choice]} has no API key. Add {var} to .env and restart the API.")
    previous = active()
    _apply(choice)
    _write_saved(choice)
    if previous != choice:
        library.log_event("ai_provider_changed", None, f"{LABELS[previous]} -> {LABELS[choice]}")
    return options()


def reset() -> dict[str, Any]:
    previous = active()
    _apply(env_default())
    _write_saved(None)
    if previous != active():
        library.log_event(
            "ai_provider_changed", None, f"{LABELS[previous]} -> {LABELS[active()]} (reset to .env default)"
        )
    return options()
