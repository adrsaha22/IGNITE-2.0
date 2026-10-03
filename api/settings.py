"""API configuration, read from the environment with local-dev defaults.

No machine-specific addresses and no secrets are hardcoded. Secret values are
read here and used only by the service that needs them; they are never placed
in a response model.
"""

import os
from pathlib import Path


def _load_dotenv(path: Path = Path(".env")) -> None:
    """Load KEY=VALUE pairs from a local .env file, if present.

    A tiny reader rather than a new dependency. Real environment variables
    always win, so an explicit `export` overrides the file. The file is
    git-ignored and never read from anywhere outside the project directory.
    """
    if not path.is_file():
        return

    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip("'\"")
            # Do not clobber a value already set in the environment.
            if key and key not in os.environ:
                os.environ[key] = value
    except OSError:
        # A missing or unreadable .env is not fatal; defaults still apply.
        pass


_load_dotenv()

# Base URL of the local model server used by the legacy AI summary feature.
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")

# Origins allowed to call this API. Restricted to the local dev frontend rather
# than a wildcard.
_DEFAULT_ORIGINS = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:5174,http://127.0.0.1:5174"
CORS_ORIGINS = [
    origin.strip()
    for origin in os.environ.get("IGNITE_CORS_ORIGINS", _DEFAULT_ORIGINS).split(",")
    if origin.strip()
]

# How long a cached AI availability result stays fresh, so ordinary page
# renders do not repeatedly probe the model server.
AI_STATUS_TTL_SECONDS = int(os.environ.get("IGNITE_AI_STATUS_TTL", "30"))

# ----------------------------------------------------------- AI Detection Assistant

# Secret. Read from the environment only; never logged and never serialised
# into an API response.
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

# Model ID is configurable because provider catalogues change over time.
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-flash-latest")

GEMINI_BASE_URL = os.environ.get(
    "GEMINI_BASE_URL", "https://generativelanguage.googleapis.com"
).rstrip("/")

# Bounded request/response sizes keep free-tier quota use predictable.
LLM_MAX_OUTPUT_TOKENS = int(os.environ.get("IGNITE_LLM_MAX_OUTPUT_TOKENS", "1200"))
LLM_MAX_INPUT_CHARS = int(os.environ.get("IGNITE_LLM_MAX_INPUT_CHARS", "12000"))
LLM_CONNECT_TIMEOUT = float(os.environ.get("IGNITE_LLM_CONNECT_TIMEOUT", "5"))
LLM_READ_TIMEOUT = float(os.environ.get("IGNITE_LLM_READ_TIMEOUT", "45"))

# Bounds how many candidates one generation request may return.
LLM_MAX_CANDIDATES = int(os.environ.get("IGNITE_LLM_MAX_CANDIDATES", "3"))

# Structured rule candidates need a larger budget than a prose answer.
LLM_GENERATION_MAX_TOKENS = int(os.environ.get("IGNITE_LLM_GENERATION_MAX_TOKENS", "6000"))

# One short retry for transient provider 5xx errors. Deliberately small so a
# genuinely unavailable provider fails fast instead of stalling the user.
LLM_MAX_ATTEMPTS = int(os.environ.get("IGNITE_LLM_MAX_ATTEMPTS", "4"))
LLM_RETRY_DELAY = float(os.environ.get("IGNITE_LLM_RETRY_DELAY", "2"))

# ------------------------------------------------- Generation mode

# "gemini" uses the LLM provider. "demo" uses offline, clearly-labelled
# templates so the app can be shown without a provider. An unrecognised value
# falls back to "gemini" with a warning rather than silently degrading.
_MODE_RAW = os.environ.get("DETECTION_GENERATION_MODE", "gemini").strip().lower()
# "llm" is accepted as a provider-neutral alias for "gemini" (the LLM path).
if _MODE_RAW == "llm":
    _MODE_RAW = "gemini"
DETECTION_GENERATION_MODE = _MODE_RAW if _MODE_RAW in ("gemini", "demo") else "gemini"

if _MODE_RAW and _MODE_RAW != DETECTION_GENERATION_MODE:
    import logging as _logging

    _logging.getLogger(__name__).warning(
        "Unrecognised DETECTION_GENERATION_MODE=%r; using 'gemini'.", _MODE_RAW
    )

# ---------------------------------------------------------- Persistence

# SQLite file for saved investigations. Local, single-user, no server needed.
DATA_DIR = Path(os.environ.get("IGNITE_DATA_DIR", "data"))
INVESTIGATIONS_DB = Path(
    os.environ.get("IGNITE_DB_PATH", str(DATA_DIR / "investigations.db"))
)

# ------------------------------------------------------- LLM providers

# Which provider backs rule generation and the Assistant. Gemini stays the
# default; Anthropic and OpenAI suit organisations with an enterprise agreement,
# and Ollama keeps every prompt on your own hardware.
LLM_PROVIDERS = ("gemini", "anthropic", "openai", "ollama", "ellm")
_PROVIDER_RAW = os.environ.get("IGNITE_LLM_PROVIDER", "gemini").strip().lower()
LLM_PROVIDER = _PROVIDER_RAW if _PROVIDER_RAW in LLM_PROVIDERS else "gemini"

if _PROVIDER_RAW and _PROVIDER_RAW != LLM_PROVIDER:
    import logging as _logging

    _logging.getLogger(__name__).warning(
        "Unrecognised IGNITE_LLM_PROVIDER=%r; using 'gemini'.", _PROVIDER_RAW
    )

# Secrets. Read here, used only by api/services/llm.py, never serialised.
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-opus-5-5")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o")
OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "").rstrip("/")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.1")

# ELLM: your own LLM behind an OpenAI-compatible endpoint (an internal gateway,
# vLLM, LiteLLM, LM Studio, ...). Needs a base URL and model; the key is
# optional because many internal endpoints use network-level access instead.
ELLM_BASE_URL = os.environ.get("ELLM_BASE_URL", "").rstrip("/")
ELLM_MODEL = os.environ.get("ELLM_MODEL", "")
ELLM_API_KEY = os.environ.get("ELLM_API_KEY", "")

# Local models on a laptop CPU run at a few tokens per second, so generation
# with Ollama asks for less: fewer candidates, references and repairs, a
# context window large enough for the prompt plus the answer, and a bound on
# answer length. Hosted providers are unaffected.
OLLAMA_NUM_CTX = int(os.environ.get("OLLAMA_NUM_CTX", "8192"))
OLLAMA_NUM_PREDICT = int(os.environ.get("OLLAMA_NUM_PREDICT", "2048"))
OLLAMA_MAX_CANDIDATES = int(os.environ.get("OLLAMA_MAX_CANDIDATES", "1"))
OLLAMA_RETRIEVAL_TOP_K = int(os.environ.get("OLLAMA_RETRIEVAL_TOP_K", "1"))
OLLAMA_MAX_REPAIR_ATTEMPTS = int(os.environ.get("OLLAMA_MAX_REPAIR_ATTEMPTS", "1"))

# ------------------------------------------------------ Quality gates

# How many times failed quality checks are sent back to the model for repair.
# Each repair is one extra provider request, so keep this small on free tiers.
MAX_REPAIR_ATTEMPTS = int(os.environ.get("IGNITE_MAX_REPAIR_ATTEMPTS", "2"))

# A test search returning this many events or more is flagged as noisy.
NOISY_RESULT_THRESHOLD = int(os.environ.get("IGNITE_NOISY_THRESHOLD", "50"))

# ---------------------------------------------------------------- Splunk

# Management port (8089), not the web port. Configured on the server only, so
# the token never travels through the browser.
SPLUNK_URL = os.environ.get("SPLUNK_URL", "").rstrip("/")
SPLUNK_TOKEN = os.environ.get("SPLUNK_TOKEN", "")
SPLUNK_USERNAME = os.environ.get("SPLUNK_USERNAME", "")
SPLUNK_PASSWORD = os.environ.get("SPLUNK_PASSWORD", "")
SPLUNK_APP = os.environ.get("SPLUNK_APP", "search")
SPLUNK_OWNER = os.environ.get("SPLUNK_OWNER", "nobody")
SPLUNK_VERIFY_SSL = os.environ.get("SPLUNK_VERIFY_SSL", "true").strip().lower() in (
    "1", "true", "yes", "on",
)
SPLUNK_TIMEOUT = float(os.environ.get("SPLUNK_TIMEOUT", "60"))

# ------------------------------------------------------ Knowledge base

# Reference detections (Splunk ESCU + SigmaHQ) used for retrieval. Built by
# scripts/build_dataset.py; a small bundled sample is used until then.
KNOWLEDGE_DIR = Path(os.environ.get("IGNITE_KNOWLEDGE_DIR", str(DATA_DIR / "knowledge")))
KNOWLEDGE_RAW_DIR = KNOWLEDGE_DIR / "raw"
KNOWLEDGE_PROCESSED_DIR = KNOWLEDGE_DIR / "processed"
KNOWLEDGE_SAMPLE_DIR = KNOWLEDGE_DIR / "sample"
RETRIEVAL_TOP_K = int(os.environ.get("IGNITE_RETRIEVAL_TOP_K", "3"))

# ------------------------------------------------------------ Governance

# Name recorded in the audit log for reviews, edits and deployments. There is
# no login yet, so this identifies the operator running the API. Replace
# api.services.library.current_actor() when SSO is added.
OPERATOR_NAME = os.environ.get("IGNITE_OPERATOR", "")

# Minimum length of the written justification required to approve a rule
# that still fails quality checks.
OVERRIDE_MIN_CHARS = int(os.environ.get("IGNITE_OVERRIDE_MIN_CHARS", "20"))
