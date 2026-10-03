"""Pydantic models for the rule library, audit log, coverage and platform status.

No model here carries a secret: Splunk and provider status report only whether
something is configured, never a token or key.
"""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Splunk relative time modifiers such as -20m, -24h, -7d@d, or now.
TIME_MODIFIER = r"^(now|0|-\d{1,4}(s|m|h|d|w|mon|y)(@[a-z]{1,4})?)$"
CRON = r"^[0-9*/,\- ]{9,100}$"


# ------------------------------------------------------------------- library


class MappingInput(BaseModel):
    id: str = Field(max_length=20)
    evidence: str = Field(default="", max_length=2000)


class SaveRuleRequest(BaseModel):
    """A generated candidate to store as a draft. Re-verified server-side."""

    candidate: dict[str, Any]
    scenario: str = Field(default="", max_length=8000)

    @field_validator("candidate")
    @classmethod
    def has_spl(cls, value: dict[str, Any]) -> dict[str, Any]:
        if not str(value.get("spl", "")).strip():
            raise ValueError("candidate must contain an SPL query")
        if len(str(value.get("spl", ""))) > 20000 or len(str(value.get("sigma_rule", ""))) > 20000:
            raise ValueError("candidate is too large")
        return value


class RuleSummary(BaseModel):
    id: str
    title: str
    status: str
    severity: str
    quality_score: int
    quality_grade: str
    passed: bool
    technique_ids: list[str]
    deployment_mode: str
    deployment_stale: bool
    version: int
    created_at: str
    updated_at: str
    created_by: str
    demo: bool = False


class LibraryRule(BaseModel):
    """A full library rule. Extra fields (hypothesis, assumptions, …) pass through."""

    model_config = ConfigDict(extra="allow")

    id: str
    title: str
    description: str = ""
    scenario: str = ""
    spl: str
    sigma_rule: str = ""
    spl_from_sigma: str = ""
    severity: str = ""
    attack_mappings: list[dict[str, Any]] = Field(default_factory=list)
    benign_near_matches: list[str] = Field(default_factory=list)
    response_actions: list[str] = Field(default_factory=list)
    how_to_implement: str = ""
    validation: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)
    status: str
    review: dict[str, Any] | None = None
    deployment: dict[str, Any] | None = None
    version: int
    created_at: str
    updated_at: str
    created_by: str
    versions: list[dict[str, Any]] = Field(default_factory=list)


class RuleUpdateRequest(BaseModel):
    """An edit. `expected_version` guards against overwriting someone else's change."""

    expected_version: int = Field(ge=1)
    note: str = Field(default="", max_length=2000)
    title: str | None = Field(default=None, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    spl: str | None = Field(default=None, max_length=20000)
    sigma_rule: str | None = Field(default=None, max_length=20000)
    severity: str | None = Field(default=None, max_length=20)
    benign_near_matches: list[str] | None = Field(default=None, max_length=30)
    response_actions: list[str] | None = Field(default=None, max_length=30)
    how_to_implement: str | None = Field(default=None, max_length=2000)
    attack_mappings: list[MappingInput] | None = Field(default=None, max_length=20)


class ReviewRequest(BaseModel):
    decision: str = Field(pattern="^(approve|reject)$")
    note: str = Field(default="", max_length=2000)
    override_justification: str = Field(default="", max_length=2000)


class RevalidateRequest(BaseModel):
    run_test_search: bool = False
    earliest: str = Field(default="-24h", pattern=TIME_MODIFIER)


class DeployRequest(BaseModel):
    mode: str = Field(pattern="^(disabled|shadow|live)$")
    cron: str = Field(default="*/15 * * * *", pattern=CRON)
    earliest: str = Field(default="-20m", pattern=TIME_MODIFIER)
    # Comma-separated Splunk alert action names (e.g. "email,webhook"); live mode only.
    actions: str = Field(default="", max_length=200, pattern=r"^[a-z0-9_, ]*$")


# --------------------------------------------------------------------- audit


class AuditEntry(BaseModel):
    seq: int
    at: str
    actor: str
    action: str
    rule_id: str
    rule_title: str
    detail: str


# -------------------------------------------------------------- platform


class SplunkStatus(BaseModel):
    configured: bool
    url: str
    app: str
    verify_ssl: bool
    auth: str
    reachable: bool | None = None
    server: str = ""
    version: str = ""
    message: str = ""
    deploy_modes: dict[str, str] = Field(default_factory=dict)


class ProviderStatus(BaseModel):
    provider: str
    label: str
    model: str
    configured: bool
    available_providers: list[str]
    message: str = ""
    data_leaves_network: bool
    generation_mode: str


class KnowledgeStatus(BaseModel):
    location: str
    path: str
    counts: dict[str, int] = Field(default_factory=dict)
    techniques_covered: int | None = None
    sources: dict[str, Any] = Field(default_factory=dict)
    approved_rules: int = 0
    retrieval: str
    last_evaluation: dict[str, Any] | None = None


class PlatformStatus(BaseModel):
    provider: ProviderStatus
    splunk: SplunkStatus
    knowledge: KnowledgeStatus
    library: dict[str, int]
    operator: str
    pysigma: bool


# ----------------------------------------------------------- AI switcher


class AIProviderOption(BaseModel):
    id: str
    label: str
    model: str
    # The key is present in .env (always true for Ollama and Demo).
    configured: bool
    # Configured and, for Ollama, the server is up with the model installed.
    ready: bool
    message: str = ""
    local: bool
    key_env: str = ""


class AIProviders(BaseModel):
    active: str
    env_default: str
    overridden: bool
    options: list[AIProviderOption]


class AIProviderChoice(BaseModel):
    provider: str = Field(pattern="^(gemini|anthropic|openai|ollama|ellm|demo)$")
