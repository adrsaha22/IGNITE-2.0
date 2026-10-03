"""Pydantic models for the Assistant, Testing Lab and saved investigations.

No model here carries a secret. The Assistant status model reports only whether
a key is configured — never the key, nor any fragment of it.
"""

from typing import Any

from pydantic import BaseModel, Field, field_validator

# ------------------------------------------------------------- AI Detection Assistant

COPILOT_ACTIONS = (
    "explain_rule",
    "explain_conditions",
    "find_gaps",
    "reduce_false_positives",
    "explain_validation",
    "explain_attack",
    "suggest_telemetry",
    "ask",
)


class CopilotTurn(BaseModel):
    """One turn of bounded conversation history."""

    role: str = Field(pattern="^(user|assistant)$")
    content: str = Field(max_length=4000)


class CopilotContext(BaseModel):
    """The slice of the investigation sent to the provider.

    Deliberately narrow: only these fields are ever forwarded, so the whole
    application state cannot leak into a provider request.
    """

    scenario: str = Field(default="", max_length=8000)
    rule: str = Field(default="", max_length=8000)
    rule_origin: str = Field(default="", max_length=200)
    techniques: list[dict[str, Any]] = Field(default_factory=list, max_length=40)
    validation_issues: list[str] = Field(default_factory=list, max_length=40)
    quality: dict[str, Any] = Field(default_factory=dict)
    entities: dict[str, Any] = Field(default_factory=dict)


class CopilotRequest(BaseModel):
    action: str = Field(default="explain_rule")
    question: str = Field(default="", max_length=2000)
    context: CopilotContext = Field(default_factory=CopilotContext)
    history: list[CopilotTurn] = Field(default_factory=list, max_length=12)

    @field_validator("action")
    @classmethod
    def known_action(cls, value: str) -> str:
        if value not in COPILOT_ACTIONS:
            raise ValueError(f"unknown action: {value}")
        return value


class CopilotSectionModel(BaseModel):
    heading: str
    body: str


class CopilotResponse(BaseModel):
    """An Assistant answer, or an explained failure. Never fabricated content."""

    ok: bool
    status: str
    # Plain text. Rendered as text by the frontend, never as HTML.
    text: str = ""
    sections: list[CopilotSectionModel] = Field(default_factory=list)
    message: str = ""
    model: str = ""
    ai_generated: bool = True


class CopilotStatus(BaseModel):
    """Whether the Assistant can be used. Carries no secret material."""

    configured: bool
    model: str
    provider: str = "google-gemini"
    message: str = ""


# ----------------------------------------------------------- Testing Lab


class TestEvent(BaseModel):
    """One synthetic event. Free-form fields, bounded in size."""

    fields: dict[str, Any] = Field(default_factory=dict)


class RuleTestRequest(BaseModel):
    rule: str = Field(min_length=1, max_length=20000)
    events: list[dict[str, Any]] = Field(default_factory=list, max_length=200)


class FieldObservationModel(BaseModel):
    field_name: str = Field(alias="field")
    operator: str
    expected: str
    actual: str | None = None
    matched: bool
    missing: bool = False

    model_config = {"populate_by_name": True}


class EventResultModel(BaseModel):
    event_id: str
    outcome: str
    observations: list[FieldObservationModel] = Field(default_factory=list)
    missing_fields: list[str] = Field(default_factory=list)
    reason: str = ""


class RuleTestResponse(BaseModel):
    """Local sample-test results.

    `validation_mode` is always "local_sample" — this endpoint never contacts
    a Splunk instance, and the UI reports it as distinct from static checks and
    from external runtime validation.
    """

    supported: bool
    results: list[EventResultModel] = Field(default_factory=list)
    unsupported: list[str] = Field(default_factory=list)
    referenced_fields: list[str] = Field(default_factory=list)
    error: str = ""
    matched_count: int = 0
    total_count: int = 0
    validation_mode: str = "local_sample"
    disclaimer: str = (
        "Evaluated by IGNITE's local SPL subset evaluator, not by Splunk. "
        "Unsupported constructs are listed and were not applied."
    )


class SampleSet(BaseModel):
    key: str
    label: str
    description: str
    events: list[dict[str, Any]]


# ------------------------------------------------------ Investigations


class InvestigationCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    notes: str = Field(default="", max_length=5000)
    payload: dict[str, Any] = Field(default_factory=dict)


class InvestigationUpdate(BaseModel):
    title: str | None = Field(default=None, max_length=200)
    notes: str | None = Field(default=None, max_length=5000)
    payload: dict[str, Any] | None = None


class InvestigationSummary(BaseModel):
    id: str
    title: str
    notes: str
    created_at: str
    updated_at: str
    schema_version: int


class InvestigationDetail(InvestigationSummary):
    payload: dict[str, Any] = Field(default_factory=dict)
    # Set when a record was saved under a different schema version.
    warning: str = ""


# ------------------------------------------------- LLM rule generation


class AttackMappingModel(BaseModel):
    """A technique mapping after independent verification.

    `reference_verified` means the ID exists in the bundled ATT&CK dataset.
    `mapping_supported` means evidence was also supplied linking this
    detection to it. The two are never conflated.
    """

    id: str
    name: str = ""
    reference_verified: bool
    mapping_supported: bool
    status: str
    evidence: str = ""
    note: str = ""
    is_subtechnique: bool = False
    tactics: list[str] = Field(default_factory=list)


class GeneratedCandidateModel(BaseModel):
    name: str
    purpose: str = ""
    spl: str
    hypothesis: str = ""
    behaviors: list[str] = Field(default_factory=list)
    attack_mappings: list[AttackMappingModel] = Field(default_factory=list)
    log_source: dict[str, Any] = Field(default_factory=dict)
    assumptions: list[str] = Field(default_factory=list)
    expected_positive_characteristics: list[str] = Field(default_factory=list)
    benign_near_matches: list[str] = Field(default_factory=list)
    blind_spots: list[str] = Field(default_factory=list)
    required_telemetry: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    # Findings from our deterministic checks, not the model's self-assessment.
    static_findings: list[str] = Field(default_factory=list)
    provenance: dict[str, Any] = Field(default_factory=dict)
    sigma_rule: str = ""
    spl_from_sigma: str = ""
    severity: str = ""
    response_actions: list[str] = Field(default_factory=list)
    how_to_implement: str = ""
    # Weighted quality checks computed by IGNITE (validators.summarize).
    validation: dict[str, Any] = Field(default_factory=dict)


class GenerateRulesRequest(BaseModel):
    scenario: str = Field(min_length=1, max_length=8000)

    @field_validator("scenario")
    @classmethod
    def not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("scenario must not be blank")
        return value


class GenerateRulesResponse(BaseModel):
    """LLM generation result.

    On failure `ok` is false with an explicit status; no template output is
    substituted, so a caller can never mistake fallback rules for generated
    ones.
    """

    ok: bool
    candidates: list[GeneratedCandidateModel] = Field(default_factory=list)
    status: str = "ok"
    message: str = ""
    provenance: dict[str, Any] = Field(default_factory=dict)
    generator: str = "llm"
    # "gemini" or "demo". Demo output is template-based and labelled as such.
    mode: str = "gemini"


class AttackDatasetInfo(BaseModel):
    """Provenance of the bundled ATT&CK data."""

    source: str
    version: str
    loaded_at: str
    current_techniques: int
    revoked_excluded: int
    available: bool
