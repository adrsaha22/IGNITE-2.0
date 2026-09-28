"""Pydantic models for the IGNITE 2.0 API contract.

These mirror what the existing detection modules actually return. Optional
fields are optional because the underlying pipeline genuinely may not produce
them — nothing here invents data to fill a shape.
"""

from typing import Any

from pydantic import BaseModel, Field, field_validator

# The rule scorer in modules/rule_scorer.py can exceed 100 (indicator bonuses
# stack), so candidate scores are reported on their own scale rather than being
# silently presented as a percentage.
RULE_SCORE_MAX = 125


class GenerateRequest(BaseModel):
    """Request to run the detection pipeline."""

    description: str = Field(min_length=1, max_length=8000)

    @field_validator("description")
    @classmethod
    def not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("description must not be blank")
        return value


class AIRequest(BaseModel):
    """Request for the optional LLM summary."""

    description: str = Field(min_length=1, max_length=8000)

    @field_validator("description")
    @classmethod
    def not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("description must not be blank")
        return value


class Technique(BaseModel):
    """A MITRE technique ID with its official name, when resolvable.

    ``name`` is empty when the ID is absent from the bundled ATT&CK data; it is
    never guessed. ``tactic`` is always None because the current pipeline does
    not produce tactic mappings.
    """

    id: str
    name: str = ""
    tactic: str | None = None


class CandidateRule(BaseModel):
    """One ranked detection candidate."""

    spl: str
    score: int
    score_max: int = RULE_SCORE_MAX
    origin: str
    has_conditions: bool = Field(
        description="Static text check: whether the query contains any field condition."
    )


class Entities(BaseModel):
    """Entities extracted from the description by modules/entity_extractor.py."""

    tools: list[str] = []
    indicators: list[str] = []
    logs: list[str] = []
    fields: list[str] = []


class Telemetry(BaseModel):
    """Telemetry requirements for the mapped techniques."""

    logs: list[str] = []
    fields: list[str] = []
    events: list[int] = []
    indicators: list[str] = []


class Validation(BaseModel):
    """Static validation report from modules/rule_validator.py.

    ``valid`` and ``issues`` can disagree — the validator may pass a rule while
    still listing issues. Both are reported verbatim so the UI can surface the
    contradiction rather than hide it.
    """

    valid: bool | None = None
    score: int | None = None
    score_max: int = 100
    issues: list[str] = []


class Quality(BaseModel):
    """Heuristic quality report from modules/rule_quality.py."""

    quality_score: int | None = None
    score_max: int = 100
    strengths: list[str] = []
    weaknesses: list[str] = []


class AutonomousEngine(BaseModel):
    """Output of the autonomous engine, which may be unavailable."""

    available: bool
    error: str | None = None
    techniques: list[Technique] = []
    telemetry: Telemetry = Telemetry()
    telemetry_rule: str = ""
    rule: str = ""
    rule_has_conditions: bool = False
    validation: Validation = Validation()
    quality: Quality = Quality()
    explanation: str = ""


class SigmaReference(BaseModel):
    """A Sigma rule that matched the mapped technique."""

    title: str
    spl: str
    tags: list[str] = []
    logsource: dict[str, Any] = {}
    score: int | None = None
    status: str | None = None


class AnalysisResponse(BaseModel):
    """Everything the frontend needs to render one analysis."""

    description: str
    generated_at: str
    primary_technique: Technique
    entities: Entities
    candidates: list[CandidateRule]
    best: CandidateRule | None = None
    autonomous: AutonomousEngine
    sigma_references: list[SigmaReference] = []
    warnings: list[str] = []
    rule_status: str = Field(
        default="generated — not validated against a live Splunk instance",
        description="Provenance of the generated SPL. Never implies external validation.",
    )


class AIStatus(BaseModel):
    """Availability of the optional LLM feature."""

    available: bool
    detail: str
    checked_at: str


class AIResponse(BaseModel):
    """Result of an optional AI summary request."""

    available: bool
    text: str | None = None
    error: str | None = None


class HealthResponse(BaseModel):
    """Service health plus static facts about the loaded corpora."""

    status: str
    mitre_techniques_loaded: int
    sigma_corpus_available: bool
    ai: AIStatus


class ErrorResponse(BaseModel):
    """User-facing error. Never carries a stack trace."""

    detail: str
