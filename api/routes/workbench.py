"""Routes for the AI Copilot, Testing Lab and saved investigations.

Routes stay thin: validate input, call a service, map failures onto status
codes. No secret is ever placed in a response.
"""

import logging

from fastapi import APIRouter, HTTPException

from api.schemas.workbench import (
    AttackDatasetInfo,
    CopilotRequest,
    CopilotResponse,
    CopilotSectionModel,
    CopilotStatus,
    InvestigationCreate,
    InvestigationDetail,
    InvestigationSummary,
    InvestigationUpdate,
    GenerateRulesRequest,
    GenerateRulesResponse,
    RuleTestRequest,
    RuleTestResponse,
    SampleSet,
)
from api.services import attack, llm, rule_generator, spl_eval, store
from api.settings import GEMINI_MODEL

logger = logging.getLogger(__name__)
router = APIRouter()


# ------------------------------------------------------------- AI Copilot


@router.get("/copilot/status", response_model=CopilotStatus)
def copilot_status() -> CopilotStatus:
    """Whether the Copilot is configured. Reports no key material."""
    configured = llm.is_configured()
    return CopilotStatus(
        configured=configured,
        model=GEMINI_MODEL,
        message="" if configured else llm.STATUS_MESSAGE[llm.LLMStatus.NOT_CONFIGURED],
    )


@router.post("/copilot/ask", response_model=CopilotResponse)
def copilot_ask(request: CopilotRequest) -> CopilotResponse:
    """Run a Copilot action against the current investigation context.

    Provider failures are returned as 200 with `ok: false` and an explanatory
    status, so an unavailable Copilot is a normal degraded state rather than a
    client error that breaks the page.
    """
    result = llm.generate(
        action=request.action,
        question=request.question,
        context=request.context.model_dump(),
        history=[turn.model_dump() for turn in request.history],
    )

    return CopilotResponse(
        ok=result.ok,
        status=result.status.value,
        text=result.text,
        sections=[
            CopilotSectionModel(heading=section.heading, body=section.body)
            for section in result.sections
        ],
        message=result.message,
        model=result.model,
    )


# ------------------------------------------------------------ Testing Lab


@router.get("/testlab/samples", response_model=list[SampleSet])
def sample_sets() -> list[SampleSet]:
    """Synthetic sample event sets for common defensive detections."""
    return [
        SampleSet(
            key=key,
            label=value["label"],
            description=value["description"],
            events=value["events"],
        )
        for key, value in spl_eval.SAMPLE_EVENT_SETS.items()
    ]


@router.post("/testlab/run", response_model=RuleTestResponse)
def run_test(request: RuleTestRequest) -> RuleTestResponse:
    """Test a rule against synthetic events using the local evaluator."""
    try:
        report = spl_eval.evaluate(request.rule, request.events)
    except Exception as exc:
        logger.exception("Local rule evaluation failed")
        raise HTTPException(
            status_code=500, detail="The rule could not be evaluated locally."
        ) from exc

    results = [
        {
            "event_id": result.event_id,
            "outcome": result.outcome.value,
            "observations": [
                {
                    "field": observation.field,
                    "operator": observation.operator,
                    "expected": observation.expected,
                    "actual": observation.actual,
                    "matched": observation.matched,
                    "missing": observation.missing,
                }
                for observation in result.observations
            ],
            "missing_fields": result.missing_fields,
            "reason": result.reason,
        }
        for result in report.results
    ]

    matched = sum(1 for result in report.results if result.outcome.value == "match")

    return RuleTestResponse(
        supported=report.supported,
        results=results,
        unsupported=report.unsupported,
        referenced_fields=report.referenced_fields,
        error=report.error,
        matched_count=matched,
        total_count=len(report.results),
    )


# -------------------------------------------------------- Investigations


@router.get("/investigations", response_model=list[InvestigationSummary])
def list_investigations(q: str = "") -> list[InvestigationSummary]:
    """List saved investigations, newest first."""
    return [InvestigationSummary(**row) for row in store.list_investigations(q)]


@router.post("/investigations", response_model=InvestigationDetail, status_code=201)
def create_investigation(request: InvestigationCreate) -> InvestigationDetail:
    record = store.create_investigation(request.title, request.notes, request.payload)
    return InvestigationDetail(**record)


@router.get("/investigations/{investigation_id}", response_model=InvestigationDetail)
def get_investigation(investigation_id: str) -> InvestigationDetail:
    record = store.get_investigation(investigation_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return InvestigationDetail(**record)


@router.patch("/investigations/{investigation_id}", response_model=InvestigationDetail)
def update_investigation(
    investigation_id: str, request: InvestigationUpdate
) -> InvestigationDetail:
    record = store.update_investigation(
        investigation_id,
        title=request.title,
        notes=request.notes,
        payload=request.payload,
    )
    if record is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return InvestigationDetail(**record)


@router.post(
    "/investigations/{investigation_id}/duplicate",
    response_model=InvestigationDetail,
    status_code=201,
)
def duplicate_investigation(investigation_id: str) -> InvestigationDetail:
    record = store.duplicate_investigation(investigation_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return InvestigationDetail(**record)


@router.delete("/investigations/{investigation_id}", status_code=204)
def delete_investigation(investigation_id: str) -> None:
    if not store.delete_investigation(investigation_id):
        raise HTTPException(status_code=404, detail="Investigation not found.")


# --------------------------------------------- LLM rule generation


@router.get("/attack/dataset", response_model=AttackDatasetInfo)
def attack_dataset() -> AttackDatasetInfo:
    """Provenance of the bundled ATT&CK dataset, so the UI can cite a version."""
    return AttackDatasetInfo(**attack.dataset_provenance())


@router.post("/rules/generate", response_model=GenerateRulesResponse)
def generate_rules(request: GenerateRulesRequest) -> GenerateRulesResponse:
    """Generate detection candidates from the scenario using the LLM provider.

    Returns 200 with ``ok: false`` and an explicit status when the provider is
    unavailable or its output is unusable. Nothing is substituted from the
    deterministic template pipeline, so a client can never mistake fallback
    output for generated output.
    """
    try:
        result = rule_generator.generate_candidates(request.scenario.strip())
    except Exception as exc:
        logger.exception("Rule generation failed")
        raise HTTPException(
            status_code=500, detail="Rule generation failed unexpectedly."
        ) from exc

    return GenerateRulesResponse(
        ok=result.ok,
        candidates=[
            {
                "name": c.name,
                "purpose": c.purpose,
                "spl": c.spl,
                "hypothesis": c.hypothesis,
                "behaviors": c.behaviors,
                "attack_mappings": c.attack_mappings,
                "log_source": c.log_source,
                "assumptions": c.assumptions,
                "expected_positive_characteristics": c.expected_positive_characteristics,
                "benign_near_matches": c.benign_near_matches,
                "blind_spots": c.blind_spots,
                "required_telemetry": c.required_telemetry,
                "references": c.references,
                "static_findings": c.static_findings,
                "provenance": c.provenance,
            }
            for c in result.candidates
        ],
        status=result.status,
        message=result.message,
        provenance=result.provenance,
        mode=result.mode,
        generator="template" if result.mode == "demo" else "llm",
    )
