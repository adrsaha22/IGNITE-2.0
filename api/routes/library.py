"""Routes for the rule library, review workflow, audit log, coverage and platform.

Routes stay thin: validate input, call a service, map LibraryError onto its
status code. No secret is ever placed in a response.
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Response

from api.schemas.library import (
    AIProviderChoice,
    AIProviders,
    AuditEntry,
    DeployRequest,
    KnowledgeStatus,
    LibraryRule,
    PlatformStatus,
    ProviderStatus,
    RevalidateRequest,
    ReviewRequest,
    RuleSummary,
    RuleUpdateRequest,
    SaveRuleRequest,
    SplunkStatus,
)
from api.services import (
    ai_switch,
    coverage,
    exporters,
    knowledge,
    library,
    llm,
    rule_generator,
    splunk_client,
)
from api.services.sigma_tools import HAVE_PYSIGMA

logger = logging.getLogger(__name__)
router = APIRouter()


def _fail(exc: library.LibraryError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=str(exc))


# ------------------------------------------------------------------- library


@router.get("/library/rules", response_model=list[RuleSummary])
def list_rules(status: str = "", q: str = "") -> list[RuleSummary]:
    if status and status not in library.STATUSES:
        raise HTTPException(status_code=422, detail=f"status must be one of {list(library.STATUSES)}")
    return [RuleSummary(**row) for row in library.list_rules(status, q)]


@router.post("/library/rules", response_model=LibraryRule, status_code=201)
def save_rule(request: SaveRuleRequest) -> LibraryRule:
    """Save a generated candidate as a draft. Every check is recomputed here."""
    try:
        return LibraryRule(**library.save_candidate(request.candidate, request.scenario))
    except library.LibraryError as exc:
        raise _fail(exc) from exc


@router.get("/library/rules/{rule_id}", response_model=LibraryRule)
def get_rule(rule_id: str) -> LibraryRule:
    try:
        return LibraryRule(**library.get_rule(rule_id))
    except library.LibraryError as exc:
        raise _fail(exc) from exc


@router.get("/library/rules/{rule_id}/versions/{version}", response_model=LibraryRule)
def get_rule_version(rule_id: str, version: int) -> LibraryRule:
    try:
        return LibraryRule(**library.get_version(rule_id, version))
    except library.LibraryError as exc:
        raise _fail(exc) from exc


@router.patch("/library/rules/{rule_id}", response_model=LibraryRule)
def update_rule(rule_id: str, request: RuleUpdateRequest) -> LibraryRule:
    changes = request.model_dump(exclude={"expected_version", "note"}, exclude_none=True)
    try:
        return LibraryRule(
            **library.update_rule(rule_id, changes, request.expected_version, request.note)
        )
    except library.LibraryError as exc:
        raise _fail(exc) from exc


@router.post("/library/rules/{rule_id}/review", response_model=LibraryRule)
def review_rule(rule_id: str, request: ReviewRequest) -> LibraryRule:
    try:
        return LibraryRule(
            **library.review(rule_id, request.decision, request.note, request.override_justification)
        )
    except library.LibraryError as exc:
        raise _fail(exc) from exc


@router.post("/library/rules/{rule_id}/revalidate", response_model=LibraryRule)
def revalidate_rule(rule_id: str, request: RevalidateRequest) -> LibraryRule:
    try:
        return LibraryRule(**library.revalidate(rule_id, request.run_test_search, request.earliest))
    except library.LibraryError as exc:
        raise _fail(exc) from exc


@router.post("/library/rules/{rule_id}/deploy", response_model=LibraryRule)
def deploy_rule(rule_id: str, request: DeployRequest) -> LibraryRule:
    try:
        return LibraryRule(
            **library.deploy(rule_id, request.mode, request.cron, request.earliest, request.actions)
        )
    except library.LibraryError as exc:
        raise _fail(exc) from exc


@router.delete("/library/rules/{rule_id}", status_code=204)
def delete_rule(rule_id: str) -> None:
    try:
        library.delete_rule(rule_id)
    except library.LibraryError as exc:
        raise _fail(exc) from exc


@router.get("/library/rules/{rule_id}/export/{fmt}")
def export_rule(rule_id: str, fmt: str) -> Response:
    """Download one rule in a deployable format."""
    if fmt not in exporters.FORMATS:
        raise HTTPException(status_code=422, detail=f"format must be one of {list(exporters.FORMATS)}")
    try:
        rule = library.get_rule(rule_id)
    except library.LibraryError as exc:
        raise _fail(exc) from exc
    rule.pop("versions", None)
    filename, content, media = exporters.export(rule, fmt)
    library.log_event("exported", rule, f"Exported as {fmt}.")
    return Response(
        content=content,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# --------------------------------------------------------------------- audit


@router.get("/audit", response_model=list[AuditEntry])
def audit(limit: int = 500, action: str = "", rule_id: str = "") -> list[AuditEntry]:
    return [AuditEntry(**row) for row in library.list_audit(limit, action, rule_id)]


@router.get("/audit/export.csv")
def audit_csv() -> Response:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return Response(
        content=library.audit_csv(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="ignite_audit_{stamp}.csv"'},
    )


# ------------------------------------------------------------------ coverage


@router.get("/coverage")
def attack_coverage() -> dict:
    """ATT&CK matrix coloured by your strongest coverage of each technique."""
    return coverage.build_coverage()


# ------------------------------------------------------------------ platform


def _splunk_status(check: bool) -> SplunkStatus:
    return SplunkStatus(**splunk_client.status(check), deploy_modes=splunk_client.DEPLOY_MODES)


def _knowledge_status() -> KnowledgeStatus:
    stats = knowledge.dataset_stats()
    return KnowledgeStatus(
        location=stats["location"],
        path=stats["path"],
        counts={k: int(v) for k, v in (stats.get("counts") or {}).items()},
        techniques_covered=stats.get("techniques_covered"),
        sources=stats.get("sources") or {},
        approved_rules=library.counts().get("approved", 0),
        retrieval="tf-idf" if knowledge.HAVE_SKLEARN else "token-overlap",
        last_evaluation=knowledge.last_evaluation(),
    )


@router.get("/splunk/status", response_model=SplunkStatus)
def splunk_status(check: bool = False) -> SplunkStatus:
    """Splunk configuration, and reachability when `check=true`. Never returns the token."""
    return _splunk_status(check)


@router.get("/platform/status", response_model=PlatformStatus)
def platform_status() -> PlatformStatus:
    """Everything the Platform view shows, in one request."""
    return PlatformStatus(
        provider=ProviderStatus(
            **llm.provider_status(), generation_mode=rule_generator.DETECTION_GENERATION_MODE
        ),
        splunk=_splunk_status(False),
        knowledge=_knowledge_status(),
        library=library.counts(),
        operator=library.current_actor(),
        pysigma=HAVE_PYSIGMA,
    )


# ---------------------------------------------------------- AI switcher


@router.get("/ai/providers", response_model=AIProviders)
def ai_providers() -> AIProviders:
    """Which AI is active, and which can be chosen. Keys stay in .env."""
    return AIProviders(**ai_switch.options())


@router.put("/ai/provider", response_model=AIProviders)
def choose_ai_provider(request: AIProviderChoice) -> AIProviders:
    try:
        return AIProviders(**ai_switch.select(request.provider))
    except ai_switch.SwitchError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/ai/provider/reset", response_model=AIProviders)
def reset_ai_provider() -> AIProviders:
    """Return to the provider named in .env."""
    return AIProviders(**ai_switch.reset())
