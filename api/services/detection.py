"""Service layer: adapts the existing detection modules to the API schemas.

Thin by design. Every rule, score, technique and finding comes from the modules
in ``modules/`` via ``ui.pipeline``; this file only reshapes that output into
the response models. No detection logic lives here.
"""

import logging
from datetime import datetime, timezone

from api.schemas.analysis import (
    AIResponse,
    AIStatus,
    AnalysisResponse,
    AutonomousEngine,
    CandidateRule,
    Entities,
    Quality,
    SigmaReference,
    Technique,
    Telemetry,
    Validation,
)
from ui import pipeline

logger = logging.getLogger(__name__)

# modules/ai_summary.py returns this prefix instead of raising on failure.
AI_ERROR_PREFIX = "AI analysis unavailable"


#  Keys the pipeline must supply for its result to be meaningful. Without them
#  the response would serialise into an empty-but-successful analysis, which the
#  UI would wrongly present as a legitimate zero-result run.
_REQUIRED_KEYS = ("description", "generated_at", "sigma", "entities", "ranked", "autonomous")


def run_analysis(description: str) -> AnalysisResponse:
    """Run the detection pipeline and map the result onto the API schema.

    Propagates exceptions to the route, which converts them into a safe
    user-facing error while logging the detail server-side.
    """
    raw = pipeline.run_analysis(description)

    if not isinstance(raw, dict):
        raise TypeError(f"pipeline returned {type(raw).__name__}, expected a mapping")

    missing = [key for key in _REQUIRED_KEYS if key not in raw]
    if missing:
        # Fail loudly rather than returning a hollow success.
        raise ValueError(f"pipeline result is missing required keys: {', '.join(missing)}")

    auto = raw.get("autonomous", {})

    candidates = [
        CandidateRule(
            spl=r.get("rule", ""),
            score=int(r.get("score", 0)),
            origin=r.get("origin", ""),
            has_conditions=bool(r.get("has_conditions")),
        )
        for r in raw.get("ranked", [])
    ]

    names = auto.get("technique_names", {})
    techniques = [
        # tactic stays None: the current pipeline does not map tactics.
        Technique(id=tid, name=names.get(tid, ""))
        for tid in auto.get("techniques", [])
    ]

    telemetry_raw = auto.get("telemetry") or {}
    validation_raw = auto.get("validation") or {}
    quality_raw = auto.get("quality") or {}

    autonomous = AutonomousEngine(
        available=bool(auto.get("available")),
        error=auto.get("error"),
        techniques=techniques,
        telemetry=Telemetry(
            logs=list(telemetry_raw.get("logs", [])),
            fields=list(telemetry_raw.get("fields", [])),
            events=[int(e) for e in telemetry_raw.get("events", [])],
            indicators=list(telemetry_raw.get("indicators", [])),
        ),
        telemetry_rule=auto.get("telemetry_rule", "") or "",
        rule=auto.get("rule", "") or "",
        rule_has_conditions=bool(auto.get("rule_has_conditions")),
        validation=Validation(
            valid=validation_raw.get("valid"),
            score=validation_raw.get("score"),
            issues=list(validation_raw.get("issues", [])),
        ),
        quality=Quality(
            quality_score=quality_raw.get("quality_score"),
            strengths=list(quality_raw.get("strengths", [])),
            weaknesses=list(quality_raw.get("weaknesses", [])),
        ),
        explanation=auto.get("explanation", "") or "",
    )

    entities_raw = raw.get("entities", {})

    return AnalysisResponse(
        description=raw.get("description", description),
        generated_at=raw.get("generated_at", ""),
        primary_technique=Technique(
            id=raw.get("mitre_id", "Unknown"),
            name="" if raw.get("mitre_name") == "Unknown" else raw.get("mitre_name", ""),
        ),
        entities=Entities(
            tools=list(entities_raw.get("tools", [])),
            indicators=list(entities_raw.get("indicators", [])),
            logs=list(entities_raw.get("logs", [])),
            fields=list(entities_raw.get("fields", [])),
        ),
        candidates=candidates,
        best=candidates[0] if candidates else None,
        autonomous=autonomous,
        sigma_references=[
            SigmaReference(
                title=d.get("title", "") or "Untitled",
                spl=d.get("spl", "") or "",
                tags=list(d.get("tags", []) or []),
                logsource=d.get("logsource", {}) or {},
                score=d.get("score"),
                status=d.get("status"),
            )
            for d in raw.get("sigma", {}).get("detections", [])
        ],
        warnings=pipeline.validation_warnings(raw),
    )


def export_payload(description: str) -> dict:
    """Build the JSON export for a freshly run analysis."""
    return pipeline.export_payload(pipeline.run_analysis(description))


def ai_status() -> AIStatus:
    """Report whether the local model server is reachable.

    Uses a short connect timeout so an unreachable server fails fast instead of
    making the caller wait. Route-level caching keeps ordinary page renders from
    hammering the model server.
    """
    checked = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        import requests

        from api.settings import OLLAMA_BASE_URL

        response = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=(2, 3))
        if response.status_code == 200:
            return AIStatus(available=True, detail="model server reachable", checked_at=checked)
        return AIStatus(
            available=False,
            detail=f"model server returned HTTP {response.status_code}",
            checked_at=checked,
        )
    except Exception as exc:
        logger.info("AI status check failed: %s: %s", type(exc).__name__, exc)
        return AIStatus(available=False, detail="model server unreachable", checked_at=checked)


def run_ai_analysis(description: str) -> AIResponse:
    """Call the existing AI summary feature, unchanged.

    ``modules.ai_summary.summarize_attack`` swallows its own exceptions and
    returns a marker string on failure, so that contract is respected here
    rather than modified. Never substitutes fabricated text for a real answer.
    """
    from modules.ai_summary import summarize_attack

    try:
        text = summarize_attack(description)
    except Exception as exc:
        logger.warning("AI analysis raised: %s: %s", type(exc).__name__, exc)
        return AIResponse(
            available=False,
            error="AI analysis is unavailable — the language model could not be reached.",
        )

    if isinstance(text, str) and text.startswith(AI_ERROR_PREFIX):
        # Keep the underlying detail for the collapsible technical section.
        logger.info("AI analysis unavailable: %s", text)
        return AIResponse(available=False, error=text)

    return AIResponse(available=True, text=text)


def corpus_facts() -> tuple[int, bool]:
    """Report how much reference data is actually loaded.

    Lets the UI state plainly that the Sigma corpus is empty rather than
    silently showing zero matches.
    """
    techniques = 0
    try:
        from modules.mitre_lookup import MITRE_DATA

        techniques = len(MITRE_DATA)
    except Exception as exc:
        logger.warning("Could not read MITRE data: %s", exc)

    sigma_available = False
    try:
        from pathlib import Path

        from modules.sigma_search import sigma_path

        root = Path(sigma_path())
        sigma_available = root.is_dir() and any(root.rglob("*.yml"))
    except Exception as exc:
        logger.warning("Could not inspect Sigma corpus: %s", exc)

    return techniques, sigma_available
