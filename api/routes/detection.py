"""API routes for detection generation, AI analysis and health.

Routes stay thin: validate input, call the service layer, map failures onto
status codes. User-facing errors never carry a stack trace; the detail is logged
server-side instead.
"""

import logging
import time

from fastapi import APIRouter, HTTPException

from api.schemas.analysis import (
    AIStatus,
    AnalysisResponse,
    GenerateRequest,
    HealthResponse,
)
from api.services import detection
from api.settings import AI_STATUS_TTL_SECONDS

logger = logging.getLogger(__name__)
router = APIRouter()

# Short-lived cache so repeated page renders do not probe the model server.
_ai_cache: dict[str, object] = {"value": None, "at": 0.0}


def _cached_ai_status(force: bool = False) -> AIStatus:
    now = time.monotonic()
    cached = _ai_cache.get("value")
    if not force and cached is not None and (now - float(_ai_cache["at"])) < AI_STATUS_TTL_SECONDS:
        return cached  # type: ignore[return-value]

    status = detection.ai_status()
    _ai_cache["value"] = status
    _ai_cache["at"] = now
    return status


@router.get("/health", response_model=HealthResponse)
def health(refresh: bool = False) -> HealthResponse:
    """Service health, corpus facts and AI availability."""
    techniques, sigma_available = detection.corpus_facts()
    return HealthResponse(
        status="ok",
        mitre_techniques_loaded=techniques,
        sigma_corpus_available=sigma_available,
        ai=_cached_ai_status(force=refresh),
    )


@router.post("/analyze", response_model=AnalysisResponse)
def analyze(request: GenerateRequest) -> AnalysisResponse:
    """Run the detection pipeline over an attack description."""
    try:
        return detection.run_analysis(request.description.strip())
    except Exception as exc:
        # Log the real cause; return a safe message.
        logger.exception("Detection pipeline failed")
        raise HTTPException(
            status_code=500,
            detail=(
                "The detection pipeline failed while analysing this description. "
                "Please try again or adjust the input."
            ),
        ) from exc


@router.post("/export")
def export(request: GenerateRequest) -> dict:
    """Return the full JSON export for a description.

    Provided for clients that prefer the backend to assemble the export; the
    frontend can also build it from an /analyze response.
    """
    try:
        return detection.export_payload(request.description.strip())
    except Exception as exc:
        logger.exception("Export generation failed")
        raise HTTPException(
            status_code=500, detail="Could not generate the export for this description."
        ) from exc
