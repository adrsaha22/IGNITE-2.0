"""FastAPI application for IGNITE 2.0.

A thin HTTP layer over the existing Python detection modules. Run with:

    ./venv/bin/uvicorn api.main:app --reload --port 8000
"""

import logging
import threading

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import detection, library, workbench
from api.settings import CORS_ORIGINS

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(application: FastAPI):
    """Log the mounted API routes at startup.

    A server started before a route existed keeps serving 404 for it, which
    presents as a frontend bug. Logging the routes makes a stale process
    obvious: if an expected path is missing here, the running process predates
    the code on disk and needs restarting.
    """
    paths = sorted(application.openapi().get("paths", {}))
    logger.info("API routes mounted (%d): %s", len(paths), ", ".join(paths))

    # Index the Sigma corpus in the background (a few seconds for SigmaHQ),
    # so the first analysis does not pay for it.
    def warm_sigma_index() -> None:
        try:
            from modules.sigma_search import corpus_size

            logger.info("Sigma corpus indexed: %d rules", corpus_size())
        except Exception:
            logger.exception("Sigma corpus could not be indexed")

    threading.Thread(target=warm_sigma_index, daemon=True).start()

    # Re-apply the AI provider chosen on the dashboard before the last restart.
    from api.services import ai_switch

    ai_switch.restore_saved_choice()
    yield


app = FastAPI(
    title="IGNITE 2.0 API",
    description="Detection rule generation over the existing Python engine.",
    version="2.0.0",
    lifespan=lifespan,
)

# Restricted to the local dev frontend rather than a wildcard origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Content-Type"],
)

app.include_router(detection.router, prefix="/api")
app.include_router(workbench.router, prefix="/api")
app.include_router(library.router, prefix="/api")


@app.get("/")
def root() -> dict[str, str]:
    """Point callers at the docs."""
    return {"service": "IGNITE 2.0 API", "docs": "/docs", "health": "/api/health"}
