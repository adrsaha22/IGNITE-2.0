"""FastAPI application for IGNITE 2.0.

A thin HTTP layer over the existing Python detection modules. Run with:

    ./venv/bin/uvicorn api.main:app --reload --port 8000
"""

import logging

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import detection, workbench
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
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type"],
)

app.include_router(detection.router, prefix="/api")
app.include_router(workbench.router, prefix="/api")


@app.get("/")
def root() -> dict[str, str]:
    """Point callers at the docs."""
    return {"service": "IGNITE 2.0 API", "docs": "/docs", "health": "/api/health"}
