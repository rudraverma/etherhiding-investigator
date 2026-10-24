"""
EtherHawk API — deterministic EtherHiding detection orchestrator.

Served behind the UI's nginx (same origin), so no CORS is enabled. Every route
except /api/health requires the dashboard token or appliance API key.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI

from app import db
from app.config import CASES_DIR, MITM_DIR
from app.routers import health, investigate, cases, mitm, settings

log = logging.getLogger("etherhawk")

app = FastAPI(title="EtherHawk API", version="1.0.0", docs_url=None, redoc_url=None)


@app.on_event("startup")
async def _startup():
    CASES_DIR.mkdir(parents=True, exist_ok=True)
    MITM_DIR.mkdir(parents=True, exist_ok=True)
    db.init_db()
    log.info("EtherHawk API started")


app.include_router(health.router)
app.include_router(investigate.router)
app.include_router(cases.router)
app.include_router(mitm.router)
app.include_router(settings.router)
