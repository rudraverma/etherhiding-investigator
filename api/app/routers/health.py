"""Unauthenticated liveness probe (used by the compose healthcheck)."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/api")


@router.get("/health")
async def health():
    return {"ok": True, "service": "etherhawk-api"}
