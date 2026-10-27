"""Unauthenticated liveness probe (compose healthcheck) + the nginx auth_request
gate for the noVNC proxy."""

from __future__ import annotations

from fastapi import APIRouter, Cookie, HTTPException, Response

from app import auth

router = APIRouter(prefix="/api")


@router.get("/health")
async def health():
    return {"ok": True, "service": "etherhawk-api"}


@router.get("/novnc-auth")
async def novnc_auth(eh_token: str | None = Cookie(default=None)):
    """nginx calls this (auth_request) before proxying /novnc/ and /websockify.
    The dashboard sets the `eh_token` cookie on login; only a valid dashboard
    token or API key gets access to the live analyst browser. 204 = allow."""
    if auth.token_valid(eh_token):
        return Response(status_code=204)
    raise HTTPException(status_code=401, detail="Unauthorized")
