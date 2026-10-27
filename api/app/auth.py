"""
Authentication. A single shared dashboard token OR the generated appliance API key
grants access. Compared in constant time. The appliance triggers outbound visits to
attacker infrastructure, so every route except /api/health requires auth.
"""

from __future__ import annotations

import hmac

from fastapi import Header, HTTPException, status

from app import db

# Placeholder values shipped in .env.example — must never grant access if left unchanged.
_PLACEHOLDERS = {"change-me-openssl-rand-hex-32", "change-me", ""}


def _ok(candidate: str, secret: str) -> bool:
    secret = (secret or "").strip()
    candidate = (candidate or "").strip()
    if not secret or not candidate or secret in _PLACEHOLDERS:
        return False
    return hmac.compare_digest(candidate, secret)


def token_valid(candidate: str | None) -> bool:
    """True if `candidate` matches the dashboard token or the appliance API key.
    Used by the nginx auth_request gate for the noVNC proxy (cookie-based)."""
    return _ok(candidate or "", db.get_setting("dashboard_token")) or \
        _ok(candidate or "", db.get_setting("api_key"))


async def require_auth(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
) -> None:
    token = db.get_setting("dashboard_token")
    api_key = db.get_setting("api_key")

    bearer = ""
    if authorization and authorization.lower().startswith("bearer "):
        bearer = authorization[7:]

    if _ok(bearer, token) or _ok(x_api_key or "", api_key):
        return

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized",
        headers={"WWW-Authenticate": "Bearer"},
    )
