"""Settings control panel. Secrets are masked on read and only overwritten when a
real new value is supplied (the mask sentinel is ignored). The appliance API key is
generated here and shown exactly once."""

from __future__ import annotations

import json
import secrets

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app import db
from app.auth import require_auth
from app.config import SETTING_KEYS, SECRET_KEYS, DEFAULT_BRANDING

router = APIRouter(prefix="/api", dependencies=[Depends(require_auth)])

MASK = "********"
# Non-secret keys exposed/editable through the panel.
EDITABLE = sorted(SETTING_KEYS)


def _masked_value(key: str) -> str:
    val = db.get_setting(key)
    if key in SECRET_KEYS:
        return MASK if val else ""
    return val


@router.get("/settings")
async def get_settings():
    out = {k: _masked_value(k) for k in EDITABLE if k != "branding"}
    out["secret_set"] = {k: bool(db.get_setting(k)) for k in SECRET_KEYS}
    return {"ok": True, "settings": out}


class SettingsBody(BaseModel):
    # Free-form map of key -> value; unknown keys ignored, masked secrets skipped.
    values: dict


@router.post("/settings")
async def update_settings(body: SettingsBody):
    updated = []
    for key, value in (body.values or {}).items():
        if key not in SETTING_KEYS or key == "branding":
            continue
        if key in SECRET_KEYS and value == MASK:
            continue  # unchanged masked secret
        db.set_setting(key, "" if value is None else str(value))
        updated.append(key)
    return {"ok": True, "updated": updated}


@router.post("/settings/apikey")
async def generate_api_key():
    key = secrets.token_hex(24)
    db.set_setting("api_key", key)
    # Shown once; subsequent GETs only report that it is set.
    return {"ok": True, "api_key": key}


# ── Branding (used by the UI header/footer) ──────────────────────────────────
@router.get("/config")
async def get_config():
    import os
    raw = db.get_setting("branding")
    branding = dict(DEFAULT_BRANDING)
    if raw:
        try:
            branding.update(json.loads(raw))
        except Exception:
            pass
    # Port the interactive browser's noVNC view is published on (host side), so the
    # dashboard can build the embed URL: https://<dashboard-host>:<kasm_port>/
    kasm_port = os.getenv("KASM_PORT", "6901")
    return {"ok": True, "branding": branding, "kasm_port": kasm_port}


class BrandingBody(BaseModel):
    branding: dict


@router.post("/config")
async def set_config(body: BrandingBody):
    db.set_setting("branding", json.dumps(body.branding or {}))
    return {"ok": True}
