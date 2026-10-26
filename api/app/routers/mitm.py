"""Live MITM flow feed for the dashboard MITM tab. Reads the proxy's shared JSONL
and returns the flows relevant to a case (its target domain, from its start time),
or a recent global tail. Driven by polling from the UI."""

from __future__ import annotations

import json
from datetime import datetime

import httpx
from fastapi import APIRouter, Depends, Query

from app import db
from app.auth import require_auth
from app.config import MITM_FLOWS_PATH, INTERACTIVE_URL

router = APIRouter(prefix="/api", dependencies=[Depends(require_auth)])

_MAX_RETURN = 1500
_TAIL_BYTES = 3_000_000


def _read_tail(max_bytes: int = _TAIL_BYTES) -> list[dict]:
    """Seek-based tail read so a large flows.jsonl is never loaded wholesale (M1)."""
    if not MITM_FLOWS_PATH.exists():
        return []
    out: list[dict] = []
    try:
        size = MITM_FLOWS_PATH.stat().st_size
        with open(MITM_FLOWS_PATH, "rb") as f:
            if size > max_bytes:
                f.seek(size - max_bytes)
                f.readline()  # discard partial line
            raw = f.read()
        for line in raw.decode("utf-8", "replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    except Exception:
        return []
    return out


@router.get("/mitm/flows")
async def flows(id: str = Query(...)):
    row = db.get_case(id)
    if not row:
        return {"ok": False, "error": "unknown case", "flows": []}
    domain = (row.get("domain") or "").lower()
    try:
        start_epoch = datetime.fromisoformat(row["created_at"]).timestamp()
    except Exception:
        start_epoch = 0

    matched = []
    for rec in _read_tail():
        if rec.get("epoch", 0) < start_epoch - 3:
            continue
        host = (rec.get("host") or "").lower()
        if (host == domain or host.endswith("." + domain)
                or rec.get("is_blockchain_rpc") or rec.get("blocked_ssrf")):
            matched.append(rec)

    # If no file flows found, also pull from the interactive container's in-memory
    # list — this handles the case where the flows file was not writable during the
    # session (kasm-user uid mismatch) so flows lived only in memory.
    if not matched:
        try:
            async with httpx.AsyncClient(timeout=5) as c:
                r = await c.get(f"{INTERACTIVE_URL}/session/flows", params={"case_id": id})
                if r.status_code == 200:
                    live = r.json().get("flows", [])
                    matched = live[-_MAX_RETURN:]
        except Exception:
            pass

    matched = matched[-_MAX_RETURN:]
    return {
        "ok": True,
        "domain": domain,
        "count": len(matched),
        "blockchain_rpc": sum(1 for r in matched if r.get("is_blockchain_rpc")),
        "flows": matched,
    }


@router.get("/mitm/recent")
async def recent():
    tail = _read_tail(2000)[-_MAX_RETURN:]
    return {"ok": True, "count": len(tail), "flows": tail}
