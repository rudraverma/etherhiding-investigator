"""
Interactive detonation mode. The analyst drives a REAL Google Chrome (noVNC) in
the etherhawk-interactive container; capture runs browser-native over CDP so the
site sees Chrome's genuine TLS fingerprint. When the analyst is done, finalize
runs the same deterministic engine over the captured facts.

Single live session: the browser holds one analyst session at a time (this is a
single-analyst appliance). start navigates it; status reports live signals;
finalize captures the DOM + runs the verdict pipeline.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app import db
from app.auth import require_auth
from app.ssrf import validate_target, SSRFError
from app.workspace import new_case_path, ensure_layout
from app.pipeline import orchestrator
# Reuse the auto-mode live task log so the dashboard can stream finalize over SSE.
from app.routers.investigate import _tasks, _logger

router = APIRouter(prefix="/api", dependencies=[Depends(require_auth)])


class StartBody(BaseModel):
    url: str = Field(min_length=3, max_length=2048)
    case_name: str = Field(default="", max_length=80)


@router.post("/interactive/start")
async def start(body: StartBody):
    try:
        target = validate_target(body.url)
    except SSRFError as e:
        raise HTTPException(status_code=400, detail=f"Rejected URL: {e}")

    url, domain = target["url"], target["domain"]
    case_id, case_path = new_case_path(domain, body.case_name)
    ensure_layout(case_path)

    now = datetime.now(timezone.utc).isoformat()
    db.create_case({"id": case_id, "created_at": now, "url": url, "domain": domain,
                    "case_path": str(case_path), "status": "interactive"})
    (case_path / "notes.md").write_text(
        f"# EtherHiding Investigation (interactive) — {url}\n\n"
        f"- Submitted: {now}\n- Domain: {domain}\n- Case: {case_id}\n\n"
        f"_Analyst is driving the interactive browser._\n")

    try:
        res = await orchestrator.start_interactive_session(url, case_path, case_id)
    except Exception as e:
        db.update_case(case_id, status="error")
        raise HTTPException(status_code=502, detail=f"Interactive browser unavailable: {e}")

    return {"ok": True, "case_id": case_id, "url": url,
            "main_status": res.get("main_status")}


@router.get("/interactive/status")
async def status(id: str = Query(...)):
    row = db.get_case(id)
    if not row:
        raise HTTPException(status_code=404, detail="Unknown case")
    try:
        live = await orchestrator.interactive_status()
    except Exception as e:
        live = {"ok": False, "error": str(e)[:200]}
    return {"ok": True, "case": row, "live": live}


async def _finalize_bg(case_id: str, url: str, domain: str, case_path: Path):
    log = _logger(case_id)
    try:
        await orchestrator.finalize_interactive(case_id, url, domain, case_path, log)
        _tasks[case_id]["status"] = "done"
    except Exception as e:
        log(f"FATAL: {e}", "error")
        _tasks[case_id]["status"] = "error"
        db.update_case(case_id, status="error")


@router.post("/interactive/finalize")
async def finalize(id: str = Query(...)):
    row = db.get_case(id)
    if not row:
        raise HTTPException(status_code=404, detail="Unknown case")
    case_path = Path(row["case_path"])
    _tasks[id] = {"status": "running", "logs": [], "url": row["url"],
                  "domain": row["domain"], "case_path": row["case_path"]}
    asyncio.create_task(_finalize_bg(id, row["url"], row["domain"], case_path))
    return {"ok": True, "case_id": id}
