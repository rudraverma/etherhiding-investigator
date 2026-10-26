"""Submit a URL, stream the live investigation log (SSE), and query status."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app import db
from app.auth import require_auth
from app.ssrf import validate_target, SSRFError
from app.workspace import new_case_path, ensure_layout
from app.pipeline import orchestrator

router = APIRouter(prefix="/api", dependencies=[Depends(require_auth)])

# In-memory live task log (SSE). Persistent state lives in SQLite + case files.
_tasks: dict[str, dict] = {}


class SubmitBody(BaseModel):
    url: str = Field(min_length=3, max_length=2048)
    case_name: str = Field(default="", max_length=80)


def _logger(task_id: str):
    def log(msg: str, level: str = "info"):
        t = _tasks.get(task_id)
        if t is not None:
            t["logs"].append({"ts": datetime.now(timezone.utc).isoformat(),
                              "level": level, "msg": msg})
    return log


async def _background(task_id: str, url: str, domain: str, case_path: Path):
    log = _logger(task_id)
    try:
        await orchestrator.run_auto(task_id, url, domain, case_path, log)
        _tasks[task_id]["status"] = "done"
    except Exception as e:
        log(f"FATAL: {e}", "error")
        _tasks[task_id]["status"] = "error"
        try:
            db.update_case(task_id, status="error")
        except Exception:
            pass


@router.post("/investigate")
async def submit(body: SubmitBody):
    try:
        target = validate_target(body.url)
    except SSRFError as e:
        raise HTTPException(status_code=400, detail=f"Rejected URL: {e}")

    url, domain = target["url"], target["domain"]
    case_id, case_path = new_case_path(domain, body.case_name)
    ensure_layout(case_path)

    now = datetime.now(timezone.utc).isoformat()
    db.create_case({"id": case_id, "created_at": now, "url": url, "domain": domain,
                    "case_path": str(case_path), "status": "running"})
    (case_path / "notes.md").write_text(
        f"# EtherHiding Investigation — {url}\n\n"
        f"- Submitted: {now}\n- Domain: {domain}\n- Case: {case_id}\n\n_Running..._\n")

    _tasks[case_id] = {"status": "running", "logs": [], "url": url, "domain": domain,
                       "case_path": str(case_path)}
    asyncio.create_task(_background(case_id, url, domain, case_path))
    return {"ok": True, "case_id": case_id, "case_path": str(case_path)}


@router.get("/investigate/stream")
async def stream(id: str):
    case_id = id
    if case_id not in _tasks and db.get_case(case_id) is None:
        raise HTTPException(status_code=404, detail="Unknown case")

    async def gen():
        pointer = 0
        while True:
            task = _tasks.get(case_id)
            if task is None:
                yield f'data: {json.dumps({"type": "done", "status": "unknown"})}\n\n'
                break
            new = task["logs"][pointer:]
            for entry in new:
                yield f"data: {json.dumps(entry)}\n\n"
            pointer += len(new)
            if task["status"] != "running":
                yield f'data: {json.dumps({"type": "done", "status": task["status"], "case_id": case_id})}\n\n'
                break
            await asyncio.sleep(0.4)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"})


@router.get("/investigate/status")
async def status(id: str):
    case_id = id
    t = _tasks.get(case_id)
    row = db.get_case(case_id)
    if not t and not row:
        raise HTTPException(status_code=404, detail="Unknown case")
    return {"ok": True, "status": (t or {}).get("status") or (row or {}).get("status"),
            "log_count": len((t or {}).get("logs", [])), "case": row}
