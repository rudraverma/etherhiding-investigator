"""Case browser: list cases, fetch the report, walk the artifact tree, and read a
single artifact back safely (path-traversal guarded). The UI renders captured HTML
in a sandboxed iframe from these bytes — the API never serves malware as live HTML."""

from __future__ import annotations

import json
import mimetypes

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from app import db
from app.auth import require_auth
from app.workspace import case_path_from_id, resolve_case_artifact

router = APIRouter(prefix="/api", dependencies=[Depends(require_auth)])

MAX_ARTIFACT_BYTES = 16 * 1024 * 1024

# Extensions we serve as text/plain so a direct hit can never render/execute them.
_TEXT_AS_PLAIN = {".html", ".htm", ".js", ".ps1", ".json", ".txt", ".md", ".log", ".css", ".xml"}
_IMAGE = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
          ".gif": "image/gif", ".webp": "image/webp"}


@router.get("/cases")
async def cases():
    return {"ok": True, "cases": db.list_cases()}


@router.get("/case")
async def case(id: str = Query(...)):
    row = db.get_case(id)
    if not row:
        raise HTTPException(status_code=404, detail="Unknown case")
    base = case_path_from_id(id)
    report = None
    if base and (base / "report.json").exists():
        try:
            report = json.loads((base / "report.json").read_text())
        except Exception:
            report = None
    return {"ok": True, "case": row, "report": report, "iocs": db.list_iocs(id)}


@router.get("/case/tree")
async def tree(id: str = Query(...)):
    base = case_path_from_id(id)
    if not base:
        raise HTTPException(status_code=404, detail="Unknown case")
    files = []
    for p in sorted(base.rglob("*")):
        if p.is_file():
            rel = str(p.relative_to(base))
            try:
                size = p.stat().st_size
            except OSError:
                size = 0
            files.append({"path": rel, "size": size})
    return {"ok": True, "files": files}


@router.get("/case/artifact")
async def artifact(id: str = Query(...), path: str = Query(...)):
    target = resolve_case_artifact(id, path)
    if target is None:
        raise HTTPException(status_code=404, detail="Artifact not found")
    try:
        if target.stat().st_size > MAX_ARTIFACT_BYTES:
            raise HTTPException(status_code=413, detail="Artifact too large to preview")
        data = target.read_bytes()
    except OSError:
        raise HTTPException(status_code=404, detail="Artifact not readable")

    ext = target.suffix.lower()
    if ext in _IMAGE:
        ctype = _IMAGE[ext]
    elif ext in _TEXT_AS_PLAIN:
        ctype = "text/plain; charset=utf-8"
    else:
        guessed, _ = mimetypes.guess_type(target.name)
        ctype = "application/octet-stream" if not guessed else guessed

    return Response(content=data, media_type=ctype, headers={
        "X-Content-Type-Options": "nosniff",
        "Content-Disposition": f'inline; filename="{target.name}"',
        "Content-Security-Policy": "sandbox; default-src 'none'",
    })
