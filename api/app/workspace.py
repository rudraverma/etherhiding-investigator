"""
Case folder layout and path-traversal-safe artifact access.

Cases are organised as: /workspace/cases/YYYY/MM/DD/<case-name>/
Artifacts are read back only through resolve_case_artifact(), which guarantees the
resolved path stays inside the case directory (defends the Evidence browser against
`..` traversal).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from app.config import CASES_DIR

SUBDIRS = ("recon", "page", "network", "scripts", "blockchain", "c2", "sandbox", "browser")


def slugify(name: str, fallback: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "-", (name or "").strip().lower()).strip("-.")
    s = s[:60]
    return s or fallback


def new_case_path(domain: str, case_name: str, when: datetime | None = None) -> tuple[str, Path]:
    when = when or datetime.now(timezone.utc)
    slug = slugify(case_name or domain, "case")
    day = CASES_DIR / f"{when:%Y}" / f"{when:%m}" / f"{when:%d}"
    path = day / slug
    # Ensure uniqueness if a case of the same name exists for the day.
    counter = 1
    unique = path
    while unique.exists():
        counter += 1
        unique = day / f"{slug}-{counter}"
    case_id = f"{when:%Y-%m-%d}/{unique.name}"
    return case_id, unique


def ensure_layout(case_path: Path) -> None:
    for sd in SUBDIRS:
        (case_path / sd).mkdir(parents=True, exist_ok=True)


def case_path_from_id(case_id: str) -> Path | None:
    """case_id is 'YYYY-MM-DD/<name>'. Returns the directory or None."""
    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})/([A-Za-z0-9._-]{1,80})", case_id or "")
    if not m:
        return None
    y, mo, d, name = m.groups()
    if ".." in name:            # defence-in-depth (the relative_to check also contains it)
        return None
    p = (CASES_DIR / y / mo / d / name).resolve()
    try:
        p.relative_to(CASES_DIR.resolve())
    except ValueError:
        return None
    return p if p.is_dir() else None


def resolve_case_artifact(case_id: str, rel: str) -> Path | None:
    """Resolve an artifact path inside a case, rejecting traversal outside it."""
    base = case_path_from_id(case_id)
    if base is None:
        return None
    rel = (rel or "").lstrip("/")
    target = (base / rel).resolve()
    try:
        target.relative_to(base.resolve())
    except ValueError:
        return None
    return target if target.is_file() else None
