"""
SQLite persistence. All queries are parameterized. WAL mode for concurrent
read/write between the request handlers and the background pipeline task.
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager

from app.config import DB_PATH, SETTING_KEYS, env_default

_lock = threading.Lock()
_initialized = False


@contextmanager
def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=15)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=10000;")
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    global _initialized
    with _lock:
        if _initialized:
            return
        with _connect() as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )""")
            c.execute("""
                CREATE TABLE IF NOT EXISTS cases (
                    id          TEXT PRIMARY KEY,
                    created_at  TEXT NOT NULL,
                    url         TEXT NOT NULL,
                    domain      TEXT NOT NULL,
                    case_path   TEXT NOT NULL,
                    status      TEXT NOT NULL,
                    verdict     TEXT,
                    confidence  INTEGER,
                    contract    TEXT,
                    rpc_url     TEXT,
                    c2_count    INTEGER DEFAULT 0,
                    misp_event  TEXT
                )""")
            c.execute("""
                CREATE TABLE IF NOT EXISTS iocs (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id    TEXT NOT NULL,
                    type       TEXT NOT NULL,
                    value      TEXT NOT NULL,
                    to_ids     INTEGER DEFAULT 0,
                    note       TEXT,
                    created_at TEXT NOT NULL
                )""")
        _initialized = True


# ── Settings ────────────────────────────────────────────────────────────────
def get_setting(key: str) -> str:
    if key not in SETTING_KEYS:
        raise KeyError(key)
    with _connect() as c:
        row = c.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    if row is not None:
        return row["value"]
    return env_default(key)


def set_setting(key: str, value: str) -> None:
    if key not in SETTING_KEYS:
        raise KeyError(key)
    with _connect() as c:
        c.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, str(value)),
        )


def all_settings() -> dict:
    return {k: get_setting(k) for k in SETTING_KEYS}


# ── Cases ──────────────────────────────────────────────────────────────────
def create_case(row: dict) -> None:
    with _connect() as c:
        c.execute(
            """INSERT INTO cases(id, created_at, url, domain, case_path, status)
               VALUES(:id, :created_at, :url, :domain, :case_path, :status)""",
            row,
        )


def update_case(case_id: str, **fields) -> None:
    if not fields:
        return
    allowed = {"status", "verdict", "confidence", "contract", "rpc_url", "c2_count", "misp_event"}
    sets, params = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k} = ?")
            params.append(v)
    if not sets:
        return
    params.append(case_id)
    with _connect() as c:
        c.execute(f"UPDATE cases SET {', '.join(sets)} WHERE id = ?", params)


def get_case(case_id: str) -> dict | None:
    with _connect() as c:
        row = c.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    return dict(row) if row else None


def list_cases(limit: int = 200) -> list[dict]:
    with _connect() as c:
        rows = c.execute(
            "SELECT * FROM cases ORDER BY created_at DESC LIMIT ?", (int(limit),)
        ).fetchall()
    return [dict(r) for r in rows]


# ── IOCs ───────────────────────────────────────────────────────────────────
def add_iocs(case_id: str, iocs: list[dict], created_at: str) -> None:
    if not iocs:
        return
    with _connect() as c:
        c.executemany(
            "INSERT INTO iocs(case_id, type, value, to_ids, note, created_at) "
            "VALUES(?, ?, ?, ?, ?, ?)",
            [(case_id, i.get("type", "text"), i.get("value", ""),
              1 if i.get("to_ids") else 0, i.get("note", ""), created_at) for i in iocs],
        )


def list_iocs(case_id: str) -> list[dict]:
    with _connect() as c:
        rows = c.execute(
            "SELECT type, value, to_ids, note FROM iocs WHERE case_id = ? ORDER BY id", (case_id,)
        ).fetchall()
    return [dict(r) for r in rows]
