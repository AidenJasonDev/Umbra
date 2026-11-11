"""SQLite registry of every training run and its outcome."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id        TEXT PRIMARY KEY,
    created_at    TEXT,
    actor         TEXT,
    is_agent      INTEGER,
    scenario      TEXT,
    action_label  TEXT,
    category      TEXT,
    rep           INTEGER,
    status        TEXT,     -- ok | error | timeout | capture_failed
    outcome       TEXT,     -- completed | not_completed | refused
    checks_passed INTEGER,
    checks_total  INTEGER,
    exit_code     INTEGER,
    duration_s    REAL,
    captured      INTEGER,  -- 1 if eslogger+pktap ran
    fs_events     INTEGER,
    net_packets   INTEGER,
    notes         TEXT,
    manifest      TEXT
);
"""


def connect(path: Path = DB_PATH) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    return con


def upsert(manifest: dict, path: Path = DB_PATH) -> None:
    cols = ["run_id", "created_at", "actor", "is_agent", "scenario", "action_label", "category",
            "rep", "status", "outcome", "checks_passed", "checks_total", "exit_code",
            "duration_s", "captured", "fs_events", "net_packets", "notes"]
    row = {c: manifest.get(c) for c in cols}
    row["manifest"] = json.dumps(manifest)
    with connect(path) as con:
        con.execute(
            f"INSERT OR REPLACE INTO runs ({','.join(row)}) VALUES ({','.join('?' * len(row))})",
            list(row.values()))


def all_runs(path: Path = DB_PATH, captured_only: bool = False) -> list[dict]:
    with connect(path) as con:
        q = "SELECT * FROM runs"
        if captured_only:
            q += " WHERE captured = 1 AND status = 'ok'"
        return [dict(r) for r in con.execute(q + " ORDER BY created_at")]


def matrix(path: Path = DB_PATH) -> tuple[list[str], list[str], dict]:
    """(actors, scenarios, {(actor, scenario): {'n':, 'captured':, 'completed':, 'refused':}})"""
    runs = all_runs(path)
    actors = sorted({r["actor"] for r in runs})
    scen = sorted({r["scenario"] for r in runs})
    cells: dict = {}
    for r in runs:
        c = cells.setdefault((r["actor"], r["scenario"]),
                             {"n": 0, "captured": 0, "completed": 0, "refused": 0})
        c["n"] += 1
        c["captured"] += 1 if (r["captured"] and r["status"] == "ok") else 0
        c["completed"] += 1 if r["outcome"] == "completed" else 0
        c["refused"] += 1 if r["outcome"] == "refused" else 0
    return actors, scen, cells
