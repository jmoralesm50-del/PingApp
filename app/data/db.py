# app/data/db.py
from __future__ import annotations
import sqlite3
from pathlib import Path
from typing import Optional, Iterable, Tuple

DB_PATH = Path("pineo.db")


def _conn() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH, timeout=5.0)
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA synchronous=NORMAL;")
    return con


def init_db() -> None:
    with _conn() as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at REAL NOT NULL,
                ended_at REAL,
                range_text TEXT NOT NULL,
                cycle_seconds INTEGER NOT NULL
            );
        """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                ip TEXT NOT NULL,
                status TEXT NOT NULL,
                rtt_ms REAL,
                hostname TEXT,
                method TEXT NOT NULL,
                seen_at REAL NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            );
        """
        )
        con.execute("CREATE INDEX IF NOT EXISTS ix_scan_results_scan_ip ON scan_results (scan_id, ip);")


def start_scan(started_at: float, range_text: str, cycle_seconds: int) -> int:
    with _conn() as con:
        cur = con.execute(
            "INSERT INTO scans(started_at, range_text, cycle_seconds) VALUES (?, ?, ?)",
            (started_at, range_text, cycle_seconds),
        )
        return int(cur.lastrowid)


def end_scan(scan_id: int, ended_at: float) -> None:
    with _conn() as con:
        con.execute("UPDATE scans SET ended_at = ? WHERE id = ?", (ended_at, scan_id))


def save_results(
    scan_id: int,
    rows: Iterable[Tuple[str, str, Optional[float], Optional[str], str, float]],
) -> None:
    with _conn() as con:
        con.executemany(
            """
            INSERT INTO scan_results (scan_id, ip, status, rtt_ms, hostname, method, seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            ((scan_id, ip, status, rtt, host, method, ts) for (ip, status, rtt, host, method, ts) in rows),
        )
