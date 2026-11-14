import sqlite3
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

DB_PATH = Path(__file__).parent / "phishlens.db"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize SQLite database and create tables if they do not exist."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                score INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                signals TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scans_created_at
            ON scans(created_at DESC);
            """
        )
        conn.commit()


def save_scan(scan: Dict[str, Any]) -> None:
    """Persist a scan result dictionary into the SQLite database."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO scans (
                scan_id, url, score, verdict, signals, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                scan.get("scan_id"),
                scan.get("website") or scan.get("url", ""),
                int(scan.get("score", 0)),
                scan.get("verdict", "safe"),
                json.dumps(scan.get("signals", [])),
                scan.get("created_at") or datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()


def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve a single scan result by scan_id."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT scan_id, url, score, verdict, signals, created_at
            FROM scans
            WHERE scan_id = ?
            """,
            (scan_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None

        return {
            "scan_id": row["scan_id"],
            "website": row["url"],
            "score": row["score"],
            "verdict": row["verdict"],
            "signals": json.loads(row["signals"]),
            "created_at": row["created_at"],
        }


def get_recent_scans(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve recent scans ordered by creation time descending."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT scan_id, url, score, verdict, signals, created_at
            FROM scans
            ORDER BY datetime(created_at) DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        results = []
        for row in rows:
            results.append(
                {
                    "scan_id": row["scan_id"],
                    "website": row["url"],
                    "score": row["score"],
                    "verdict": row["verdict"],
                    "signals": json.loads(row["signals"]),
                    "created_at": row["created_at"],
                }
            )
        return results
