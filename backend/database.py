import sqlite3
import json
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

DB_PATH = Path(__file__).parent / "phishlens.db"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _normalize_url(url: str) -> str:
    """Normalize URL by stripping spaces, lowercase, and removing trailing slashes."""
    cleaned = url.strip().lower()
    if cleaned.endswith("/"):
        cleaned = cleaned[:-1]
    return cleaned


def _extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        return (parsed.hostname or parsed.path.split("/")[0]).lower()
    except Exception:
        return ""


def init_db() -> None:
    """Initialize SQLite database and create tables if they do not exist."""
    with get_connection() as conn:
        cursor = conn.cursor()
        # 1. Scans table for historical logs
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                score INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                signals TEXT NOT NULL,
                reports_count INTEGER DEFAULT 0,
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

        # Migration: Ensure reports_count column exists if DB was created previously
        try:
            cursor.execute("ALTER TABLE scans ADD COLUMN reports_count INTEGER DEFAULT 0;")
        except sqlite3.OperationalError:
            pass

        # 2. Community reports table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                url TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                reports_count INTEGER DEFAULT 0,
                last_reported_at TEXT NOT NULL
            );
            """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_reports_domain
            ON reports(domain);
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
                scan_id, url, score, verdict, signals, reports_count, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan.get("scan_id"),
                scan.get("website") or scan.get("url", ""),
                int(scan.get("score", 0)),
                scan.get("verdict", "safe"),
                json.dumps(scan.get("signals", [])),
                int(scan.get("reports_count", 0)),
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
            SELECT scan_id, url, score, verdict, signals, reports_count, created_at
            FROM scans
            WHERE scan_id = ?
            """,
            (scan_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None

        # Check live reports count for latest accurate number
        url = row["url"]
        live_count = get_reports_count(url)

        return {
            "scan_id": row["scan_id"],
            "website": row["url"],
            "score": row["score"],
            "verdict": row["verdict"],
            "signals": json.loads(row["signals"]),
            "reports_count": live_count if live_count > 0 else (row["reports_count"] or 0),
            "created_at": row["created_at"],
        }


def get_recent_scans(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve recent scans ordered by creation time descending with live report counts column."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT scan_id, url, score, verdict, signals, reports_count, created_at
            FROM scans
            ORDER BY datetime(created_at) DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        results = []
        for row in rows:
            url = row["url"]
            live_count = get_reports_count(url)
            results.append(
                {
                    "scan_id": row["scan_id"],
                    "website": row["url"],
                    "score": row["score"],
                    "verdict": row["verdict"],
                    "signals": json.loads(row["signals"]),
                    "reports_count": live_count if live_count > 0 else (row["reports_count"] or 0),
                    "created_at": row["created_at"],
                }
            )
        return results


def record_report(url: str) -> int:
    """
    Increment community report count for a given URL and its domain.
    Returns the new updated reports count.
    """
    norm_url = _normalize_url(url)
    domain = _extract_domain(url)
    now_iso = datetime.now(timezone.utc).isoformat()

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO reports (url, domain, reports_count, last_reported_at)
            VALUES (?, ?, 1, ?)
            ON CONFLICT(url) DO UPDATE SET
                reports_count = reports_count + 1,
                last_reported_at = excluded.last_reported_at;
            """,
            (norm_url, domain, now_iso),
        )

        cursor.execute("SELECT reports_count FROM reports WHERE url = ?", (norm_url,))
        row = cursor.fetchone()
        new_count = row["reports_count"] if row else 1

        # Also update reports_count in scans table if this URL exists there
        cursor.execute(
            "UPDATE scans SET reports_count = ? WHERE url = ? OR url = ?",
            (new_count, url, norm_url),
        )
        conn.commit()

        return new_count


def get_reports_count(url: str) -> int:
    """
    Get total reports for a specific URL, with fallback to domain-level aggregate.
    """
    norm_url = _normalize_url(url)
    domain = _extract_domain(url)

    with get_connection() as conn:
        cursor = conn.cursor()
        # 1. Exact URL match first
        cursor.execute("SELECT reports_count FROM reports WHERE url = ?", (norm_url,))
        row = cursor.fetchone()
        if row and row["reports_count"] > 0:
            return row["reports_count"]

        # 2. Domain-level fallback sum
        if domain:
            cursor.execute("SELECT SUM(reports_count) as total FROM reports WHERE domain = ?", (domain,))
            domain_row = cursor.fetchone()
            if domain_row and domain_row["total"]:
                return int(domain_row["total"])

        return 0
