"""
db.py — Shared SQLite logging layer for DeceptionNet.

Every honeypot service (SSH, FTP, Web) imports log_event() from here
so all attack data lands in one place for the dashboard to read.
"""

import sqlite3
import threading
from datetime import datetime, timezone

DB_PATH = "deceptionnet.db"

# SQLite connections aren't thread-safe by default; one lock keeps
# writes from the SSH/FTP/Web threads from colliding.
_lock = threading.Lock()


def init_db():
    """Create the events table if it doesn't exist yet. Call once at startup."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            service TEXT NOT NULL,        -- 'ssh', 'ftp', 'web'
            source_ip TEXT NOT NULL,
            source_port INTEGER,
            username TEXT,
            password TEXT,
            raw_payload TEXT,
            attack_type TEXT NOT NULL,    -- 'brute_force', 'sqli', 'xss', 'port_scan', 'recon'
            country TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def log_event(service, source_ip, source_port=None, username=None,
               password=None, raw_payload=None, attack_type="recon", country=None):
    """Insert one attack/connection event. Thread-safe."""
    timestamp = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            """
            INSERT INTO events
                (timestamp, service, source_ip, source_port, username,
                 password, raw_payload, attack_type, country)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (timestamp, service, source_ip, source_port, username,
             password, raw_payload, attack_type, country),
        )
        conn.commit()
        conn.close()
    return timestamp


def recent_attempts_by_ip(source_ip, service=None, window_seconds=60):
    """
    Count how many events a given IP has triggered in the last `window_seconds`.
    Used by the classifier to detect brute force (many attempts, short window).
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    query = "SELECT timestamp FROM events WHERE source_ip = ?"
    params = [source_ip]
    if service:
        query += " AND service = ?"
        params.append(service)
    rows = conn.execute(query, params).fetchall()
    conn.close()

    now = datetime.now(timezone.utc)
    count = 0
    for row in rows:
        ts = datetime.fromisoformat(row["timestamp"])
        if (now - ts).total_seconds() <= window_seconds:
            count += 1
    return count


def distinct_ports_by_ip(source_ip, window_seconds=60):
    """Count distinct destination ports an IP has touched recently (port-scan signal)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT timestamp, source_port FROM events WHERE source_ip = ?", (source_ip,)
    ).fetchall()
    conn.close()

    now = datetime.now(timezone.utc)
    ports = set()
    for row in rows:
        ts = datetime.fromisoformat(row["timestamp"])
        if (now - ts).total_seconds() <= window_seconds and row["source_port"] is not None:
            ports.add(row["source_port"])
    return len(ports)


def is_ip_honeytoken_tagged(source_ip, window_seconds=3600):
    """Check if an IP address has an active tagged honeytoken session (triggered within last hour)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT timestamp FROM events WHERE source_ip = ? AND attack_type IN ('honeytoken_triggered', 'honeytoken_session')",
        (source_ip,)
    ).fetchall()
    conn.close()

    now = datetime.now(timezone.utc)
    for row in rows:
        ts = datetime.fromisoformat(row["timestamp"])
        if (now - ts).total_seconds() <= window_seconds:
            return True
    return False



def all_events(limit=200):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def stats_summary():
    """Aggregate counts used by the dashboard charts."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    total = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]

    by_type = conn.execute(
        "SELECT attack_type, COUNT(*) AS c FROM events GROUP BY attack_type"
    ).fetchall()

    by_ip = conn.execute(
        """
        SELECT source_ip, COUNT(*) AS c FROM events
        GROUP BY source_ip ORDER BY c DESC LIMIT 10
        """
    ).fetchall()

    by_service = conn.execute(
        "SELECT service, COUNT(*) AS c FROM events GROUP BY service"
    ).fetchall()

    # last 24 buckets (hourly) for the timeline chart
    timeline = conn.execute(
        """
        SELECT strftime('%Y-%m-%d %H:00', timestamp) AS hour, COUNT(*) AS c
        FROM events GROUP BY hour ORDER BY hour DESC LIMIT 24
        """
    ).fetchall()

    conn.close()
    return {
        "total": total,
        "by_type": [dict(r) for r in by_type],
        "by_ip": [dict(r) for r in by_ip],
        "by_service": [dict(r) for r in by_service],
        "timeline": [dict(r) for r in reversed(timeline)],
    }
