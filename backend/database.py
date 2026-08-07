"""
database.py
SQLite persistence layer for the deception platform.
Handles honeytoken registration and telemetry event storage.
"""

import sqlite3
import json
import os
from contextlib import contextmanager
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "deception.db")


def init_db():
    """Create tables if they don't already exist."""
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS honeytokens (
                token_id TEXT PRIMARY KEY,
                token_type TEXT NOT NULL,           -- e.g. 'pdf', 'env_file', 'api_key', 'endpoint'
                bait_name TEXT NOT NULL,             -- filename or credential label shown to attacker
                created_at TEXT NOT NULL,
                location_hint TEXT,                  -- where it was placed (path/system)
                active INTEGER DEFAULT 1
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                headers_json TEXT,
                request_path TEXT,
                method TEXT,
                geo_json TEXT,               -- IP OSINT enrichment result
                intent_score REAL,           -- 0-100 score from AI agent
                severity TEXT,               -- LOW / MEDIUM / HIGH / CRITICAL
                triage_summary TEXT,         -- AI-generated human-readable summary
                proposed_action TEXT,        -- AI-generated containment recommendation
                status TEXT DEFAULT 'NEW',   -- NEW / REVIEWED / ACTIONED / DISMISSED
                FOREIGN KEY (token_id) REFERENCES honeytokens (token_id)
            )
        """)
        conn.commit()


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


# ---------- Honeytoken CRUD ----------

def register_token(token_id: str, token_type: str, bait_name: str, location_hint: str = ""):
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO honeytokens (token_id, token_type, bait_name, created_at, location_hint, active) "
            "VALUES (?, ?, ?, ?, ?, 1)",
            (token_id, token_type, bait_name, datetime.utcnow().isoformat(), location_hint),
        )
        conn.commit()


def list_tokens():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM honeytokens ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]


def get_token(token_id: str):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM honeytokens WHERE token_id = ?", (token_id,)).fetchone()
        return dict(row) if row else None


# ---------- Event CRUD ----------

def insert_event(token_id: str, ip_address: str, user_agent: str, headers: dict,
                  request_path: str, method: str) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO events (token_id, timestamp, ip_address, user_agent, headers_json,
               request_path, method, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'NEW')""",
            (token_id, datetime.utcnow().isoformat(), ip_address, user_agent,
             json.dumps(headers), request_path, method),
        )
        conn.commit()
        return cur.lastrowid


def update_event_enrichment(event_id: int, geo: dict = None, intent_score: float = None,
                             severity: str = None, triage_summary: str = None,
                             proposed_action: str = None):
    fields, values = [], []
    if geo is not None:
        fields.append("geo_json = ?"); values.append(json.dumps(geo))
    if intent_score is not None:
        fields.append("intent_score = ?"); values.append(intent_score)
    if severity is not None:
        fields.append("severity = ?"); values.append(severity)
    if triage_summary is not None:
        fields.append("triage_summary = ?"); values.append(triage_summary)
    if proposed_action is not None:
        fields.append("proposed_action = ?"); values.append(proposed_action)
    if not fields:
        return
    values.append(event_id)
    with get_conn() as conn:
        conn.execute(f"UPDATE events SET {', '.join(fields)} WHERE event_id = ?", values)
        conn.commit()


def update_event_status(event_id: int, status: str):
    with get_conn() as conn:
        conn.execute("UPDATE events SET status = ? WHERE event_id = ?", (status, event_id))
        conn.commit()


def list_events(limit: int = 200):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM events ORDER BY event_id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_event(event_id: int):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
        return dict(row) if row else None
