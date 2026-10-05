import sqlite3
import secrets
import json
import time
from typing import Optional, Dict, Any, List
from sentinelshield.config import settings
from sentinelshield.auth.users import hash_password, verify_password


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(settings.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL,
                role TEXT NOT NULL,
                tier TEXT NOT NULL,
                api_key TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS security_audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                user_tier TEXT NOT NULL,
                details_json TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Seed default enterprise users if not present
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        if count == 0:
            seed_users = [
                ("admin", "admin@sentinelshield.internal", "SentinelAdmin2026!", "admin", "admin", "sk_live_admin_9821a7c"),
                ("developer", "dev@sentinelshield.internal", "DevSecret2026!", "developer", "tier-2", "sk_live_dev_87123bc"),
                ("enterprise_app", "app@enterprise.corp", "ClientApp2026!", "service", "tier-1", "sk_live_tier1_51299ef"),
                ("guest", "guest@sentinelshield.internal", "GuestDemo2026!", "guest", "guest", "sk_live_guest_0000000"),
            ]
            for u, e, p, r, t, k in seed_users:
                conn.execute(
                    "INSERT INTO users (username, email, hashed_password, role, tier, api_key) VALUES (?, ?, ?, ?, ?, ?)",
                    (u, e, hash_password(p), r, t, k),
                )

        # Ensure demo gmail aliases exist in users table
        gmail_seeds = [
            ("developer@gmail.com", "developer@gmail.com", "DevSecret2026!", "developer", "tier-2", "sk_live_dev_gmail"),
            ("admin@gmail.com", "admin@gmail.com", "SentinelAdmin2026!", "admin", "admin", "sk_live_admin_gmail"),
            ("guest@gmail.com", "guest@gmail.com", "GuestDemo2026!", "guest", "guest", "sk_live_guest_gmail"),
        ]
        for u, e, p, r, t, k in gmail_seeds:
            cursor.execute("SELECT COUNT(*) FROM users WHERE username = ? OR email = ?", (u, e))
            if cursor.fetchone()[0] == 0:
                conn.execute(
                    "INSERT INTO users (username, email, hashed_password, role, tier, api_key) VALUES (?, ?, ?, ?, ?, ?)",
                    (u, e, hash_password(p), r, t, k),
                )
    conn.close()


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? OR email = ? COLLATE NOCASE", (username, username))
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None


def get_user_by_username_or_email(identifier: str) -> Optional[Dict[str, Any]]:
    return get_user_by_username(identifier)


def update_user_password(user_id: int, new_password: str) -> bool:
    hashed = hash_password(new_password)
    conn = get_db_connection()
    with conn:
        conn.execute("UPDATE users SET hashed_password = ? WHERE id = ?", (hashed, user_id))
    conn.close()
    return True


def get_user_by_api_key(api_key: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE api_key = ?", (api_key,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None


def create_user(username: str, email: str, password: str, role: str = "developer", tier: str = "tier-1") -> Dict[str, Any]:
    api_key = f"sk_live_{secrets.token_hex(16)}"
    hashed = hash_password(password)
    conn = get_db_connection()
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, email, hashed_password, role, tier, api_key) VALUES (?, ?, ?, ?, ?, ?)",
                (username, email, hashed, role, tier, api_key),
            )
            user_id = cursor.lastrowid
        conn.close()
        return {
            "id": user_id,
            "username": username,
            "email": email,
            "role": role,
            "tier": tier,
            "api_key": api_key,
        }
    except sqlite3.IntegrityError:
        conn.close()
        raise ValueError(f"Username '{username}' or email '{email}' already registered.")


def record_audit_event(event_type: str, severity: str, user_tier: str, details: Dict[str, Any]):
    conn = get_db_connection()
    with conn:
        conn.execute(
            "INSERT INTO security_audit_events (timestamp, event_type, severity, user_tier, details_json) VALUES (?, ?, ?, ?, ?)",
            (time.time(), event_type, severity, user_tier, json.dumps(details)),
        )
    conn.close()


def get_audit_events(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT timestamp, event_type, severity, user_tier, details_json FROM security_audit_events ORDER BY id DESC LIMIT ?",
        (limit,),
    )
    rows = cursor.fetchall()
    conn.close()
    events = []
    for r in rows:
        events.append({
            "timestamp": r["timestamp"],
            "event_type": r["event_type"],
            "severity": r["severity"],
            "user_tier": r["user_tier"],
            "details": json.loads(r["details_json"]),
        })
    return events


def clear_audit_events():
    conn = get_db_connection()
    with conn:
        conn.execute("DELETE FROM security_audit_events")
    conn.close()


def get_audit_summary() -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM security_audit_events")
    total_events = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_audit_events WHERE event_type = 'INJECTION_BLOCKED'")
    blocked_injections = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_audit_events WHERE event_type = 'JSON_REPAIRED'")
    json_repairs = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_audit_events WHERE event_type = 'RATE_LIMIT_HIT'")
    rate_limit_hits = cursor.fetchone()[0]

    conn.close()
    return {
        "total_audit_events": total_events,
        "blocked_injections": blocked_injections,
        "json_repairs": json_repairs,
        "rate_limit_hits": rate_limit_hits,
    }
