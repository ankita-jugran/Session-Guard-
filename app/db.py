"""
SQLite database management for Dummy Login App.
Handles user credentials and token revocation tracking.
"""
import hashlib
import os
import sqlite3
from typing import Optional, Dict, Any, List

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "target_app.db")

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str) -> str:
    """SHA-256 password hash for test app simplicity."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def hash_token(token: str) -> str:
    """Hash token for revocation storage."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def init_db():
    """Initialize database tables and seed default accounts."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Revoked tokens table (Blacklist)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS revoked_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            jti TEXT,
            token_hash TEXT NOT NULL,
            username TEXT,
            revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reason TEXT DEFAULT 'user_logout'
        )
    """)
    
    # Seed default test accounts
    seed_users = [
        ("admin", "admin2026", "administrator"),
        ("alice", "password123", "user"),
        ("bob", "secretPass!", "user"),
    ]
    
    for username, password, role in seed_users:
        pwd_hash = hash_password(password)
        cursor.execute("""
            INSERT OR IGNORE INTO users (username, password_hash, role)
            VALUES (?, ?, ?)
        """, (username, pwd_hash, role))
    
    conn.commit()
    conn.close()

def verify_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Verify credentials, returns user dict if valid, else None."""
    conn = get_connection()
    cursor = conn.cursor()
    pwd_hash = hash_password(password)
    cursor.execute(
        "SELECT id, username, role FROM users WHERE username = ? AND password_hash = ?",
        (username, pwd_hash)
    )
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

def register_user(username: str, password: str, role: str = "user") -> Tuple[bool, str]:
    """Register a new user account in SQLite."""
    conn = get_connection()
    cursor = conn.cursor()
    pwd_hash = hash_password(password)
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username.strip(), pwd_hash, role)
        )
        conn.commit()
        conn.close()
        return True, "Account registered successfully! You can now sign in."
    except sqlite3.IntegrityError:
        conn.close()
        return False, f"Username '{username}' is already taken."
    except Exception as e:
        conn.close()
        return False, f"Registration failed: {str(e)}"

def update_password(username: str, new_password: str) -> Tuple[bool, str]:
    """Update user password in SQLite database."""
    conn = get_connection()
    cursor = conn.cursor()
    pwd_hash = hash_password(new_password)
    cursor.execute("SELECT id FROM users WHERE username = ?", (username.strip(),))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False, f"User '{username}' not found."

    cursor.execute(
        "UPDATE users SET password_hash = ? WHERE username = ?",
        (pwd_hash, username.strip())
    )
    conn.commit()
    conn.close()
    return True, "Password updated successfully. Please log in with your new credentials."

def revoke_token(token: str, jti: Optional[str] = None, username: Optional[str] = None, reason: str = "logout"):
    """Add a token to the revoked tokens blacklist."""
    conn = get_connection()
    cursor = conn.cursor()
    t_hash = hash_token(token)
    cursor.execute("""
        INSERT INTO revoked_tokens (jti, token_hash, username, reason)
        VALUES (?, ?, ?, ?)
    """, (jti, t_hash, username, reason))
    conn.commit()
    conn.close()

def revoke_all_user_tokens(username: str, reason: str = "password_reset"):
    """Revoke all active tokens for a user upon password reset."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO revoked_tokens (jti, token_hash, username, reason)
        VALUES ('ALL_SESSIONS', 'ALL_SESSIONS', ?, ?)
    """, (username.strip(), reason))
    conn.commit()
    conn.close()

def is_token_revoked(token: str, jti: Optional[str] = None, username: Optional[str] = None) -> bool:
    """Check if token, jti, or user sessions have been revoked."""
    conn = get_connection()
    cursor = conn.cursor()
    t_hash = hash_token(token)
    
    conditions = ["token_hash = ?"]
    params = [t_hash]

    if jti:
        conditions.append("jti = ?")
        params.append(jti)
    if username:
        conditions.append("(username = ? AND jti = 'ALL_SESSIONS')")
        params.append(username)

    query = f"SELECT id FROM revoked_tokens WHERE {' OR '.join(conditions)}"
    cursor.execute(query, tuple(params))
    row = cursor.fetchone()
    conn.close()
    return row is not None

def get_revoked_tokens(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve recent revoked tokens."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, jti, token_hash, username, revoked_at, reason
        FROM revoked_tokens
        ORDER BY revoked_at DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def clear_revoked_tokens():
    """Clear blacklist table for testing reset."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM revoked_tokens")
    conn.commit()
    conn.close()
