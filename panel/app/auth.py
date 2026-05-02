import secrets
from datetime import datetime, timedelta, timezone

import pyotp
import segno
from passlib.hash import argon2

from .db import connect


def hash_password(plaintext: str) -> str:
    return argon2.using(type="ID", time_cost=2, memory_cost=64 * 1024, parallelism=1).hash(plaintext)


def verify_password(plaintext: str, hashed: str) -> bool:
    try:
        return argon2.verify(plaintext, hashed)
    except Exception:
        return False


def new_session_id() -> str:
    return secrets.token_urlsafe(32)


def create_session(db_path: str, user_id: int, lifetime_secs: int) -> str:
    sid = new_session_id()
    expires = (datetime.now(timezone.utc) + timedelta(seconds=lifetime_secs)).isoformat()
    with connect(db_path) as c:
        c.execute(
            "INSERT INTO sessions(id, user_id, mfa_passed, expires_at) VALUES(?,?,?,?)",
            (sid, user_id, 0, expires),
        )
    return sid


def mark_session_mfa_passed(db_path: str, session_id: str) -> None:
    with connect(db_path) as c:
        c.execute("UPDATE sessions SET mfa_passed=1 WHERE id=?", (session_id,))


def get_session(db_path: str, session_id: str) -> dict | None:
    with connect(db_path) as c:
        row = c.execute(
            "SELECT s.id, s.user_id, s.mfa_passed, s.expires_at, u.username, u.totp_confirmed "
            "FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.id = ?",
            (session_id,),
        ).fetchone()
    if not row:
        return None
    if datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
        delete_session(db_path, session_id)
        return None
    return dict(row)


def delete_session(db_path: str, session_id: str) -> None:
    with connect(db_path) as c:
        c.execute("DELETE FROM sessions WHERE id=?", (session_id,))


def cleanup_expired_sessions(db_path: str) -> None:
    with connect(db_path) as c:
        c.execute("DELETE FROM sessions WHERE expires_at < datetime('now')")


def get_user_by_username(db_path: str, username: str) -> dict | None:
    with connect(db_path) as c:
        row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    return dict(row) if row else None


def get_user_by_id(db_path: str, user_id: int) -> dict | None:
    with connect(db_path) as c:
        row = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return dict(row) if row else None


def create_user(db_path: str, username: str, password: str) -> int:
    pw = hash_password(password)
    with connect(db_path) as c:
        cur = c.execute(
            "INSERT INTO users(username, password_hash) VALUES(?,?)",
            (username, pw),
        )
        return cur.lastrowid


def update_password(db_path: str, user_id: int, new_password: str) -> None:
    pw = hash_password(new_password)
    with connect(db_path) as c:
        c.execute("UPDATE users SET password_hash=? WHERE id=?", (pw, user_id))


def delete_other_sessions(db_path: str, user_id: int, keep_session_id: str) -> int:
    with connect(db_path) as c:
        cur = c.execute(
            "DELETE FROM sessions WHERE user_id=? AND id<>?",
            (user_id, keep_session_id),
        )
        return cur.rowcount or 0


def reset_totp(db_path: str, user_id: int) -> None:
    """Clear TOTP so the user is forced to re-enroll on next login."""
    with connect(db_path) as c:
        c.execute(
            "UPDATE users SET totp_secret=NULL, totp_confirmed=0 WHERE id=?",
            (user_id,),
        )


def set_totp_secret(db_path: str, user_id: int, secret: str) -> None:
    with connect(db_path) as c:
        c.execute(
            "UPDATE users SET totp_secret=?, totp_confirmed=0 WHERE id=?",
            (secret, user_id),
        )


def confirm_totp(db_path: str, user_id: int) -> None:
    with connect(db_path) as c:
        c.execute("UPDATE users SET totp_confirmed=1 WHERE id=?", (user_id,))


def make_totp_uri(secret: str, username: str, issuer: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def make_qr_svg(uri: str) -> str:
    qr = segno.make(uri, error="m")
    return qr.svg_inline(scale=6, dark="#111", light="#fff")


def verify_totp(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def bootstrap_admin(db_path: str, username: str, password: str) -> None:
    if not username or not password:
        return
    if get_user_by_username(db_path, username):
        return
    create_user(db_path, username, password)
