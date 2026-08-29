from __future__ import annotations

from datetime import UTC, datetime

from werkzeug.security import generate_password_hash


def create_user(db, email: str, password: str, *, status: str = "pending", role: str = "user") -> int:
    cursor = db.execute(
        "INSERT INTO users(email, password_hash, role, status, created_at) VALUES (?, ?, ?, ?, ?)",
        (
            str(email or "").strip().lower(),
            generate_password_hash(password),
            role,
            status,
            datetime.now(UTC).isoformat(),
        ),
    )
    db.commit()
    return int(cursor.lastrowid)
