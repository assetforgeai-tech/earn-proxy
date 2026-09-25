from __future__ import annotations

from datetime import UTC, datetime

from werkzeug.security import generate_password_hash

MAX_EMAIL_LENGTH = 254


def create_user(db, email: str, password: str, *, status: str = "pending", role: str = "user") -> int:
    normalized_email = str(email or "").strip().lower()
    if len(normalized_email) > MAX_EMAIL_LENGTH:
        raise ValueError("email exceeds maximum length")
    cursor = db.execute(
        "INSERT INTO users(email, password_hash, role, status, created_at) VALUES (?, ?, ?, ?, ?)",
        (
            normalized_email,
            generate_password_hash(password),
            role,
            status,
            datetime.now(UTC).isoformat(),
        ),
    )
    db.commit()
    return int(cursor.lastrowid)
