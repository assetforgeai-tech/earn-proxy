from __future__ import annotations

from functools import wraps

from flask import abort, g, session

from app.db import get_db


def load_logged_in_user() -> None:
    user_id = session.get("user_id")
    if user_id is None:
        g.user = None
        return
    user = get_db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if (
        user is None
        or user["status"] != "active"
        or int(session.get("session_version", 0)) != int(user["session_version"])
    ):
        session.clear()
        g.user = None
        return
    g.user = user


def login_required(view):
    @wraps(view)
    def wrapped(**kwargs):
        if g.user is None:
            abort(401)
        return view(**kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(**kwargs):
        if g.user is None or g.user["role"] != "admin":
            abort(403)
        return view(**kwargs)

    return wrapped
