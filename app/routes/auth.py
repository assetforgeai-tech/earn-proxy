from __future__ import annotations

import sqlite3

from flask import Blueprint, current_app, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from app.db import get_db
from app.registration_rate_limit import admit_login_attempt, admit_registration_attempt, request_identity
from app.routes.forms import form_error, form_success, is_browser_form
from app.services.users import create_user

bp = Blueprint("auth", __name__)

# A valid password hash keeps the unknown-account path at the same expensive
# verification step as the known-account path without storing a real secret.
_DUMMY_PASSWORD_HASH = (
    "scrypt:32768:8:1$GszEukes0tkczT9u$"
    "b67903a8373a7ca6a60d6eec81b92e609842e0e57e549a89994034b13dd0f9b35565b91a1d1217f8d85dc39fbb98006aa4b1e72b80033b66913abad7b2de26a2"
)


@bp.route("/register", methods=("GET", "POST"))
def register():
    if request.method == "GET":
        return render_template("register.html")
    database = get_db()
    if not admit_registration_attempt(database, request_identity(request), current_app.config):
        return form_error(
            "Too many registration attempts. Try again later.",
            429,
            "auth.register",
            field="email",
        )
    email = str(request.form.get("email") or "").strip().lower()
    password = str(request.form.get("password") or "")
    if "@" not in email or len(password) < 8:
        field = "email" if "@" not in email else "password"
        return form_error(
            "A valid email and password of at least 8 characters are required",
            400,
            "auth.register",
            field=field,
        )
    try:
        create_user(database, email, password)
    except sqlite3.IntegrityError:
        # Keep account existence indistinguishable from a new pending request.
        return form_success(
            {"status": "pending"},
            status=201,
            endpoint="auth.login",
            message="Registration received. Your account is awaiting administrator approval.",
        )
    return form_success(
        {"status": "pending"},
        status=201,
        endpoint="auth.login",
        message="Registration received. Your account is awaiting administrator approval.",
    )


@bp.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "GET":
        if g.user is not None:
            endpoint = "admin.dashboard" if g.user["role"] == "admin" else "dashboard.dashboard"
            return redirect(url_for(endpoint))
        return render_template("login.html")
    email = str(request.form.get("email") or "").strip().lower()
    password = str(request.form.get("password") or "")
    database = get_db()
    if not admit_login_attempt(database, request_identity(request), email, current_app.config):
        return form_error("Too many sign-in attempts. Try again later.", 429, "auth.login", field="email")
    user = database.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    password_valid = check_password_hash(user["password_hash"] if user is not None else _DUMMY_PASSWORD_HASH, password)
    if user is None or not password_valid:
        field = "email" if "@" not in email else "password"
        return form_error("Invalid email or password", 401, "auth.login", field=field)
    if user["status"] != "active":
        return form_error("Account is awaiting approval or blocked", 403, "auth.login", field="email")
    session.clear()
    session["user_id"] = user["id"]
    session["session_version"] = user["session_version"]
    login_endpoint = "admin.dashboard" if user["role"] == "admin" else "dashboard.dashboard"
    return form_success(
        {"id": user["id"], "role": user["role"], "status": user["status"]},
        endpoint=login_endpoint,
        message="Signed in successfully.",
    )


@bp.post("/logout")
def logout():
    # Flask's signed cookie is stateless, so bump the server-side version to
    # invalidate copies of the cookie that may have been captured elsewhere.
    if g.user is not None:
        db = get_db()
        db.execute(
            "UPDATE users SET session_version=session_version+1 WHERE id=?",
            (g.user["id"],),
        )
        db.commit()
    session.clear()
    if is_browser_form():
        flash("Signed out.", "success")
        return redirect(url_for("auth.login"), code=303)
    return "", 204
