from __future__ import annotations

import sqlite3

from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from app.db import get_db
from app.routes.forms import form_error, form_success, is_browser_form
from app.services.users import create_user

bp = Blueprint("auth", __name__)


@bp.route("/register", methods=("GET", "POST"))
def register():
    if request.method == "GET":
        return render_template("register.html")
    email = str(request.form.get("email") or "").strip().lower()
    password = str(request.form.get("password") or "")
    if "@" not in email or len(password) < 8:
        return form_error(
            "A valid email and password of at least 8 characters are required",
            400,
            "auth.register",
        )
    try:
        user_id = create_user(get_db(), email, password)
    except sqlite3.IntegrityError:
        return form_error("Email is already registered", 409, "auth.register")
    return form_success(
        {"id": user_id, "status": "pending"},
        status=201,
        endpoint="auth.login",
        message="Registration received. Your account is awaiting administrator approval.",
    )


@bp.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "GET":
        return render_template("login.html")
    email = str(request.form.get("email") or "").strip().lower()
    password = str(request.form.get("password") or "")
    user = get_db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if user is None or not check_password_hash(user["password_hash"], password):
        return form_error("Invalid email or password", 401, "auth.login")
    if user["status"] != "active":
        return form_error("Account is awaiting approval or blocked", 403, "auth.login")
    session.clear()
    session["user_id"] = user["id"]
    session["session_version"] = user["session_version"]
    return form_success(
        {"id": user["id"], "role": user["role"], "status": user["status"]},
        endpoint="dashboard.dashboard",
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
