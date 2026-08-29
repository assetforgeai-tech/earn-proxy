from __future__ import annotations

from flask import flash, jsonify, redirect, request, url_for


def is_browser_form() -> bool:
    return request.form.get("ui") == "1"


def form_error(message: str, status: int, endpoint: str, **values):
    if is_browser_form():
        flash(message, "error")
        return redirect(url_for(endpoint, **values), code=303)
    return jsonify(error=message), status


def form_success(
    payload: dict,
    *,
    endpoint: str,
    message: str,
    status: int = 200,
    **values,
):
    if is_browser_form():
        flash(message, "success")
        return redirect(url_for(endpoint, **values), code=303)
    return jsonify(payload), status
