from __future__ import annotations

import csv
import io
from urllib.parse import quote

from flask import Blueprint, current_app, flash, g, redirect, request, url_for

from app.auth import login_required
from app.db import get_db
from app.proxy_parser import ProxyParseError
from app.routes.forms import form_error, form_success, is_browser_form
from app.services.proxies import (
    DuplicateCredential,
    ProxyImportLimitExceeded,
    ProxyQuotaExceeded,
    add_proxy,
    archive_proxy,
    bulk_add_proxies,
    replace_proxy,
)

bp = Blueprint("proxies", __name__, url_prefix="/proxies")


def _import_lines_from_request() -> tuple[list[str], str | None]:
    """Read text and optional UTF-8 file input without echoing uploaded data."""
    max_bytes = max(1, int(current_app.config.get("MAX_PROXY_IMPORT_BYTES", 512 * 1024)))
    max_lines = max(1, int(current_app.config.get("MAX_PROXY_IMPORT_LINES", 5_000)))
    chunks: list[str] = []
    total_bytes = 0

    if request.is_json:
        content_length = request.content_length
        if content_length is not None and content_length > max_bytes:
            raise ProxyImportLimitExceeded(f"Import input is limited to {max_bytes // 1024} KB")
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            raise ValueError("JSON import body must be an object")
        raw_value = payload.get("raw_proxies", payload.get("raw_proxy", ""))
        if isinstance(raw_value, list):
            if not all(isinstance(item, str) for item in raw_value):
                raise ValueError("JSON proxy lines must be strings")
            text_lines = list(raw_value)
        elif isinstance(raw_value, str):
            text_lines = str(raw_value or "").splitlines()
        elif raw_value in (None, ""):
            text_lines = []
        else:
            raise ValueError("JSON proxy input must be a string or an array of strings")
        total_bytes += content_length if content_length is not None else len("\n".join(text_lines).encode("utf-8"))
        chunks.extend(text_lines)
    else:
        raw_text = request.form.get("raw_proxies", request.form.get("raw_proxy", ""))
        if raw_text:
            encoded = raw_text.encode("utf-8")
            total_bytes += len(encoded)
            chunks.extend(raw_text.splitlines())
        upload = request.files.get("proxy_file")
        if upload is not None and upload.filename:
            filename = str(upload.filename or "").lower()
            if not filename.endswith((".txt", ".csv")):
                raise ProxyImportLimitExceeded("Import file must use a .txt or .csv extension")
            payload = upload.stream.read(max_bytes + 1)
            if len(payload) > max_bytes:
                raise ProxyImportLimitExceeded(f"Import file is limited to {max_bytes // 1024} KB")
            total_bytes += len(payload)
            try:
                file_text = payload.decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                raise ProxyImportLimitExceeded("Import file must be UTF-8 text") from exc
            if any(ord(char) < 32 and char not in "\r\n\t" for char in file_text):
                raise ProxyImportLimitExceeded("Import file must be UTF-8 text without binary control characters")
            if filename.endswith(".csv"):
                chunks.extend(_csv_proxy_lines(file_text))
            else:
                chunks.extend(file_text.splitlines())

    if total_bytes > max_bytes:
        raise ProxyImportLimitExceeded(f"Import input is limited to {max_bytes // 1024} KB")
    if len(chunks) > max_lines:
        raise ProxyImportLimitExceeded(f"A single import can contain at most {max_lines} lines")
    if not any(str(line).strip() for line in chunks):
        raise ValueError("Add proxy lines or choose a text file")
    return chunks, None


def _csv_proxy_lines(file_text: str) -> list[str]:
    """Accept one raw proxy per row or a simple host/port/credential CSV."""
    try:
        rows = list(csv.reader(io.StringIO(file_text), strict=True))
    except csv.Error as exc:
        raise ValueError("CSV file is malformed") from exc
    if not rows:
        return []
    header = [str(value or "").strip().lower().removeprefix("\ufeff") for value in rows[0]]
    aliases = {
        "raw_proxy": {"raw_proxy", "proxy", "url", "endpoint"},
        "host": {"host", "ip", "server"},
        "port": {"port"},
        "username": {"username", "user", "login"},
        "password": {"password", "pass", "secret"},
        "protocol": {"protocol", "scheme", "type"},
    }
    indexes = {
        key: next((index for index, value in enumerate(header) if value in names), None)
        for key, names in aliases.items()
    }
    has_header = indexes["raw_proxy"] is not None or (indexes["host"] is not None and indexes["port"] is not None)
    if not has_header:
        if any(len(row) > 1 for row in rows if any(str(value or "").strip() for value in row)):
            raise ValueError("CSV must use one raw proxy column or supported structured headers")
        return [str(row[0] or "").strip() if row else "" for row in rows]
    data_rows = rows[1:] if has_header else rows
    lines: list[str] = []
    for row in data_rows:
        if not any(str(value or "").strip() for value in row):
            lines.append("")
            continue
        if indexes["raw_proxy"] is not None:
            value = row[indexes["raw_proxy"]] if indexes["raw_proxy"] < len(row) else ""
            lines.append(str(value or "").strip())
            continue
        host = row[indexes["host"]] if indexes["host"] is not None and indexes["host"] < len(row) else ""
        port = row[indexes["port"]] if indexes["port"] is not None and indexes["port"] < len(row) else ""
        username = (
            row[indexes["username"]] if indexes["username"] is not None and indexes["username"] < len(row) else ""
        )
        password = (
            row[indexes["password"]] if indexes["password"] is not None and indexes["password"] < len(row) else ""
        )
        protocol = (
            row[indexes["protocol"]] if indexes["protocol"] is not None and indexes["protocol"] < len(row) else ""
        )
        raw = f"{host}:{port}"
        if username or password:
            raw += f":{username}:{password}"
        if protocol:
            if username or password:
                credentials = f"{quote(str(username), safe='')}:{quote(str(password), safe='')}@"
                raw = f"{protocol}://{credentials}{host}:{port}"
            else:
                raw = f"{protocol}://{host}:{port}"
        lines.append(raw)
    return lines


def _import_summary(result) -> str:
    parts = [f"{result.added} added"]
    if result.duplicates:
        parts.append(f"{result.duplicates} duplicate")
    if result.invalid:
        parts.append(f"{result.invalid} invalid")
    if result.quota_skipped:
        parts.append(f"{result.quota_skipped} skipped by quota")
    if result.ignored_blank:
        parts.append(f"{result.ignored_blank} blank line(s) ignored")
    message = "Import complete: " + ", ".join(parts) + "."
    if result.issues:
        line_labels = ", ".join(f"line {issue.line} ({issue.category})" for issue in result.issues[:8])
        hidden_count = max(0, len(result.issues) - 8) + int(result.issues_truncated or 0)
        suffix = "" if hidden_count == 0 else f" +{hidden_count} more"
        message += f" Review {line_labels}{suffix}."
    return message


@bp.post("")
@login_required
def create_proxy():
    if g.user["role"] != "user":
        return form_error("Only user accounts can add proxies", 403, "dashboard.proxies")
    db = get_db()
    try:
        quota = max(1, min(10_000, int(current_app.config.get("MAX_ACTIVE_PROXIES_PER_USER", 5_000))))
    except (TypeError, ValueError):
        quota = 5_000
    # Fast rejection keeps malformed input out of the service when the quota
    # is already exhausted; add_proxy repeats this check under a write lock.
    active_count = int(
        db.execute(
            "SELECT COUNT(*) AS count FROM proxies WHERE user_id=? AND archived_at IS NULL",
            (g.user["id"],),
        ).fetchone()["count"]
    )
    if active_count >= quota:
        return form_error(
            f"This account has reached the maximum number of active proxies ({quota})",
            429,
            "dashboard.proxies",
            field="raw_proxy",
            focus="raw_proxy",
        )
    try:
        proxy_id = add_proxy(
            db,
            g.user["id"],
            request.form.get("raw_proxy", ""),
            max_active_proxies=quota,
        )
    except ProxyParseError as exc:
        return form_error(str(exc), 400, "dashboard.proxies", field="raw_proxy", focus="raw_proxy")
    except DuplicateCredential as exc:
        return form_error(str(exc), 409, "dashboard.proxies", field="raw_proxy", focus="raw_proxy")
    except ProxyQuotaExceeded as exc:
        return form_error(str(exc), 429, "dashboard.proxies", field="raw_proxy", focus="raw_proxy")
    return form_success(
        {"id": proxy_id, "status": "pending"},
        status=201,
        endpoint="dashboard.proxies",
        message="Proxy added and queued for checking.",
    )


@bp.post("/import")
@login_required
def import_proxies():
    if g.user["role"] != "user":
        return form_error("Only user accounts can add proxies", 403, "dashboard.proxies")
    db = get_db()
    try:
        lines, _ = _import_lines_from_request()
        quota = max(1, min(10_000, int(current_app.config.get("MAX_ACTIVE_PROXIES_PER_USER", 5_000))))
        result = bulk_add_proxies(
            db,
            g.user["id"],
            lines,
            max_active_proxies=quota,
            max_lines=max(1, int(current_app.config.get("MAX_PROXY_IMPORT_LINES", 5_000))),
        )
    except (ValueError, ProxyImportLimitExceeded) as exc:
        return form_error(str(exc), 400, "dashboard.proxies", field="raw_proxies", focus="raw_proxies")

    payload = result.as_dict()
    payload["status"] = "accepted"
    if is_browser_form():
        flash(_import_summary(result), "success" if result.added else "error")
        return redirect(url_for("dashboard.proxies", error_focus="raw_proxies" if result.issues else ""), code=303)
    return payload, 201


@bp.post("/<int:proxy_id>/replace")
@login_required
def replace(proxy_id: int):
    try:
        replace_proxy(get_db(), proxy_id, g.user["id"], request.form.get("raw_proxy", ""))
    except (ProxyParseError, DuplicateCredential) as exc:
        return form_error(
            str(exc),
            400,
            "dashboard.proxies",
            field="raw_proxy",
            focus=f"replace-{proxy_id}",
        )
    except LookupError as exc:
        return form_error(str(exc), 404, "dashboard.proxies")
    return form_success(
        {"id": proxy_id, "status": "pending"},
        endpoint="dashboard.proxies",
        message="Proxy replaced and queued for checking.",
    )


@bp.post("/<int:proxy_id>/delete")
@login_required
def delete(proxy_id: int):
    try:
        archive_proxy(get_db(), proxy_id, g.user["id"])
    except LookupError as exc:
        return form_error(str(exc), 404, "dashboard.proxies")
    if is_browser_form():
        flash("Proxy removed. Historical earnings are retained.", "success")
        return redirect(url_for("dashboard.proxies"), code=303)
    return "", 204
