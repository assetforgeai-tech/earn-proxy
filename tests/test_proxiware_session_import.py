from __future__ import annotations

import io
import json
from datetime import UTC, datetime

import pytest

from app.db import get_db
from app.services.proxiware_credentials import load_provider_session
from scripts.proxiware_session_import import import_session


def test_import_session_validates_and_encrypts_proxiware_cookies(app):
    raw_cookie = "opaque-session-secret"
    payload = json.dumps(
        [
            {
                "name": "session",
                "value": raw_cookie,
                "domain": ".proxiware.com",
                "path": "/",
                "secure": True,
                "httpOnly": True,
                "expires": 1_800_000_000,
            }
        ]
    )

    with app.app_context():
        result = import_session(get_db(), io.StringIO(payload), now=datetime(2026, 9, 27, tzinfo=UTC))
        row = (
            get_db()
            .execute("SELECT cookie_encrypted,state,expires_at FROM provider_sessions WHERE provider='proxiware'")
            .fetchone()
        )
        restored = load_provider_session(get_db())

    assert result == {"status": "active", "cookie_count": 1, "expires_at": "2027-01-15T08:00:00+00:00"}
    assert row["state"] == "active"
    assert raw_cookie not in row["cookie_encrypted"]
    assert restored[0]["value"] == raw_cookie


def test_import_session_rejects_cookie_outside_proxiware_origin(app):
    payload = json.dumps([{"name": "session", "value": "secret", "domain": ".example.com", "path": "/"}])

    with app.app_context(), pytest.raises(ValueError, match="invalid_session"):
        import_session(get_db(), io.StringIO(payload))

    with app.app_context():
        row = get_db().execute("SELECT state FROM provider_sessions WHERE provider='proxiware'").fetchone()
    assert row is None


def test_import_session_rejects_oversized_input_without_echoing_secret(app):
    secret = "s" * 70_000

    with app.app_context(), pytest.raises(ValueError, match="input_too_large") as error:
        import_session(get_db(), io.StringIO(secret))

    assert secret not in str(error.value)
