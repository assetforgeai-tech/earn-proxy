from __future__ import annotations

from datetime import UTC, datetime

from app.db import get_db
from app.services.proxiware_credentials import (
    clear_provider_secret,
    get_provider_secret,
    get_provider_secret_metadata,
    load_provider_session,
    redact_provider_payload,
    renew_provider_session,
    save_provider_credentials,
    save_provider_secret,
    store_provider_session,
)
from app.services.proxiware_credentials import test_provider_connections as check_provider_connections
from app.services.settings import get_setting, set_setting


class FakeCaptcha:
    def __init__(self, token="captcha-result", balance=3.5, error=None):
        self.token = token
        self.balance = balance
        self.error = error

    def solve_hcaptcha(self, *, site_key, page_url):
        if self.error:
            raise RuntimeError(self.error)
        assert site_key == "site-key"
        assert page_url == "https://app.proxiware.com/login"
        return self.token

    def get_balance(self):
        return self.balance


class FakeBrowser:
    def __init__(self, result=None, error=None):
        self.result = result or {
            "cookies": [{"name": "session", "value": "browser-cookie-secret"}],
            "expires_at": "2026-09-25T12:00:00+00:00",
            "fingerprint_observed": True,
        }
        self.error = error
        self.kwargs = None

    def renew(self, **kwargs):
        self.kwargs = kwargs
        if self.error:
            raise RuntimeError(self.error)
        return self.result


class FakeApiClient:
    def __init__(self, account=None):
        self.account = account or {"id": 123, "email": "owner@example.com"}

    def get_account(self):
        return self.account


def test_bulk_secret_update_preserves_blank_and_clear_is_explicit(app):
    with app.app_context():
        db = get_db()
        save_provider_secret(db, "api_key", "first-secret-key")
        save_provider_credentials(db, {"api_key": "", "login_email": "owner@example.com"})
        assert get_provider_secret(db, "api_key") == "first-secret-key"
        assert clear_provider_secret(db, "api_key") is True
        assert get_provider_secret(db, "api_key") is None


def test_secret_metadata_never_returns_plaintext_ciphertext_or_password_suffix(app):
    with app.app_context():
        db = get_db()
        save_provider_credentials(
            db,
            {
                "login_email": "owner@example.com",
                "login_password": "correct horse battery staple",
                "api_key": "px_api_12345678",
                "captcha_api_key": "2captcha_87654321",
            },
        )
        metadata = get_provider_secret_metadata(db)
        serialized = repr(metadata)
    assert "correct horse" not in serialized
    assert "px_api_12345678" not in serialized
    assert metadata["login_password"]["last_four"] == ""
    assert metadata["api_key"]["last_four"] == "5678"


def test_provider_session_cookie_is_encrypted_at_rest(app):
    expiry = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        store_provider_session(db, [{"name": "session", "value": "cookie-secret"}], expires_at=expiry)
        row = db.execute("SELECT * FROM provider_sessions WHERE provider='proxiware'").fetchone()
        decoded = load_provider_session(db)
    assert "cookie-secret" not in row["cookie_encrypted"]
    assert decoded[0]["value"] == "cookie-secret"


def test_session_renewal_uses_injected_adapters_and_persists_no_ephemeral_material(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    browser = FakeBrowser()
    captcha = FakeCaptcha()
    with app.app_context():
        db = get_db()
        save_provider_credentials(
            db,
            {"login_email": "owner@example.com", "login_password": "password", "captcha_api_key": "solver-key"},
        )
        result = renew_provider_session(
            db,
            browser,
            captcha,
            site_key="site-key",
            page_url="https://app.proxiware.com/login",
            now=now,
        )
        dump = " ".join(
            str(value)
            for table in ("provider_sessions", "provider_audit_events")
            for row in db.execute(f"SELECT * FROM {table}").fetchall()
            for value in tuple(row)
        )
    assert result.state == "active"
    assert browser.kwargs == {
        "email": "owner@example.com",
        "password": "password",
        "captcha_token": "captcha-result",
    }
    assert "captcha-result" not in dump
    assert "password" not in dump
    assert "fingerprint" not in dump


def test_missing_real_fingerprint_fails_closed_and_pauses_swaps(app):
    browser = FakeBrowser(result={"cookies": [{"name": "session", "value": "secret"}]})
    with app.app_context():
        db = get_db()
        save_provider_credentials(db, {"login_email": "owner@example.com", "login_password": "password"})
        set_setting(db, "proxiware_auto_swap", "1")
        result = renew_provider_session(
            db,
            browser,
            FakeCaptcha(),
            site_key="site-key",
            page_url="https://app.proxiware.com/login",
        )
        session = db.execute("SELECT * FROM provider_sessions WHERE provider='proxiware'").fetchone()
        paused = get_setting(db, "proxiware_auto_swap", "1")
    assert result.state == "manual_action_required"
    assert result.error_code == "fingerprint_failed"
    assert session["state"] == "manual_action_required"
    assert paused == "0"


def test_captcha_failure_records_safe_code_not_exception_text(app):
    with app.app_context():
        db = get_db()
        save_provider_credentials(db, {"login_email": "owner@example.com", "login_password": "password"})
        result = renew_provider_session(
            db,
            FakeBrowser(),
            FakeCaptcha(error="captcha provider leaked-key-123"),
            site_key="site-key",
            page_url="https://app.proxiware.com/login",
        )
        audit = db.execute("SELECT * FROM provider_audit_events ORDER BY id DESC LIMIT 1").fetchone()
    assert result.error_code == "captcha_timeout"
    assert audit["error_code"] == "captcha_timeout"
    assert "leaked-key-123" not in repr(dict(audit))


def test_connection_check_is_read_only_and_returns_safe_status(app):
    with app.app_context():
        db = get_db()
        before = db.total_changes
        report = check_provider_connections(db, FakeApiClient(), FakeCaptcha())
        after = db.total_changes
    assert report.api_ok is True
    assert report.captcha_ok is True
    assert report.captcha_balance == 3.5
    assert after == before


def test_structured_redaction_removes_secret_fields():
    assert redact_provider_payload({"api_key": "secret", "nested": {"cookie": "value", "status": "ok"}}) == {
        "api_key": "[redacted]",
        "nested": {"cookie": "[redacted]", "status": "ok"},
    }


def test_manual_action_error_code_is_allowlisted(app):
    from app.services.proxiware_credentials import mark_manual_action_required

    with app.app_context():
        db = get_db()
        set_setting(db, "proxiware_auto_swap", "1")
        mark_manual_action_required(db, "secret=password123")
        row = db.execute("SELECT state,last_error_code FROM provider_sessions WHERE provider='proxiware'").fetchone()
        paused = get_setting(db, "proxiware_auto_swap", "1")
    assert row["state"] == "manual_action_required"
    assert row["last_error_code"] == "manual_action_required"
    assert paused == "0"


def test_browser_adapter_unavailable_maps_to_manual_action_required(app):
    from app.services.proxiware_browser import BrowserAdapterUnavailable

    with app.app_context():
        db = get_db()
        save_provider_credentials(
            db,
            {"login_email": "owner@example.com", "login_password": "password", "captcha_api_key": "key"},
        )
        result = renew_provider_session(
            db,
            type(
                "Browser", (), {"renew": lambda *_args, **_kwargs: (_ for _ in ()).throw(BrowserAdapterUnavailable())}
            )(),
            type("Captcha", (), {"solve_hcaptcha": lambda *_args, **_kwargs: "token"})(),
            site_key="site-key",
            page_url="https://app.proxiware.com/login",
        )

        row = db.execute("SELECT state,last_error_code FROM provider_sessions WHERE provider='proxiware'").fetchone()

    assert result.state == "manual_action_required"
    assert result.error_code == "manual_action_required"
    assert tuple(row) == ("manual_action_required", "manual_action_required")


def test_manual_action_pauses_only_canonical_auto_swap_setting(app):
    from app.services.proxiware_credentials import mark_manual_action_required

    with app.app_context():
        db = get_db()
        db.execute(
            "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)",
            ("proxiware_auto_swap_enabled", "1", "2026-01-01T00:00:00+00:00"),
        )
        db.commit()
        mark_manual_action_required(db, "captcha_timeout")
        values = dict(db.execute("SELECT key,value FROM settings WHERE key LIKE 'proxiware_auto_swap%'").fetchall())

    assert values["proxiware_auto_swap"] == "0"
    assert "proxiware_auto_swap_enabled" not in values


def test_provider_credentials_are_explicitly_scoped_to_proxiware(app):
    with app.app_context():
        db = get_db()
        columns = {row["name"] for row in db.execute('PRAGMA table_info("provider_credentials")').fetchall()}
        assert "provider" in columns

        save_provider_credentials(db, {"api_key": "provider-key"})
        row = db.execute("SELECT provider FROM provider_credentials WHERE name='api_key'").fetchone()
        assert row["provider"] == "proxiware"

        db.execute("UPDATE provider_credentials SET provider='other-provider' WHERE name='api_key'")
        db.commit()
        assert get_provider_secret(db, "api_key") is None
