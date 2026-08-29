from conftest import login_admin

from app.db import get_db


def test_admin_ui_exposes_health_interval_concurrency_and_api_status_toggles(app, client):
    login_admin(client)
    page = client.get("/admin").get_data(as_text=True)

    assert 'name="health_interval_minutes"' in page
    assert 'value="60"' in page
    assert 'name="health_concurrency"' in page
    assert 'value="5"' in page
    assert 'name="api_include_allow"' in page
    assert 'name="api_include_risk"' in page


def test_admin_can_update_checker_settings_and_api_toggles(app, client):
    login_admin(client)
    response = client.post(
        "/admin/settings",
        data={
            "health_interval_minutes": "60",
            "health_concurrency": "3",
            "api_include_allow": "1",
        },
    )
    assert response.status_code == 200

    with app.app_context():
        settings = dict(get_db().execute("SELECT key, value FROM settings").fetchall())
    assert settings["health_interval_minutes"] == "60"
    assert settings["health_concurrency"] == "3"
    assert settings["api_include_allow"] == "1"
    assert settings["api_include_risk"] == "0"


def test_admin_cannot_raise_checker_concurrency_above_safe_cap(app, client):
    login_admin(client)
    response = client.post(
        "/admin/settings",
        data={"health_interval_minutes": "60", "health_concurrency": "50"},
    )
    assert response.status_code == 200
    with app.app_context():
        value = get_db().execute("SELECT value FROM settings WHERE key='health_concurrency'").fetchone()["value"]
    assert value == "5"
