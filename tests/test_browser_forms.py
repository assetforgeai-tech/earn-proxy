from io import BytesIO

from conftest import login, login_admin, register

from app.db import get_db
from app.services.proxies import add_proxy


def _activate_user(app, client, email="browser@example.com"):
    register(client, email, "member-password")
    login_admin(client)
    with app.app_context():
        user_id = get_db().execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
    client.post(f"/admin/users/{user_id}/approve")
    client.post("/logout")
    return user_id


def test_browser_login_redirects_to_dashboard_and_keeps_json_contract(app, client):
    _activate_user(app, client)

    browser_response = client.post(
        "/login",
        data={"email": "browser@example.com", "password": "member-password", "ui": "1"},
    )
    assert browser_response.status_code == 303
    assert browser_response.headers["Location"].endswith("/dashboard")

    client.post("/logout")
    api_response = login(client, "browser@example.com", "member-password")
    assert api_response.status_code == 200
    assert api_response.get_json()["status"] == "active"


def test_browser_admin_login_redirects_to_admin(client):
    response = client.post(
        "/login",
        data={
            "email": "admin@example.com",
            "password": "correct horse battery staple",
            "ui": "1",
        },
    )
    assert response.status_code == 303
    assert response.headers["Location"].endswith("/admin")


def test_browser_registration_and_validation_show_feedback(client):
    invalid = client.post(
        "/register",
        data={"email": "invalid", "password": "short", "ui": "1"},
        follow_redirects=True,
    )
    assert invalid.status_code == 200
    assert "valid email" in invalid.get_data(as_text=True).lower()

    created = client.post(
        "/register",
        data={"email": "pending@example.com", "password": "member-password", "ui": "1"},
        follow_redirects=True,
    )
    assert created.status_code == 200
    page = created.get_data(as_text=True)
    assert "awaiting administrator approval" in page.lower()
    assert "Sign in" in page


def test_admin_browser_forms_redirect_and_flash(app, client):
    login_admin(client)
    response = client.post(
        "/admin/settings",
        data={
            "health_interval_minutes": "60",
            "health_concurrency": "3",
            "api_include_allow": "1",
            "api_include_risk": "1",
            "ui": "1",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "Checker policy saved" in page
    assert 'value="60"' in page
    assert 'value="3"' in page


def test_user_browser_forms_return_to_the_focused_contributor_workspace(app, client):
    user_id = _activate_user(app, client)
    login(client, "browser@example.com", "member-password")

    added = client.post(
        "/proxies",
        data={"raw_proxy": "browser-proxy.example:9000:user:pass", "ui": "1"},
        follow_redirects=True,
    )
    assert added.status_code == 200
    page = added.get_data(as_text=True)
    assert "Proxy added" in page
    assert "browser-proxy.example:9000" in page
    assert 'action="/payouts"' not in page
    assert 'data-nav="proxy_pool" aria-current="page"' in page

    with app.app_context():
        proxy_id = add_proxy(get_db(), user_id, "second-proxy.example:9001:user:pass")
    removed = client.post(f"/proxies/{proxy_id}/delete", data={"ui": "1"})
    assert removed.status_code == 303
    assert removed.headers["Location"].endswith("/dashboard/proxies")

    wallet = client.post(
        "/wallet",
        data={"address": "0x1111111111111111111111111111111111111111", "ui": "1"},
    )
    assert wallet.status_code == 303
    assert wallet.headers["Location"].endswith("/dashboard/wallet")


def test_user_can_import_multiline_text_and_utf8_text_file(app, client):
    user_id = _activate_user(app, client, "bulk-browser@example.com")
    login(client, "bulk-browser@example.com", "member-password")

    response = client.post(
        "/proxies/import",
        data={
            "raw_proxies": "text-one.example:9000:user:text-secret\ntext-two.example:9001",
            "proxy_file": (BytesIO(b"file-one.example:9002:user:file-secret\n"), "proxies.txt"),
            "ui": "1",
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "3 added" in page
    assert "text-one.example:9000" in page
    assert "file-one.example:9002" in page
    assert "text-secret" not in page
    assert "file-secret" not in page
    with app.app_context():
        count = (
            get_db().execute("SELECT COUNT(*) AS count FROM proxies WHERE user_id=?", (user_id,)).fetchone()["count"]
        )
    assert count == 3


def test_bulk_import_json_reports_safe_line_errors(app, client):
    user_id = _activate_user(app, client, "bulk-json@example.com")
    login(client, "bulk-json@example.com", "member-password")

    response = client.post(
        "/proxies/import",
        json={
            "raw_proxies": "valid.example:9000:user:valid-secret\ninvalid-value:invalid-secret",
        },
    )

    assert response.status_code == 201
    payload = response.get_json()
    assert payload["added"] == 1
    assert payload["invalid"] == 1
    assert payload["issues"][0]["line"] == 2
    assert "valid-secret" not in str(payload)
    assert "invalid-secret" not in str(payload)
    with app.app_context():
        count = (
            get_db().execute("SELECT COUNT(*) AS count FROM proxies WHERE user_id=?", (user_id,)).fetchone()["count"]
        )
    assert count == 1


def test_bulk_import_rejects_missing_or_non_utf8_input(app, client):
    _activate_user(app, client, "bulk-invalid@example.com")
    login(client, "bulk-invalid@example.com", "member-password")

    missing = client.post("/proxies/import", json={"raw_proxies": "\n\n"})
    invalid_file = client.post(
        "/proxies/import",
        data={"proxy_file": (BytesIO(b"\xff\xfe\x00\x80"), "proxies.txt")},
        content_type="multipart/form-data",
    )

    assert missing.status_code == 400
    assert invalid_file.status_code == 400
    assert "utf-8" in invalid_file.get_json()["error"].lower()


def test_bulk_import_rejects_binary_nul_content(app, client):
    _activate_user(app, client, "bulk-binary@example.com")
    login(client, "bulk-binary@example.com", "member-password")

    response = client.post(
        "/proxies/import",
        data={"proxy_file": (BytesIO(b"proxy.example:9000\x00:user:secret"), "proxies.txt")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert "text" in response.get_json()["error"].lower()


def test_bulk_import_enforces_the_import_byte_limit_for_json(app, client):
    user_id = _activate_user(app, client, "bulk-json-limit@example.com")
    login(client, "bulk-json-limit@example.com", "member-password")
    app.config["MAX_PROXY_IMPORT_BYTES"] = 32

    response = client.post(
        "/proxies/import",
        json={"raw_proxies": "limit.example:9000:user:" + ("s" * 40)},
    )

    assert response.status_code == 400
    assert "limited" in response.get_json()["error"].lower()
    with app.app_context():
        count = (
            get_db().execute("SELECT COUNT(*) AS count FROM proxies WHERE user_id=?", (user_id,)).fetchone()["count"]
        )
    assert count == 0


def test_bulk_import_counts_json_envelope_bytes_toward_limit(app, client):
    user_id = _activate_user(app, client, "bulk-json-envelope@example.com")
    login(client, "bulk-json-envelope@example.com", "member-password")
    app.config["MAX_PROXY_IMPORT_BYTES"] = 20

    response = client.post("/proxies/import", json={"raw_proxies": "proxy.example:9000"})

    assert response.status_code == 400
    assert "limited" in response.get_json()["error"].lower()
    with app.app_context():
        count = (
            get_db().execute("SELECT COUNT(*) AS count FROM proxies WHERE user_id=?", (user_id,)).fetchone()["count"]
        )
    assert count == 0


def test_bulk_import_accepts_supported_csv_layouts(app, client):
    user_id = _activate_user(app, client, "bulk-csv@example.com")
    login(client, "bulk-csv@example.com", "member-password")

    headerless = client.post(
        "/proxies/import",
        data={
            "proxy_file": (
                BytesIO(b"raw-one.example:9000:user:secret-one\nraw-two.example:9001\n"),
                "raw-list.csv",
            )
        },
        content_type="multipart/form-data",
    )
    raw_column = client.post(
        "/proxies/import",
        data={
            "proxy_file": (
                BytesIO(b"raw_proxy\nraw-three.example:9002:user:secret-three\n"),
                "raw-column.csv",
            )
        },
        content_type="multipart/form-data",
    )
    structured = client.post(
        "/proxies/import",
        data={
            "proxy_file": (
                BytesIO(
                    b"protocol,host,port,username,password\n"
                    b"socks5,structured.example,1080,structured-user,structured-secret\n"
                ),
                "structured.csv",
            )
        },
        content_type="multipart/form-data",
    )

    assert headerless.status_code == 201
    assert headerless.get_json()["added"] == 2
    assert raw_column.status_code == 201
    assert raw_column.get_json()["added"] == 1
    assert structured.status_code == 201
    assert structured.get_json()["added"] == 1
    with app.app_context():
        rows = (
            get_db()
            .execute(
                "SELECT host,port,protocol_hint FROM proxies WHERE user_id=? ORDER BY id",
                (user_id,),
            )
            .fetchall()
        )
    assert [tuple(row) for row in rows] == [
        ("raw-one.example", 9000, "auto"),
        ("raw-two.example", 9001, "auto"),
        ("raw-three.example", 9002, "auto"),
        ("structured.example", 1080, "socks5"),
    ]


def test_bulk_import_accepts_utf8_bom_files(app, client):
    user_id = _activate_user(app, client, "bulk-bom@example.com")
    login(client, "bulk-bom@example.com", "member-password")

    response = client.post(
        "/proxies/import",
        data={
            "proxy_file": (
                BytesIO(b"\xef\xbb\xbfraw_proxy\nbom.example:9000:user:secret\n"),
                "bom.csv",
            )
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 201
    assert response.get_json()["added"] == 1
    assert response.get_json()["invalid"] == 0
    with app.app_context():
        row = get_db().execute("SELECT host,port FROM proxies WHERE user_id=?", (user_id,)).fetchone()
    assert tuple(row) == ("bom.example", 9000)


def test_bulk_import_rejects_unsupported_or_ambiguous_file_layouts(app, client):
    user_id = _activate_user(app, client, "bulk-file-validation@example.com")
    login(client, "bulk-file-validation@example.com", "member-password")

    unsupported = client.post(
        "/proxies/import",
        data={"proxy_file": (BytesIO(b"proxy.example:9000:user:secret"), "proxies.json")},
        content_type="multipart/form-data",
    )
    ambiguous_csv = client.post(
        "/proxies/import",
        data={"proxy_file": (BytesIO(b"proxy.example,9000,user,secret\n"), "proxies.csv")},
        content_type="multipart/form-data",
    )

    assert unsupported.status_code == 400
    assert ".txt or .csv" in unsupported.get_json()["error"].lower()
    assert ambiguous_csv.status_code == 400
    assert "headers" in ambiguous_csv.get_json()["error"].lower()
    with app.app_context():
        count = (
            get_db().execute("SELECT COUNT(*) AS count FROM proxies WHERE user_id=?", (user_id,)).fetchone()["count"]
        )
    assert count == 0


def test_bulk_import_rejects_malformed_json_shapes_without_server_error(app, client):
    _activate_user(app, client, "bulk-json-shape@example.com")
    login(client, "bulk-json-shape@example.com", "member-password")

    non_object = client.post("/proxies/import", json=["proxy.example:9000:user:secret"])
    non_string_values = client.post("/proxies/import", json={"raw_proxies": ["proxy.example:9000", 123]})

    assert non_object.status_code == 400
    assert "object" in non_object.get_json()["error"].lower()
    assert non_string_values.status_code == 400
    assert "string" in non_string_values.get_json()["error"].lower()


def test_bulk_import_rejects_malformed_csv_without_server_error(app, client):
    _activate_user(app, client, "bulk-csv-malformed@example.com")
    login(client, "bulk-csv-malformed@example.com", "member-password")

    response = client.post(
        "/proxies/import",
        data={"proxy_file": (BytesIO(b'raw_proxy\n"unterminated\n'), "broken.csv")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert "csv" in response.get_json()["error"].lower()
