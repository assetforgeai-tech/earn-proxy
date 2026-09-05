from conftest import login_admin, register


def test_admin_integration_page_explains_connection_without_exposing_key(client):
    login_admin(client)
    response = client.get("/admin/integrations")
    page = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "API &amp; integrations" in page or "API & integrations" in page
    assert "/api/v1/proxies" in page
    assert "/api/v1/proxy-raw" in page
    assert "/api/v1/proxy-transfer" in page
    assert "Proxy raw" in page
    assert "Proxy transfer" in page
    assert "X-API-Key" in page
    assert "format=json" in page
    assert "EARN_PROXY_INTERNAL_API_KEY" in page
    assert "internal-test-key" not in page
    assert "data-copy-target" in page


def test_integration_page_is_not_available_to_anonymous_or_contributor_users(app, client):
    assert client.get("/admin/integrations").status_code == 403

    register(client, "integration-user@example.com", "member-password")
    client.post("/logout")
    assert client.get("/admin/integrations").status_code == 403


def test_admin_has_route_based_navigation_and_section_pages(client):
    login_admin(client)
    page = client.get("/admin").get_data(as_text=True)
    assert 'href="/admin/checker"' in page
    assert 'href="/admin/users"' in page
    assert 'href="/admin/payouts"' in page
    assert 'href="/admin/integrations"' in page
    assert 'href="#checker-policy"' not in page

    assert "Checker policy" in client.get("/admin/checker").get_data(as_text=True)
    assert "User approvals" in client.get("/admin/users").get_data(as_text=True)
    assert "Payout queue" in client.get("/admin/payouts").get_data(as_text=True)


def test_route_pages_offer_isolated_workspaces_and_a_short_overview(client):
    login_admin(client)
    overview = client.get("/admin").get_data(as_text=True)
    assert "Choose an area to manage" in overview
    assert 'id="checker-policy"' not in overview
    assert 'id="user-approvals"' not in overview
    assert 'id="payout-queue"' not in overview
    checker = client.get("/admin/checker").get_data(as_text=True)
    users = client.get("/admin/users").get_data(as_text=True)
    payouts = client.get("/admin/payouts").get_data(as_text=True)
    assert "Tune health checks without over-probing." in checker
    assert "Approve and manage contributors." in users
    assert "Review payout requests." in payouts
    assert 'id="user-approvals"' not in checker
    assert 'id="payout-queue"' not in checker
    assert 'id="checker-policy"' not in users
    assert 'id="payout-queue"' not in users
    assert 'id="checker-policy"' not in payouts
    assert 'id="user-approvals"' not in payouts


def test_admin_browser_forms_return_to_their_route_specific_workspace(client):
    login_admin(client)

    response = client.post(
        "/admin/settings",
        data={
            "health_interval_minutes": "60",
            "health_concurrency": "5",
            "health_per_host_concurrency": "2",
            "health_retry_first_minutes": "5",
            "health_retry_second_minutes": "15",
            "health_stale_minutes": "120",
            "api_include_allow": "1",
            "api_include_risk": "1",
            "ui": "1",
        },
    )
    assert response.status_code == 303
    assert response.headers["Location"].endswith("/admin/checker")


def test_integration_endpoint_uses_forwarded_https_host(client):
    client.post(
        "/login",
        base_url="http://earn.proxy.acacondos.com",
        data={"email": "admin@example.com", "password": "correct horse battery staple"},
    )
    response = client.get(
        "/admin/integrations",
        base_url="http://earn.proxy.acacondos.com",
        headers={
            "X-Forwarded-Proto": "https",
        },
    )
    page = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "https://earn.proxy.acacondos.com/api/v1/proxies" in page


def test_admin_workspace_titles_match_the_selected_route(client):
    login_admin(client)
    assert "Checker policy - Earn Proxy" in client.get("/admin/checker").get_data(as_text=True)
    assert "Users - Earn Proxy" in client.get("/admin/users").get_data(as_text=True)
    assert "Payouts - Earn Proxy" in client.get("/admin/payouts").get_data(as_text=True)


def test_admin_brand_link_does_not_route_through_contributor_dashboard(client):
    login_admin(client)
    page = client.get("/admin/integrations").get_data(as_text=True)
    assert '<a class="brand" href="/admin">Earn Proxy</a>' in page


def test_transfer_proxy_workspace_is_admin_only_and_uses_expiring_handoff(app, client):
    assert client.get("/admin/transfer-proxy").status_code == 403
    app.config["RELAY_SSO_SECRET"] = "test-relay-secret"
    app.config["RELAY_PUBLIC_URL"] = "https://transfer.proxy.acacondos.com"
    login_admin(client)
    response = client.get("/admin/transfer-proxy")
    page = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "Continue to Transfer Proxy" in page
    assert 'action="https://transfer.proxy.acacondos.com/sso"' in page
    assert 'name="token"' in page
    assert response.headers["Cache-Control"] == "no-store"
