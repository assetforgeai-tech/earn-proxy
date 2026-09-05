from __future__ import annotations

import os
import uuid

from playwright.sync_api import Page, sync_playwright

BASE_URL = os.environ.get("EARN_PROXY_SMOKE_URL", "http://127.0.0.1:8878").rstrip("/")
ADMIN_EMAIL = os.environ["EARN_PROXY_ADMIN_EMAIL"]
ADMIN_PASSWORD = os.environ["EARN_PROXY_ADMIN_PASSWORD"]

ADMIN_ROUTES = (
    ("Overview", "/admin"),
    ("Health checker", "/admin/checker"),
    ("Users", "/admin/users"),
    ("Payouts", "/admin/payouts"),
    ("Distribution API", "/admin/integrations"),
    ("API keys", "/admin/integrations/api-keys"),
    ("Transfer Proxy", "/admin/transfer-proxy"),
)
CONTRIBUTOR_ROUTES = (
    ("Overview", "/dashboard", "Your earning overview"),
    ("Proxy pool", "/dashboard/proxies", "Manage your proxy pool"),
    ("Earnings", "/dashboard/earnings", "Track your earnings"),
    ("Wallet & payouts", "/dashboard/wallet", "Wallet & payouts"),
)


def sign_in(page: Page, email: str, password: str, target: str) -> None:
    page.goto(f"{BASE_URL}/login", wait_until="networkidle")
    page.get_by_label("Email").fill(email)
    page.get_by_label("Password").fill(password)
    page.get_by_role("button", name="Sign in").click()
    page.wait_for_url(f"**{target}")
    page.wait_for_load_state("networkidle")


def create_approved_contributor(page: Page) -> tuple[str, str]:
    email = f"nav-audit-{uuid.uuid4().hex}@example.com"
    password = "local-navigation-audit-password"
    page.goto(f"{BASE_URL}/register", wait_until="networkidle")
    page.get_by_label("Email").fill(email)
    page.get_by_label("Password").fill(password)
    page.get_by_role("button", name="Register").click()
    page.wait_for_url(f"{BASE_URL}/login")

    sign_in(page, ADMIN_EMAIL, ADMIN_PASSWORD, "/admin")
    page.goto(f"{BASE_URL}/admin/users", wait_until="networkidle")
    row = page.locator("tr").filter(has_text=email)
    row.get_by_role("button", name="Approve").click()
    page.wait_for_load_state("networkidle")
    page.get_by_role("button", name="Sign out").click()
    page.wait_for_url(f"{BASE_URL}/login")
    return email, password


def assert_no_overflow(page: Page) -> None:
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")


def audit_admin(page: Page, width: int, height: int) -> None:
    page.set_viewport_size({"width": width, "height": height})
    for label, path in ADMIN_ROUTES:
        page.goto(f"{BASE_URL}{path}", wait_until="networkidle")
        if width <= 1099:
            page.get_by_role("button", name="Open navigation").click()
        assert page.get_by_role("link", name=label, exact=True).get_attribute("aria-current") == "page"
        assert page.locator(".section-nav").count() == 0
        assert page.locator("[data-page-search]").count() == 0
        assert_no_overflow(page)

        if width <= 1099:
            assert page.locator("#app-sidebar").get_attribute("aria-hidden") == "false"
            page.keyboard.press("Escape")
            assert page.locator("#app-sidebar").get_attribute("aria-hidden") == "true"

    if width <= 1099:
        toggle = page.get_by_role("button", name="Open navigation")
        assert toggle.is_visible()
        toggle.click()
        assert page.locator("#app-sidebar").get_attribute("aria-hidden") == "false"
        page.wait_for_timeout(50)
        assert (
            page.locator("#app-sidebar")
            .locator('[aria-current="page"]')
            .evaluate("el => el === document.activeElement")
        )
        page.keyboard.press("Escape")
        page.wait_for_timeout(50)
        assert page.locator("#mobile-menu-toggle").evaluate("el => el === document.activeElement")


def audit_contributor(page: Page, width: int, height: int) -> None:
    page.set_viewport_size({"width": width, "height": height})
    for label, path, heading in CONTRIBUTOR_ROUTES:
        page.goto(f"{BASE_URL}{path}", wait_until="networkidle")
        if width <= 1099:
            page.get_by_role("button", name="Open navigation").click()
        assert page.get_by_role("link", name=label, exact=True).get_attribute("aria-current") == "page"
        assert page.get_by_role("heading", name=heading).is_visible()
        assert page.locator("#dashboard-nav").count() == 0
        assert_no_overflow(page)
        if width <= 1099:
            page.keyboard.press("Escape")


with sync_playwright() as playwright:
    browser = playwright.chromium.launch(headless=True)
    errors: list[str] = []
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.on("console", lambda message: errors.append(message.text) if message.type == "error" else None)
    page.on("pageerror", lambda error: errors.append(str(error)))

    sign_in(page, ADMIN_EMAIL, ADMIN_PASSWORD, "/admin")
    for width, height in ((1440, 900), (1024, 768), (375, 812)):
        audit_admin(page, width, height)

    page.set_viewport_size({"width": 1440, "height": 900})
    page.goto(f"{BASE_URL}/admin", wait_until="networkidle")
    page.get_by_role("button", name="Sign out").click()
    page.wait_for_url(f"{BASE_URL}/login")

    # Prefer supplied smoke credentials, otherwise create disposable local data.
    contributor_email = os.environ.get("EARN_PROXY_SMOKE_CONTRIBUTOR_EMAIL")
    contributor_password = os.environ.get("EARN_PROXY_SMOKE_CONTRIBUTOR_PASSWORD")
    if not contributor_email or not contributor_password:
        contributor_email, contributor_password = create_approved_contributor(page)
    sign_in(page, contributor_email, contributor_password, "/dashboard")
    for width, height in ((1440, 900), (1024, 768), (375, 812)):
        audit_contributor(page, width, height)

    assert errors == [], errors
    browser.close()

print("navigation UX audit passed")
