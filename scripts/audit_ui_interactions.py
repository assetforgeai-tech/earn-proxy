from __future__ import annotations

import os
import uuid

from playwright.sync_api import sync_playwright

BASE_URL = os.environ.get("EARN_PROXY_SMOKE_URL", "http://127.0.0.1:8878")
ADMIN_EMAIL = os.environ["EARN_PROXY_ADMIN_EMAIL"]
ADMIN_PASSWORD = os.environ["EARN_PROXY_ADMIN_PASSWORD"]


def sign_in(page) -> None:
    page.goto(f"{BASE_URL}/login")
    page.get_by_label("Email").fill(ADMIN_EMAIL)
    page.get_by_label("Password").fill(ADMIN_PASSWORD)
    page.get_by_role("button", name="Sign in").click()
    page.wait_for_url(f"{BASE_URL}/admin")


with sync_playwright() as playwright:
    browser = playwright.chromium.launch(headless=True)

    page = browser.new_page(viewport={"width": 1440, "height": 1000})
    console_errors: list[str] = []
    page.on("console", lambda message: console_errors.append(message.text) if message.type == "error" else None)
    page.on("pageerror", lambda error: console_errors.append(str(error)))

    contributor_email = f"ui-dialog-{uuid.uuid4().hex}@example.com"
    contributor_password = "ui-dialog-password"
    page.goto(f"{BASE_URL}/register")
    page.get_by_label("Email").fill(contributor_email)
    page.get_by_label("Password").fill(contributor_password)
    page.get_by_role("button", name="Register").click()
    page.wait_for_url(f"{BASE_URL}/login")

    page.goto(f"{BASE_URL}/login")
    page.get_by_label("Email").fill("unknown@example.com")
    page.get_by_label("Password").fill("wrong-password")
    page.get_by_role("button", name="Sign in").click()
    page.wait_for_url(f"{BASE_URL}/login?error_field=password")
    assert page.locator('[role="alert"]').is_visible()
    assert page.locator("#password").get_attribute("aria-invalid") == "true"
    assert page.evaluate("document.activeElement.id") == "password"

    sign_in(page)
    block_form = page.locator("form[data-confirm-title='Block user?']").first
    block_form.locator("button[type='submit']").click()
    dialog = page.locator("#confirm-dialog")
    assert dialog.is_visible()
    assert dialog.get_by_role("heading", name="Block user?").is_visible()
    dialog.get_by_role("button", name="Cancel").click()
    assert not dialog.is_visible()

    user_row = page.locator("tr").filter(has_text=contributor_email)
    user_row.get_by_role("button", name="Approve").click()
    page.wait_for_load_state("networkidle")
    page.get_by_role("button", name="Sign out").click()
    page.wait_for_url(f"{BASE_URL}/login")
    page.get_by_label("Email").fill(contributor_email)
    page.get_by_label("Password").fill(contributor_password)
    page.get_by_role("button", name="Sign in").click()
    page.wait_for_url(f"{BASE_URL}/dashboard")

    endpoint = f"audit-{uuid.uuid4().hex}.example:9000"
    page.get_by_label("Raw proxy").fill(f"{endpoint}:masked-user:masked-pass")
    page.get_by_role("button", name="Add securely").click()
    page.wait_for_load_state("networkidle")
    assert page.get_by_text(endpoint).is_visible()
    assert "masked-user" not in page.locator("body").inner_text()
    assert "masked-pass" not in page.locator("body").inner_text()
    page.get_by_role("button", name="Remove").click()
    assert dialog.get_by_role("heading", name="Remove proxy?").is_visible()
    dialog.get_by_role("button", name="Cancel").click()
    assert page.get_by_text(endpoint).is_visible()

    mobile = browser.new_page(viewport={"width": 375, "height": 812})
    mobile.goto(f"{BASE_URL}/login")
    mobile.get_by_label("Email").fill(contributor_email)
    mobile.get_by_label("Password").fill(contributor_password)
    mobile.get_by_role("button", name="Sign in").click()
    mobile.wait_for_url(f"{BASE_URL}/dashboard")
    mobile.wait_for_load_state("networkidle")
    assert mobile.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    assert mobile.get_by_role("navigation", name="Dashboard sections").is_visible()
    assert mobile.get_by_role("button", name="Add securely").is_visible()
    endpoint_cell = mobile.locator('tbody th[data-label="Endpoint"]').first
    assert endpoint_cell.evaluate("element => element.scrollWidth <= element.clientWidth")
    mobile.close()

    page.get_by_role("button", name="Remove").click()
    dialog.get_by_role("button", name="Remove proxy").click()
    page.wait_for_load_state("networkidle")
    assert not page.get_by_text(endpoint).is_visible()

    page.get_by_role("button", name="Sign out").click()
    page.wait_for_url(f"{BASE_URL}/login")
    sign_in(page)
    settings_form = page.locator('form[action="/admin/settings"]')
    settings_form.evaluate("form => form.addEventListener('submit', event => event.preventDefault(), {once: true})")
    save_button = settings_form.locator('button[type="submit"]')
    save_button.click()
    assert save_button.is_disabled()
    assert save_button.inner_text() == "Saving policy..."
    assert settings_form.get_attribute("aria-busy") == "true"

    assert console_errors == []
    browser.close()

print("interaction and responsive audit passed")
