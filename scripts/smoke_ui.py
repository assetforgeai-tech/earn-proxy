from __future__ import annotations

import os

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
    page.wait_for_load_state("networkidle")


with sync_playwright() as playwright:
    browser = playwright.chromium.launch(headless=True)

    desktop = browser.new_page(viewport={"width": 1440, "height": 1000})
    sign_in(desktop)
    assert desktop.get_by_label("Health interval (minutes)").input_value() == "60"
    assert desktop.get_by_label("Health concurrency (max 20)").input_value() == "5"
    assert desktop.get_by_label("Per-host concurrency (max 3)").input_value() == "2"
    assert desktop.get_by_label("First retry (minutes)").input_value() == "5"
    assert desktop.get_by_label("Second retry (minutes)").input_value() == "15"
    assert desktop.get_by_label("API freshness limit (minutes)").input_value() == "120"
    assert desktop.get_by_label("Include Allow").is_checked()
    assert desktop.get_by_label("Include Risk").is_checked()
    desktop.get_by_label("Health concurrency (max 20)").fill("3")
    desktop.get_by_role("button", name="Save policy").click()
    desktop.wait_for_load_state("networkidle")
    assert desktop.get_by_text("Checker policy saved.").is_visible()
    assert desktop.get_by_label("Health concurrency (max 20)").input_value() == "3"
    assert desktop.evaluate("document.documentElement.scrollWidth <= window.innerWidth")

    mobile = browser.new_page(viewport={"width": 375, "height": 812})
    sign_in(mobile)
    assert mobile.get_by_role("heading", name="Operate the pool without over-probing it.").is_visible()
    assert mobile.get_by_role("button", name="Save policy").is_visible()
    assert mobile.evaluate("document.documentElement.scrollWidth <= window.innerWidth")

    browser.close()

print("desktop and mobile smoke passed")
