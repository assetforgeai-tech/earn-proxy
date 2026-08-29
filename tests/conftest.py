from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from app import create_app
from app.db import get_db


@pytest.fixture()
def app(tmp_path):
    application = create_app(
        {
            "TESTING": True,
            "DATABASE": str(tmp_path / "earn-proxy.db"),
            "SECRET_KEY": "test-session-secret",
            "FERNET_KEY": Fernet.generate_key().decode("ascii"),
            "INTERNAL_API_KEY": "internal-test-key",
            "ADMIN_EMAIL": "admin@example.com",
            "ADMIN_PASSWORD": "correct horse battery staple",
            "CSRF_ENABLED": False,
            "SESSION_COOKIE_SECURE": False,
        }
    )
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def db(app):
    with app.app_context():
        yield get_db()


def register(client, email="member@example.com", password="member-password"):
    return client.post("/register", data={"email": email, "password": password})


def login(client, email="member@example.com", password="member-password"):
    return client.post("/login", data={"email": email, "password": password})


def login_admin(client):
    return client.post(
        "/login",
        data={"email": "admin@example.com", "password": "correct horse battery staple"},
    )
