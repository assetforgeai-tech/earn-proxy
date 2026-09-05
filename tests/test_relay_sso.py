from __future__ import annotations

from app.services.relay_sso import create_relay_sso_token, verify_relay_sso_token


def test_relay_sso_token_round_trips_and_rejects_tampering():
    token = create_relay_sso_token("shared-secret", now=1_000)

    assert verify_relay_sso_token(token, "shared-secret", now=1_001)
    assert not verify_relay_sso_token(token + "x", "shared-secret", now=1_001)
    assert not verify_relay_sso_token(token, "wrong-secret", now=1_001)


def test_relay_sso_token_expires_after_one_minute():
    token = create_relay_sso_token("shared-secret", now=1_000)

    assert verify_relay_sso_token(token, "shared-secret", now=1_060)
    assert not verify_relay_sso_token(token, "shared-secret", now=1_061)
