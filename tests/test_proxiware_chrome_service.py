from __future__ import annotations

from pathlib import Path

import pytest

from app.proxiware_chrome_service import ChromeConfig, _chrome_child_environment, build_chrome_command


def test_chrome_command_binds_cdp_to_loopback_and_uses_isolated_profile(tmp_path):
    binary = tmp_path / "chrome"
    binary.write_text("")
    profile = tmp_path / "profile"

    command = build_chrome_command(
        ChromeConfig(
            enabled=True,
            binary=binary,
            cdp_url="http://127.0.0.1:9222",
            profile_dir=profile,
        )
    )

    assert command[0] == str(binary.resolve())
    assert "--remote-debugging-address=127.0.0.1" in command
    assert "--remote-debugging-port=9222" in command
    assert f"--user-data-dir={profile.resolve()}" in command
    assert "--no-sandbox" not in command


def test_chrome_command_rejects_non_loopback_cdp(tmp_path):
    binary = tmp_path / "chrome"
    binary.write_text("")

    with pytest.raises(ValueError, match="loopback"):
        build_chrome_command(
            ChromeConfig(
                enabled=True,
                binary=binary,
                cdp_url="http://0.0.0.0:9222",
                profile_dir=tmp_path / "profile",
            )
        )


def test_chrome_command_requires_an_absolute_existing_binary(tmp_path):
    with pytest.raises(ValueError, match="absolute"):
        build_chrome_command(
            ChromeConfig(
                enabled=True,
                binary=Path("chrome"),
                cdp_url="http://127.0.0.1:9222",
                profile_dir=tmp_path / "profile",
            )
        )


def test_disabled_chrome_does_not_build_a_process_command(tmp_path):
    assert (
        build_chrome_command(
            ChromeConfig(
                enabled=False,
                binary=tmp_path / "missing",
                cdp_url="http://127.0.0.1:9222",
                profile_dir=tmp_path / "profile",
            )
        )
        == []
    )


def test_chrome_command_rejects_profile_outside_isolated_root(tmp_path):
    binary = tmp_path / "chrome"
    binary.write_text("")

    with pytest.raises(ValueError, match="isolated root"):
        build_chrome_command(
            ChromeConfig(
                enabled=True,
                binary=binary,
                cdp_url="http://127.0.0.1:9222",
                profile_dir=tmp_path / "not-isolated",
                profile_root=tmp_path / "isolated-root",
            )
        )


def test_chrome_command_resolves_profile_before_isolation_check(tmp_path):
    binary = tmp_path / "chrome"
    binary.write_text("")
    root = tmp_path / "isolated-root"

    with pytest.raises(ValueError, match="isolated root"):
        build_chrome_command(
            ChromeConfig(
                enabled=True,
                binary=binary,
                cdp_url="http://127.0.0.1:9222",
                profile_dir=root / "nested" / ".." / ".." / "outside",
                profile_root=root,
            )
        )


def test_chrome_environment_defaults_to_ephemeral_runtime_profile(monkeypatch):
    from app.proxiware_chrome_service import _config_from_env

    for name in (
        "EARN_PROXY_PROXIWARE_CHROME_PROFILE_ROOT",
        "EARN_PROXY_PROXIWARE_CHROME_PROFILE_DIR",
    ):
        monkeypatch.delenv(name, raising=False)

    config = _config_from_env()

    assert config.profile_root == Path("/run/earn-proxy-browser")
    assert config.profile_dir == Path("/run/earn-proxy-browser/profile")


def test_chrome_child_environment_does_not_forward_application_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("EARN_PROXY_FERNET_KEY", "secret")
    monkeypatch.setenv("EARN_PROXY_INTERNAL_API_KEY", "secret")
    config = ChromeConfig(
        enabled=True,
        binary=tmp_path / "chrome",
        cdp_url="http://127.0.0.1:9222",
        profile_dir=tmp_path / "profile",
    )

    child_env = _chrome_child_environment(config)

    assert "EARN_PROXY_FERNET_KEY" not in child_env
    assert "EARN_PROXY_INTERNAL_API_KEY" not in child_env
    assert child_env["HOME"] == str(config.profile_dir.parent.resolve())
