from __future__ import annotations

import os
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]


def test_native_web_unit_does_not_depend_on_a_console_script_shebang():
    unit = (ROOT / "deploy" / "earn-proxy-web.service").read_text()

    assert "ExecStart=/opt/earn-proxy/.venv/bin/python -m gunicorn " in unit
    assert "ExecStart=/opt/earn-proxy/.venv/bin/gunicorn " not in unit


def test_release_installer_builds_the_venv_at_its_final_absolute_path():
    installer = (ROOT / "deploy" / "release.sh").read_text()

    assert 'release_dir="/opt/earn-proxy-${revision}"' in installer
    assert 'python_bin="${EARN_PROXY_PYTHON:-/opt/python3.11/bin/python3.11}"' in installer
    assert '"$python_bin" -m venv "$release_dir/.venv"' in installer
    assert 'python3 -m venv "$release_dir/.venv"' not in installer
    assert '"$release_dir/.venv/bin/python" -m pip install' in installer
    assert '"$release_dir/.venv/bin/python" -m pip check' in installer
    assert 'chown -R root:root "$release_dir"' in installer
    assert 'chmod -R go-w "$release_dir"' in installer
    assert "cp -a /opt/earn-proxy/.venv" not in installer
    assert "sed -i" not in installer


def test_release_installer_preflights_before_switching_and_rolls_back_on_failure():
    installer = (ROOT / "deploy" / "release.sh").read_text()

    preflight = installer.index("systemd-run --quiet --wait --pipe --collect")
    switch = installer.index('ln -s "$release_dir" "$next_link"')
    assert preflight < switch
    assert "source /etc/earn-proxy.env" not in installer
    assert "--uid=earnproxy" in installer
    assert "--property=EnvironmentFile=/etc/earn-proxy.env" in installer
    assert 'previous_release="$(readlink -f /opt/earn-proxy || true)"' in installer
    assert 'ln -s "$previous_release" "$next_link"' in installer
    assert 'systemctl restart "${services[@]}"' in installer


def test_release_installer_preserves_database_config_and_previous_units():
    installer = (ROOT / "deploy" / "release.sh").read_text()

    assert 'backup_dir="/var/backups/earn-proxy/${backup_stamp}-${revision}"' in installer
    assert 'database_path="$(awk -F= ' in installer
    assert 'database_path="${database_path:-/var/lib/earn-proxy/earn-proxy.db}"' in installer
    assert 'gsub(/^\\"|\\"$/' not in installer
    assert "source.backup(destination)" in installer
    assert 'cp -a /etc/earn-proxy.env "$backup_dir/earn-proxy.env"' in installer
    assert 'cp -a /etc/systemd/system/earn-proxy-*.service "$backup_dir/systemd/"' in installer
    assert 'install -m 0644 "$backup_dir"/systemd/earn-proxy-*.service /etc/systemd/system/' in installer

    backup = installer.index("source.backup(destination)")
    preflight = installer.index("systemd-run --quiet --wait --pipe --collect")
    assert backup < preflight


def test_release_installer_removes_an_unactivated_release_after_failure():
    installer = (ROOT / "deploy" / "release.sh").read_text()

    assert "activated=0" in installer
    assert 'if [[ "$activated" -eq 0 && -d "$release_dir" ]]; then' in installer
    assert 'rm -rf -- "$release_dir"' in installer
    assert "activated=1" in installer
    health_check = installer.index('if ! systemctl restart "${services[@]}"')
    activated = installer.index("activated=1", health_check)
    assert health_check < activated


def test_release_installer_manages_proxiware_workers_and_restores_previous_service_set():
    installer = (ROOT / "deploy" / "release.sh").read_text()

    for service in (
        "earn-proxy-proxiware",
        "earn-proxy-proxiware-qualification",
        "earn-proxy-proxiware-swap",
        "earn-proxy-proxiware-chrome",
        "earn-proxy-proxiware-browser",
    ):
        assert service in installer
    assert 'systemctl enable "${services[@]}"' in installer
    assert 'systemctl is-active --quiet "${services[@]}"' in installer
    assert 'previous_services+=("${unit_name%.service}")' in installer
    assert 'systemctl stop "${services[@]}" || true' in installer
    assert 'systemctl disable "${services[@]}" || true' in installer
    assert 'rm -f -- "/etc/systemd/system/$unit_name"' in installer
    assert 'systemctl enable "${previous_services[@]}"' in installer
    assert 'systemctl restart "${previous_services[@]}"' in installer


def test_release_installer_uses_descriptor_safe_runtime_permission_helper():
    installer = (ROOT / "deploy" / "release.sh").read_text()

    assert "secure_runtime_permissions.py" in installer
    assert '"$release_dir/deploy/secure_runtime_permissions.py"' in installer
    assert '"$source_dir/deploy/secure_runtime_permissions.py"' not in installer
    assert 'database_path" != "/var/lib/earn-proxy/earn-proxy.db"' in installer
    assert "os.O_NOFOLLOW" in installer
    assert "file:/proc/self/fd/{source_fd}?mode=ro" in installer
    assert 'chown earnproxy:earnproxy "$database_path"' not in installer
    assert 'chmod 0660 "$database_path"' not in installer
    assert 'chown earnproxy:earnproxy "$sqlite_sidecar"' not in installer
    assert 'chmod 0660 "$sqlite_sidecar"' not in installer


def test_runtime_permission_helper_rejects_symlink_targets_and_accepts_regular_files(tmp_path):
    if os.name != "posix":
        pytest.skip("descriptor ownership APIs are POSIX-only")

    from deploy.secure_runtime_permissions import secure_runtime_permissions

    database = tmp_path / "earn-proxy.db"
    database.write_bytes(b"database")
    secure_runtime_permissions(database, uid=os.getuid(), gid=os.getgid(), mode=0o660)

    assert database.stat().st_mode & 0o777 == 0o660

    target = tmp_path / "root-owned"
    target.write_bytes(b"do not touch")
    target.chmod(0o640)
    database.unlink()
    main_link = tmp_path / "earn-proxy.db"
    main_link.symlink_to(target)

    with pytest.raises((OSError, RuntimeError, ValueError)):
        secure_runtime_permissions(main_link, uid=os.getuid(), gid=os.getgid(), mode=0o660)

    link = tmp_path / "earn-proxy.db-wal"
    link.symlink_to(target)

    with pytest.raises((OSError, RuntimeError, ValueError)):
        secure_runtime_permissions(link, uid=os.getuid(), gid=os.getgid(), mode=0o660)
    assert target.read_bytes() == b"do not touch"
    assert target.stat().st_mode & 0o777 == 0o640


def test_browser_worker_is_isolated_and_mutation_is_disabled_by_default():
    unit = (ROOT / "deploy" / "earn-proxy-proxiware-browser.service").read_text()
    chrome_unit = (ROOT / "deploy" / "earn-proxy-proxiware-chrome.service").read_text()
    env = (ROOT / ".env.example").read_text()

    assert "User=earnproxy-browser" in unit
    assert "NoNewPrivileges=true" in unit
    assert "ProtectSystem=strict" in unit
    assert "PrivateDevices=true" in unit
    assert "earn-proxy-proxiware-chrome.service" in unit
    assert "User=earnproxy-chrome" in chrome_unit
    assert "Group=earnproxy-chrome" in chrome_unit
    assert "EnvironmentFile=/etc/earn-proxy.env" not in chrome_unit
    assert "EnvironmentFile=-/etc/earn-proxy-browser.env" in chrome_unit
    assert "Environment=EARN_PROXY_PROXIWARE_CHROME_ENABLED=0" in chrome_unit
    assert "Environment=EARN_PROXY_PROXIWARE_CDP_URL=http://127.0.0.1:9222" in chrome_unit
    assert chrome_unit.index("Environment=EARN_PROXY_PROXIWARE_CHROME_ENABLED=0") < chrome_unit.index(
        "EnvironmentFile=-/etc/earn-proxy-browser.env"
    )
    assert "NoNewPrivileges=true" in chrome_unit
    assert "ProtectSystem=strict" in chrome_unit
    assert "PrivateDevices=true" in chrome_unit
    assert "app.proxiware_chrome_service" in chrome_unit
    assert "EARN_PROXY_PROXIWARE_CDP_URL=http://127.0.0.1:9222" in env
    assert "EARN_PROXY_PROXIWARE_CHROME_BINARY=/usr/bin/google-chrome" in env
    assert "EARN_PROXY_PROXIWARE_CHROME_PROFILE_DIR=/run/earn-proxy-browser/profile" in env
    assert "RuntimeDirectory=earn-proxy-browser" in chrome_unit
    assert "UMask=0077" in chrome_unit
    assert "RuntimeDirectory=earn-proxy-browser" in chrome_unit
    assert "ReadWritePaths=/run/earn-proxy-browser" in chrome_unit
    assert "EARN_PROXY_PROXIWARE_BROWSER_ALLOW_MUTATION=0" in env
    assert "EARN_PROXY_PROXIWARE_SWAP_MUTATION_TIMEOUT_SECONDS=60" in env


def test_cdp_acl_is_required_before_chrome_and_stops_with_it():
    acl_unit = (ROOT / "deploy" / "earn-proxy-proxiware-cdp-acl.service").read_text()
    chrome_unit = (ROOT / "deploy" / "earn-proxy-proxiware-chrome.service").read_text()
    browser_unit = (ROOT / "deploy" / "earn-proxy-proxiware-browser.service").read_text()
    swap_unit = (ROOT / "deploy" / "earn-proxy-proxiware-swap.service").read_text()
    installer = (ROOT / "deploy" / "release.sh").read_text()

    assert "earn-proxy-proxiware-cdp-acl" in installer
    assert "Requires=earn-proxy-proxiware-cdp-acl.service" in chrome_unit
    assert any(
        line.startswith("After=") and "earn-proxy-proxiware-cdp-acl.service" in line
        for line in chrome_unit.splitlines()
    )
    assert "BindsTo=earn-proxy-proxiware-cdp-acl.service" in chrome_unit
    assert "Before=earn-proxy-proxiware-chrome.service" in acl_unit
    assert "PartOf=earn-proxy-proxiware-chrome.service" in acl_unit
    assert "Type=oneshot" in acl_unit
    assert "RemainAfterExit=yes" in acl_unit
    assert "--user earnproxy-browser" in acl_unit
    assert "Requires=earn-proxy-proxiware-chrome.service" in browser_unit
    assert "User=earnproxy-browser" in swap_unit
    assert "Requires=earn-proxy-proxiware-chrome.service" in swap_unit


def test_cdp_acl_only_allows_the_browser_uid():
    from app.proxiware_cdp_acl import nft_ruleset

    rendered = nft_ruleset(table="earn_proxy_cdp", port=9222, uid=123)

    assert "meta skuid 123 accept" in rendered
    assert "127.0.0.1" in rendered
    assert "9222" in rendered
    assert "priority -200" in rendered
    assert "reject" in rendered


def test_release_preflight_rejects_a_venv_created_for_another_release(tmp_path, monkeypatch):
    from deploy.release_preflight import validate_runtime_prefix

    release_dir = tmp_path / "earn-proxy-deadbee"
    monkeypatch.setattr("sys.prefix", str(tmp_path / "earn-proxy-old" / ".venv"))

    errors = validate_runtime_prefix(release_dir)

    assert errors == [f"virtualenv prefix is not {release_dir / '.venv'}"]


def test_release_preflight_requires_browser_runtime_dependency():
    preflight = (ROOT / "deploy" / "release_preflight.py").read_text()

    assert '"playwright"' in preflight


def test_release_preflight_rejects_browser_without_isolated_chrome():
    from deploy.release_preflight import validate_browser_runtime

    errors = validate_browser_runtime(
        {
            "EARN_PROXY_PROXIWARE_BROWSER_ENABLED": "1",
            "EARN_PROXY_PROXIWARE_CHROME_ENABLED": "0",
        }
    )

    assert errors == ["enabled Proxiware browser requires isolated Chrome"]


def test_release_installer_does_not_persist_browser_profile():
    installer = (ROOT / "deploy" / "release.sh").read_text()

    assert "--home-dir /nonexistent --no-create-home" in installer
    assert "install -d -o earnproxy-browser -g earnproxy -m 0750 /var/lib/earn-proxy-browser" not in installer
    assert "useradd --system --gid earnproxy-chrome" in installer


def test_release_installer_grants_browser_observer_group_access_to_runtime_database():
    installer = (ROOT / "deploy" / "release.sh").read_text()
    unit = (ROOT / "deploy" / "earn-proxy-proxiware-browser.service").read_text()

    assert "install -d -o earnproxy -g earnproxy -m 0770 /var/lib/earn-proxy" in installer
    assert "secure_runtime_permissions.py" in installer
    assert "--user earnproxy --group earnproxy --mode 0660" in installer
    assert "UMask=0007" in unit


def test_database_writers_preserve_group_write_access_for_sqlite_sidecars():
    units = [
        path
        for path in (ROOT / "deploy").glob("earn-proxy-*.service")
        if "ReadWritePaths=/var/lib/earn-proxy" in path.read_text()
    ]

    assert units
    assert all("UMask=0007" in path.read_text() for path in units)


def test_browser_observer_loads_its_required_worker_environment():
    unit = (ROOT / "deploy" / "earn-proxy-proxiware-browser.service").read_text()

    assert "EnvironmentFile=/etc/earn-proxy-proxiware-worker.env" in unit


def test_proxiware_workers_do_not_load_web_or_chrome_secrets():
    browser_unit = (ROOT / "deploy" / "earn-proxy-proxiware-browser.service").read_text()
    swap_unit = (ROOT / "deploy" / "earn-proxy-proxiware-swap.service").read_text()
    chrome_unit = (ROOT / "deploy" / "earn-proxy-proxiware-chrome.service").read_text()
    acl_unit = (ROOT / "deploy" / "earn-proxy-proxiware-cdp-acl.service").read_text()

    for unit in (browser_unit, swap_unit):
        assert "EnvironmentFile=/etc/earn-proxy.env" not in unit
        assert "EnvironmentFile=-/etc/earn-proxy-browser.env" not in unit
        assert "EnvironmentFile=/etc/earn-proxy-proxiware-worker.env" in unit
        assert "EnvironmentFile=/etc/earn-proxy-proxiware-worker-key.env" in unit
        assert "Environment=EARN_PROXY_RUNTIME_PROFILE=proxiware_worker" in unit
    qualification_unit = (ROOT / "deploy" / "earn-proxy-proxiware-qualification.service").read_text()
    assert "EnvironmentFile=/etc/earn-proxy.env" not in qualification_unit
    assert "EnvironmentFile=/etc/earn-proxy-proxiware-worker.env" in qualification_unit
    assert "EnvironmentFile=/etc/earn-proxy-proxiware-worker-key.env" in qualification_unit
    assert "Environment=EARN_PROXY_RUNTIME_PROFILE=proxiware_worker" in qualification_unit
    for unit in (chrome_unit, acl_unit):
        assert "EnvironmentFile=/etc/earn-proxy.env" not in unit
        assert "EnvironmentFile=/etc/earn-proxy-proxiware-worker.env" not in unit
        assert "EnvironmentFile=-/etc/earn-proxy-browser.env" in unit


def test_worker_services_use_worker_app_factory():
    browser_service = (ROOT / "app" / "proxiware_browser_service.py").read_text()
    swap_service = (ROOT / "app" / "proxiware_swap_service.py").read_text()
    qualification_service = (ROOT / "app" / "services" / "proxiware_qualification_service.py").read_text()

    assert "create_worker_app" in browser_service
    assert "create_worker_app" in swap_service
    assert "create_worker_app" in qualification_service


def test_release_backs_up_and_requires_worker_environment():
    installer = (ROOT / "deploy" / "release.sh").read_text()

    assert 'worker_env="/etc/earn-proxy-proxiware-worker.env"' in installer
    assert "render_worker_env()" in installer
    assert "EARN_PROXY_RUNTIME_PROFILE=proxiware_worker" in installer
    assert "EARN_PROXY_PROXIWARE_WORKER_FERNET_KEY" in installer
    worker_env_start = installer.index("render_worker_env()")
    worker_keys_start = installer.index("EARN_PROXY_DATABASE", worker_env_start)
    worker_keys = installer[worker_keys_start : installer.index("EOF", worker_keys_start)]
    assert "EARN_PROXY_FERNET_KEY" not in worker_keys
    assert "EARN_PROXY_PROXIWARE_SWAP_MUTATION_TIMEOUT_SECONDS" in worker_keys
    assert 'cp -a "$worker_env" "$backup_dir/earn-proxy-proxiware-worker.env"' in installer
    assert 'install -o root -g root -m 0600 "$worker_env_tmp" "$worker_env"' in installer
    assert 'install -o root -g root -m 0600 "$backup_dir/earn-proxy-proxiware-worker.env" "$worker_env"' in installer


def test_release_generates_and_rolls_back_a_dedicated_worker_key_file():
    installer = (ROOT / "deploy" / "release.sh").read_text()

    assert 'worker_key_env="/etc/earn-proxy-proxiware-worker-key.env"' in installer
    assert "EARN_PROXY_PROXIWARE_WORKER_FERNET_KEY=" in installer
    assert "urlsafe_b64encode(os.urandom(32))" in installer
    assert 'cp -a "$worker_key_env" "$backup_dir/earn-proxy-proxiware-worker-key.env"' in installer
    assert 'install -o root -g root -m 0600 "$worker_key_env_tmp" "$worker_key_env"' in installer
    assert (
        'install -o root -g root -m 0600 "$backup_dir/earn-proxy-proxiware-worker-key.env" "$worker_key_env"'
        in installer
    )
    assert "EnvironmentFile=/etc/earn-proxy-proxiware-worker-key.env" in installer


def test_every_application_service_receives_the_dedicated_provider_key():
    application_units = [
        path
        for path in (ROOT / "deploy").glob("earn-proxy-*.service")
        if (
            "ExecStart=/opt/earn-proxy/.venv/bin/python -m app." in path.read_text()
            and "app.proxiware_cdp_acl" not in path.read_text()
            and "app.proxiware_chrome_service" not in path.read_text()
        )
        or '"app:create_app()"' in path.read_text()
    ]

    assert application_units
    assert all(
        "EnvironmentFile=/etc/earn-proxy-proxiware-worker-key.env" in path.read_text() for path in application_units
    )


def test_release_backup_listing_is_group_visible_but_backup_files_stay_private():
    installer = (ROOT / "deploy" / "release.sh").read_text()

    assert "umask 0077" in installer
    assert installer.index('chmod -R go-w "$release_dir"') < installer.index("umask 0077")
    assert "install -d -o root -g earnproxy -m 0750 /var/backups/earn-proxy" in installer
    assert 'install -d -o root -g earnproxy -m 0750 "$backup_dir"' in installer
    assert 'install -o root -g root -m 0600 /dev/null "$backup_dir/earn-proxy.db"' in installer
    assert 'chmod 0600 "$backup_dir/earn-proxy.db" "$backup_dir/earn-proxy.env"' in installer


def test_release_preflight_loads_optional_browser_environment():
    installer = (ROOT / "deploy" / "release.sh").read_text()

    assert "EnvironmentFile=-/etc/earn-proxy-browser.env" in installer


def test_release_preflight_validates_enabled_chrome_runtime(tmp_path, monkeypatch):
    from deploy.release_preflight import validate_browser_runtime

    binary = tmp_path / "chrome"
    binary.write_text("")
    monkeypatch.setattr("deploy.release_preflight.os.access", lambda _path, _mode: True)
    env = {
        "EARN_PROXY_PROXIWARE_BROWSER_ENABLED": "1",
        "EARN_PROXY_PROXIWARE_CHROME_ENABLED": "1",
        "EARN_PROXY_PROXIWARE_CHROME_BINARY": str(binary),
        "EARN_PROXY_PROXIWARE_CDP_URL": "http://127.0.0.1:9222",
        "EARN_PROXY_PROXIWARE_CHROME_PROFILE_ROOT": "/run/earn-proxy-browser",
        "EARN_PROXY_PROXIWARE_CHROME_PROFILE_DIR": "/run/earn-proxy-browser/profile",
    }

    assert validate_browser_runtime(env) == []


def test_release_preflight_rejects_public_cdp_and_persistent_profile(tmp_path, monkeypatch):
    from deploy.release_preflight import validate_browser_runtime

    binary = tmp_path / "chrome"
    binary.write_text("")
    monkeypatch.setattr("deploy.release_preflight.os.access", lambda _path, _mode: True)
    env = {
        "EARN_PROXY_PROXIWARE_BROWSER_ENABLED": "1",
        "EARN_PROXY_PROXIWARE_CHROME_ENABLED": "1",
        "EARN_PROXY_PROXIWARE_CHROME_BINARY": str(binary),
        "EARN_PROXY_PROXIWARE_CDP_URL": "http://0.0.0.0:9222",
        "EARN_PROXY_PROXIWARE_CHROME_PROFILE_ROOT": "/var/lib/earn-proxy-browser",
        "EARN_PROXY_PROXIWARE_CHROME_PROFILE_DIR": "/var/lib/earn-proxy-browser/profile",
    }

    errors = validate_browser_runtime(env)

    assert "Proxiware CDP endpoint must be loopback HTTP with an explicit port" in errors
    assert "Proxiware Chrome profile root must be under /run" in errors


def test_release_preflight_requires_a_distinct_worker_encryption_key():
    preflight = (ROOT / "deploy" / "release_preflight.py").read_text()

    assert '"EARN_PROXY_PROXIWARE_WORKER_FERNET_KEY"' in preflight
    assert "must differ from the global Fernet key" in preflight
