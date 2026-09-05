from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_native_web_unit_does_not_depend_on_a_console_script_shebang():
    unit = (ROOT / "deploy" / "earn-proxy-web.service").read_text()

    assert "ExecStart=/opt/earn-proxy/.venv/bin/python -m gunicorn " in unit
    assert "ExecStart=/opt/earn-proxy/.venv/bin/gunicorn " not in unit


def test_release_installer_builds_the_venv_at_its_final_absolute_path():
    installer = (ROOT / "deploy" / "release.sh").read_text()

    assert 'release_dir="/opt/earn-proxy-${revision}"' in installer
    assert 'python3 -m venv "$release_dir/.venv"' in installer
    assert '"$release_dir/.venv/bin/python" -m pip install' in installer
    assert '"$release_dir/.venv/bin/python" -m pip check' in installer
    assert "cp -a /opt/earn-proxy/.venv" not in installer
    assert "sed -i" not in installer


def test_release_installer_preflights_before_switching_and_rolls_back_on_failure():
    installer = (ROOT / "deploy" / "release.sh").read_text()

    preflight = installer.index('"$release_dir/.venv/bin/python" -m deploy.release_preflight')
    switch = installer.index('ln -s "$release_dir" "$next_link"')
    assert preflight < switch
    assert 'previous_release="$(readlink -f /opt/earn-proxy || true)"' in installer
    assert 'ln -s "$previous_release" "$next_link"' in installer
    assert 'systemctl restart "${services[@]}"' in installer


def test_release_preflight_rejects_a_venv_created_for_another_release(tmp_path, monkeypatch):
    from deploy.release_preflight import validate_runtime_prefix

    release_dir = tmp_path / "earn-proxy-deadbee"
    monkeypatch.setattr("sys.prefix", str(tmp_path / "earn-proxy-old" / ".venv"))

    errors = validate_runtime_prefix(release_dir)

    assert errors == [f"virtualenv prefix is not {release_dir / '.venv'}"]
