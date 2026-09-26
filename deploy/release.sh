#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: sudo deploy/release.sh <revision>" >&2
  exit 64
fi
if [[ "${EUID}" -ne 0 ]]; then
  echo "release must run as root" >&2
  exit 77
fi

revision="$1"
if [[ ! "$revision" =~ ^[0-9a-f]{7,40}$ ]]; then
  echo "revision must be a 7-40 character lowercase Git SHA" >&2
  exit 64
fi

source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
release_dir="/opt/earn-proxy-${revision}"
python_bin="${EARN_PROXY_PYTHON:-/opt/python3.11/bin/python3.11}"
previous_release="$(readlink -f /opt/earn-proxy || true)"
next_link="/opt/.earn-proxy-next"
archive="$(mktemp --tmpdir earn-proxy-release.XXXXXX.tar)"
backup_stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_dir="/var/backups/earn-proxy/${backup_stamp}-${revision}"
database_path="$(awk -F= '$1 == "EARN_PROXY_DATABASE" { sub(/^[[:space:]]+/, "", $2); gsub(/^"|"$/, "", $2); print $2; exit }' /etc/earn-proxy.env)"
database_path="${database_path:-/var/lib/earn-proxy/earn-proxy.db}"
# ponytail: keep production DB at the fixed direct path; support custom paths
# only after adding dirfd/openat2 validation for every parent component.
if [[ "$database_path" != "/var/lib/earn-proxy/earn-proxy.db" ]]; then
  echo "EARN_PROXY_DATABASE must be /var/lib/earn-proxy/earn-proxy.db" >&2
  exit 78
fi
activated=0
services=(
  earn-proxy-web
  earn-proxy-checker
  earn-proxy-earnapp
  earn-proxy-maintenance
  earn-proxy-payout-verifier
  earn-proxy-proxiware
  earn-proxy-proxiware-qualification
  earn-proxy-proxiware-swap
  earn-proxy-proxiware-cdp-acl
  earn-proxy-proxiware-chrome
  earn-proxy-proxiware-browser
)
previous_services=()

if ! getent group earnproxy-chrome >/dev/null 2>&1; then
  groupadd --system earnproxy-chrome
fi
if ! id -u earnproxy-browser >/dev/null 2>&1; then
  useradd --system --gid earnproxy --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin earnproxy-browser
fi
if ! id -u earnproxy-chrome >/dev/null 2>&1; then
  useradd --system --gid earnproxy-chrome --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin earnproxy-chrome
fi

cleanup() {
  rm -f -- "$archive" "$next_link"
  if [[ "$activated" -eq 0 && -d "$release_dir" ]]; then
    rm -rf -- "$release_dir"
  fi
}
trap cleanup EXIT

if [[ -e "$release_dir" ]]; then
  echo "release already exists: $release_dir" >&2
  exit 73
fi
if [[ ! -f /etc/earn-proxy.env ]]; then
  echo "missing /etc/earn-proxy.env" >&2
  exit 78
fi
if [[ ! -x "$python_bin" ]]; then
  python_bin="$(command -v python3.11 || true)"
fi
if [[ -z "$python_bin" ]] || ! "$python_bin" -c 'import sys; raise SystemExit(sys.version_info < (3, 11))'; then
  echo "Python 3.11 or newer is required" >&2
  exit 69
fi

git -C "$source_dir" archive --format=tar "$revision" -o "$archive"
install -d -o root -g root -m 0755 "$release_dir"
tar -xf "$archive" -C "$release_dir"

# The browser observer shares the runtime database through the earnproxy group.
# Run the descriptor-safe helper from the immutable archived revision, never
# from the mutable source checkout used to invoke this release.
install -d -o earnproxy -g earnproxy -m 0770 /var/lib/earn-proxy
"$python_bin" "$release_dir/deploy/secure_runtime_permissions.py" \
  --user earnproxy --group earnproxy --mode 0660 "$database_path"
for sqlite_sidecar in "$database_path"-wal "$database_path"-shm; do
  "$python_bin" "$release_dir/deploy/secure_runtime_permissions.py" \
    --user earnproxy --group earnproxy --mode 0660 --optional "$sqlite_sidecar"
done

"$python_bin" -m venv "$release_dir/.venv"
"$release_dir/.venv/bin/python" -m pip install --disable-pip-version-check --upgrade "pip>=25.3" "setuptools>=83"
"$release_dir/.venv/bin/python" -m pip install --disable-pip-version-check "$release_dir"
"$release_dir/.venv/bin/python" -m pip check
chown -R root:root "$release_dir"
chmod -R go-w "$release_dir"
umask 0077

install -d -o root -g earnproxy -m 0750 /var/backups/earn-proxy
install -d -o root -g earnproxy -m 0750 "$backup_dir"
install -d -o root -g root -m 0700 "$backup_dir/systemd"
install -o root -g root -m 0600 /dev/null "$backup_dir/earn-proxy.db"
"$release_dir/.venv/bin/python" - "$database_path" "$backup_dir/earn-proxy.db" <<'PY'
import os
import sqlite3
import stat
import sys

source_fd = os.open(sys.argv[1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
try:
    if not stat.S_ISREG(os.fstat(source_fd).st_mode):
        raise RuntimeError("database source is not a regular file")
    source = sqlite3.connect(f"file:/proc/self/fd/{source_fd}?mode=ro", uri=True)
    destination = sqlite3.connect(sys.argv[2])
    try:
        with destination:
            source.backup(destination)
    finally:
        source.close()
        destination.close()
finally:
    os.close(source_fd)
PY
cp -a /etc/earn-proxy.env "$backup_dir/earn-proxy.env"
chmod 0600 "$backup_dir/earn-proxy.db" "$backup_dir/earn-proxy.env"
cp -a /etc/systemd/system/earn-proxy-*.service "$backup_dir/systemd/"
for unit_path in "$backup_dir"/systemd/earn-proxy-*.service; do
  unit_name="$(basename "$unit_path")"
  previous_services+=("${unit_name%.service}")
done

systemd-run --quiet --wait --pipe --collect \
  --uid=earnproxy --gid=earnproxy \
  --working-directory="$release_dir" \
  --property=EnvironmentFile=/etc/earn-proxy.env \
  --property=EnvironmentFile=-/etc/earn-proxy-browser.env \
  "$release_dir/.venv/bin/python" -m deploy.release_preflight --release-dir "$release_dir"

install -m 0644 "$release_dir"/deploy/earn-proxy-*.service /etc/systemd/system/
systemctl daemon-reload
systemd-analyze verify "$release_dir"/deploy/earn-proxy-*.service
systemctl enable "${services[@]}"
ln -s "$release_dir" "$next_link"
mv -Tf "$next_link" /opt/earn-proxy
if ! systemctl restart "${services[@]}" || ! systemctl is-active --quiet "${services[@]}" || ! timeout 30 bash -c '
  until curl -fsS http://127.0.0.1:8100/healthz >/dev/null; do sleep 1; done
'; then
  echo "new release failed health verification; restoring previous release" >&2
  if [[ -n "$previous_release" && -d "$previous_release" ]]; then
    systemctl stop "${services[@]}" || true
    systemctl disable "${services[@]}" || true
    for service in "${services[@]}"; do
      unit_name="${service}.service"
      rm -f -- "/etc/systemd/system/$unit_name"
    done
    ln -s "$previous_release" "$next_link"
    mv -Tf "$next_link" /opt/earn-proxy
    install -m 0644 "$backup_dir"/systemd/earn-proxy-*.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable "${previous_services[@]}"
    systemctl restart "${previous_services[@]}"
  fi
  rm -rf -- "$release_dir"
  exit 1
fi

activated=1
printf 'release active: %s\n' "$release_dir"
printf 'rollback release: %s\n' "${previous_release:-none}"
