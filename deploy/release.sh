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
worker_env="/etc/earn-proxy-proxiware-worker.env"
worker_key_env="/etc/earn-proxy-proxiware-worker-key.env"
worker_env_tmp=""
worker_key_env_tmp=""
worker_env_existed=0
worker_key_env_existed=0
worker_env_installed=0
worker_key_env_installed=0
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
  rm -f -- "$archive" "$next_link" "$worker_env_tmp" "$worker_key_env_tmp"
  if [[ "$activated" -eq 0 && "$worker_env_installed" -eq 1 ]]; then
    if [[ "$worker_env_existed" -eq 1 && -f "$backup_dir/earn-proxy-proxiware-worker.env" ]]; then
      install -o root -g root -m 0600 "$backup_dir/earn-proxy-proxiware-worker.env" "$worker_env"
    else
      rm -f -- "$worker_env"
    fi
  fi
  if [[ "$activated" -eq 0 && "$worker_key_env_installed" -eq 1 ]]; then
    if [[ "$worker_key_env_existed" -eq 1 && -f "$backup_dir/earn-proxy-proxiware-worker-key.env" ]]; then
      install -o root -g root -m 0600 "$backup_dir/earn-proxy-proxiware-worker-key.env" "$worker_key_env"
    else
      rm -f -- "$worker_key_env"
    fi
  fi
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
if [[ -f "$worker_env" ]]; then
  worker_env_existed=1
fi
if [[ -f "$worker_key_env" ]]; then
  worker_key_env_existed=1
fi
worker_env_tmp="$(mktemp --tmpdir earn-proxy-worker-env.XXXXXX)"
worker_key_env_tmp="$(mktemp --tmpdir earn-proxy-worker-key-env.XXXXXX)"
render_worker_env() {
  local key line
  : > "$worker_env_tmp"
  printf '%s\n' 'EARN_PROXY_RUNTIME_PROFILE=proxiware_worker' >> "$worker_env_tmp"
  while IFS= read -r key; do
    line="$(awk -F= -v wanted="$key" '$1 == wanted { print; exit }' /etc/earn-proxy-browser.env /etc/earn-proxy.env 2>/dev/null || true)"
    if [[ -z "$line" ]]; then
      echo "missing worker environment key: $key" >&2
      return 1
    fi
    printf '%s\n' "$line" >> "$worker_env_tmp"
  done <<'EOF'
EARN_PROXY_DATABASE
EARN_PROXY_INSTANCE_PATH
EARN_PROXY_PROXIWARE_BROWSER_ENABLED
EARN_PROXY_PROXIWARE_BROWSER_DRY_RUN
EARN_PROXY_PROXIWARE_BROWSER_ALLOW_MUTATION
EARN_PROXY_PROXIWARE_CDP_URL
EARN_PROXY_PROXIWARE_BROWSER_DASHBOARD_URL
EARN_PROXY_PROXIWARE_BROWSER_INTERVAL_SECONDS
EARN_PROXY_PROXIWARE_BROWSER_HEARTBEAT_INTERVAL_SECONDS
EOF
}
if [[ ! -x "$python_bin" ]]; then
  python_bin="$(command -v python3.11 || true)"
fi
if [[ -z "$python_bin" ]] || ! "$python_bin" -c 'import sys; raise SystemExit(sys.version_info < (3, 11))'; then
  echo "Python 3.11 or newer is required" >&2
  exit 69
fi
render_worker_env
if [[ "$worker_key_env_existed" -eq 1 ]]; then
  cp "$worker_key_env" "$worker_key_env_tmp"
else
  "$python_bin" - "$worker_key_env_tmp" <<'PY'
import base64
import os
import sys

with open(sys.argv[1], "w", encoding="ascii") as output:
    output.write("EARN_PROXY_PROXIWARE_WORKER_FERNET_KEY=")
    output.write(base64.urlsafe_b64encode(os.urandom(32)).decode("ascii"))
    output.write("\n")
PY
fi
worker_key_line="$(awk -F= '$1 == "EARN_PROXY_PROXIWARE_WORKER_FERNET_KEY" { print; exit }' "$worker_key_env_tmp")"
if [[ -z "$worker_key_line" ]]; then
  echo "missing worker encryption key" >&2
  exit 78
fi
git -C "$source_dir" archive --format=tar "$revision" -o "$archive"
install -d -o root -g root -m 0755 "$release_dir"
tar -xf "$archive" -C "$release_dir"
source_branch="$(git -C "$source_dir" branch --show-current 2>/dev/null || true)"
source_origin_main="$(git -C "$source_dir" rev-parse origin/main 2>/dev/null || true)"
if [[ -z "$source_branch" && -n "$source_origin_main" ]]; then
  source_branch="main"
fi
printf 'revision=%s\nbranch=%s\norigin_main=%s\n' \
  "$revision" "$source_branch" "$source_origin_main" > "$release_dir/.release-metadata"
chown root:root "$release_dir/.release-metadata"
chmod 0644 "$release_dir/.release-metadata"

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
if [[ "$worker_env_existed" -eq 1 ]]; then
  cp -a "$worker_env" "$backup_dir/earn-proxy-proxiware-worker.env"
fi
if [[ "$worker_key_env_existed" -eq 1 ]]; then
  cp -a "$worker_key_env" "$backup_dir/earn-proxy-proxiware-worker-key.env"
fi
chmod 0600 "$backup_dir/earn-proxy.db" "$backup_dir/earn-proxy.env"
if [[ "$worker_key_env_existed" -eq 1 ]]; then
  chmod 0600 "$backup_dir/earn-proxy-proxiware-worker-key.env"
fi
install -o root -g root -m 0600 "$worker_env_tmp" "$worker_env"
worker_env_installed=1
install -o root -g root -m 0600 "$worker_key_env_tmp" "$worker_key_env"
worker_key_env_installed=1
worker_env_mode="$(stat -c '%a' "$worker_env" 2>/dev/null || true)"
worker_env_owner="$(stat -c '%U:%G' "$worker_env" 2>/dev/null || true)"
if [[ "$worker_env_mode" != "600" || "$worker_env_owner" != "root:root" ]]; then
  echo "$worker_env must be root:root mode 0600" >&2
  exit 78
fi
worker_key_env_mode="$(stat -c '%a' "$worker_key_env" 2>/dev/null || true)"
worker_key_env_owner="$(stat -c '%U:%G' "$worker_key_env" 2>/dev/null || true)"
if [[ "$worker_key_env_mode" != "600" || "$worker_key_env_owner" != "root:root" ]]; then
  echo "$worker_key_env must be root:root mode 0600" >&2
  exit 78
fi
cp -a /etc/systemd/system/earn-proxy-*.service "$backup_dir/systemd/"
for unit_path in "$backup_dir"/systemd/earn-proxy-*.service; do
  unit_name="$(basename "$unit_path")"
  previous_services+=("${unit_name%.service}")
done

systemd-run --quiet --wait --pipe --collect \
  --uid=earnproxy --gid=earnproxy \
  --working-directory="$release_dir" \
  --property=EnvironmentFile=/etc/earn-proxy.env \
  --property=EnvironmentFile=/etc/earn-proxy-proxiware-worker-key.env \
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
    if [[ "$worker_env_existed" -eq 1 ]]; then
      install -o root -g root -m 0600 "$backup_dir/earn-proxy-proxiware-worker.env" "$worker_env"
    else
      rm -f -- "$worker_env"
    fi
    worker_env_installed=0
    if [[ "$worker_key_env_existed" -eq 1 ]]; then
      install -o root -g root -m 0600 "$backup_dir/earn-proxy-proxiware-worker-key.env" "$worker_key_env"
    else
      rm -f -- "$worker_key_env"
    fi
    worker_key_env_installed=0
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
