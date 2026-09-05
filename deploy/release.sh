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
services=(
  earn-proxy-web
  earn-proxy-checker
  earn-proxy-earnapp
  earn-proxy-maintenance
  earn-proxy-payout-verifier
)

cleanup() {
  rm -f -- "$archive" "$next_link"
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
"$python_bin" -m venv "$release_dir/.venv"
"$release_dir/.venv/bin/python" -m pip install --disable-pip-version-check --upgrade "pip>=25.3" "setuptools>=83"
"$release_dir/.venv/bin/python" -m pip install --disable-pip-version-check "$release_dir"
"$release_dir/.venv/bin/python" -m pip check
chown -R root:root "$release_dir"
chmod -R go-w "$release_dir"

set -a
source /etc/earn-proxy.env
set +a
cd "$release_dir"
"$release_dir/.venv/bin/python" -m deploy.release_preflight --release-dir "$release_dir"

install -m 0644 "$release_dir"/deploy/earn-proxy-*.service /etc/systemd/system/
systemctl daemon-reload
systemd-analyze verify "$release_dir"/deploy/earn-proxy-*.service
ln -s "$release_dir" "$next_link"
mv -Tf "$next_link" /opt/earn-proxy

if ! systemctl restart "${services[@]}" || ! timeout 30 bash -c '
  until curl -fsS http://127.0.0.1:8100/healthz >/dev/null; do sleep 1; done
'; then
  echo "new release failed health verification; restoring previous release" >&2
  if [[ -n "$previous_release" && -d "$previous_release" ]]; then
    ln -s "$previous_release" "$next_link"
    mv -Tf "$next_link" /opt/earn-proxy
    systemctl restart "${services[@]}"
  fi
  exit 1
fi

printf 'release active: %s\n' "$release_dir"
printf 'rollback release: %s\n' "${previous_release:-none}"
