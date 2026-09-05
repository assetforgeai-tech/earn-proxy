#!/usr/bin/env bash
set -euo pipefail

BACKUP_ROOT=/var/backups/proxy-relay
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
DEST="$BACKUP_ROOT/$STAMP"
install -d -m 0700 "$DEST"

python3 - "$DEST/relay.db" <<'PY'
import sqlite3
import sys

source = sqlite3.connect('/opt/proxy-relay/relay.db')
target = sqlite3.connect(sys.argv[1])
with target:
    source.backup(target)
if target.execute('pragma integrity_check').fetchone()[0] != 'ok':
    raise SystemExit('backup integrity check failed')
target.close()
source.close()
PY

install -m 0600 /opt/proxy-relay/relay.json "$DEST/relay.json"
install -m 0600 /etc/proxy-relay.env "$DEST/proxy-relay.env"
install -m 0640 /etc/caddy/Caddyfile "$DEST/Caddyfile"
install -m 0644 /etc/systemd/system/proxy-relay.service "$DEST/proxy-relay.service"
install -m 0644 /etc/systemd/system/proxy-relay-engine.service "$DEST/proxy-relay-engine.service"
ufw status numbered > "$DEST/ufw-status.txt"
chmod 0600 "$DEST/ufw-status.txt"
find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -mtime +14 -depth -delete
logger -t proxy-relay-backup -- "OK: backup=$DEST"
