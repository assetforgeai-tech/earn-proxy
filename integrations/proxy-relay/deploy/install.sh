#!/usr/bin/env bash
set -euo pipefail

install -d -m 0750 /opt/proxy-relay
python3 -m venv /opt/proxy-relay/.venv
/opt/proxy-relay/.venv/bin/pip install --disable-pip-version-check -r /opt/proxy-relay/requirements.txt
command -v go >/dev/null 2>&1 || { echo 'Go is required to build proxy-relay-engine' >&2; exit 1; }
(cd /opt/proxy-relay/engine && go build -trimpath -o /usr/local/bin/proxy-relay-engine .)
chmod 0755 /usr/local/bin/proxy-relay-engine
install -m 0644 /opt/proxy-relay/deploy/proxy-relay.service /etc/systemd/system/proxy-relay.service
install -m 0644 /opt/proxy-relay/deploy/proxy-relay-engine.service /etc/systemd/system/proxy-relay-engine.service
install -m 0750 /opt/proxy-relay/deploy/proxy-relay-healthcheck.sh /usr/local/sbin/proxy-relay-healthcheck
install -m 0644 /opt/proxy-relay/deploy/proxy-relay-healthcheck.service /etc/systemd/system/proxy-relay-healthcheck.service
install -m 0644 /opt/proxy-relay/deploy/proxy-relay-healthcheck.timer /etc/systemd/system/proxy-relay-healthcheck.timer
install -m 0750 /opt/proxy-relay/deploy/proxy-relay-backup.sh /usr/local/sbin/proxy-relay-backup
install -m 0644 /opt/proxy-relay/deploy/proxy-relay-backup.service /etc/systemd/system/proxy-relay-backup.service
install -m 0644 /opt/proxy-relay/deploy/proxy-relay-backup.timer /etc/systemd/system/proxy-relay-backup.timer
install -m 0644 /opt/proxy-relay/deploy/proxy-relay-proxiware-sync.service /etc/systemd/system/proxy-relay-proxiware-sync.service
install -m 0644 /opt/proxy-relay/deploy/proxy-relay-proxiware-sync.timer /etc/systemd/system/proxy-relay-proxiware-sync.timer
systemctl daemon-reload
systemctl enable --now proxy-relay-healthcheck.timer proxy-relay-backup.timer proxy-relay-proxiware-sync.timer
systemctl enable proxy-relay proxy-relay-engine
for unit in proxy-relay-engine proxy-relay; do
    if systemctl is-active --quiet "$unit"; then
        systemctl restart "$unit"
    else
        systemctl start "$unit"
    fi
done
systemctl enable --now caddy
ufw allow 20001:29999/tcp
ufw allow 30001:39999/tcp
