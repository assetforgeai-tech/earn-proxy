#!/usr/bin/env bash
set -euo pipefail

install -d -m 0750 /opt/proxy-relay
python3 -m venv /opt/proxy-relay/.venv
/opt/proxy-relay/.venv/bin/pip install --disable-pip-version-check -r /opt/proxy-relay/requirements.txt
install -m 0644 /opt/proxy-relay/deploy/proxy-relay.service /etc/systemd/system/proxy-relay.service
install -m 0644 /opt/proxy-relay/deploy/proxy-relay-engine.service /etc/systemd/system/proxy-relay-engine.service
install -m 0750 /opt/proxy-relay/deploy/proxy-relay-healthcheck.sh /usr/local/sbin/proxy-relay-healthcheck
install -m 0644 /opt/proxy-relay/deploy/proxy-relay-healthcheck.service /etc/systemd/system/proxy-relay-healthcheck.service
install -m 0644 /opt/proxy-relay/deploy/proxy-relay-healthcheck.timer /etc/systemd/system/proxy-relay-healthcheck.timer
install -m 0750 /opt/proxy-relay/deploy/proxy-relay-backup.sh /usr/local/sbin/proxy-relay-backup
install -m 0644 /opt/proxy-relay/deploy/proxy-relay-backup.service /etc/systemd/system/proxy-relay-backup.service
install -m 0644 /opt/proxy-relay/deploy/proxy-relay-backup.timer /etc/systemd/system/proxy-relay-backup.timer
systemctl daemon-reload
systemctl enable --now proxy-relay proxy-relay-engine proxy-relay-healthcheck.timer proxy-relay-backup.timer
systemctl enable --now caddy
ufw allow 20001:29999/tcp
ufw allow 30001:39999/tcp
