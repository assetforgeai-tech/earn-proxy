#!/usr/bin/env bash
set -u

log() { logger -t proxy-relay-healthcheck -- "$*"; }
failures=()
ALERT_AFTER=3
CPU_WARN=90
MEMORY_WARN=90
DISK_WARN=85
STATE_FILE=/var/lib/proxy-relay-monitor/consecutive-failures
install -d -m 0700 "${STATE_FILE%/*}"

for unit in proxy-relay.service proxy-relay-engine.service caddy.service; do
    if ! systemctl is-active --quiet "$unit"; then failures+=("$unit inactive"); fi
done
if ! curl --noproxy '*' --fail --silent --show-error --max-time 10 http://127.0.0.1:8000/healthz >/dev/null 2>&1; then failures+=("healthz failed"); fi

read -r live entries listeners missing_ports < <(python3 - <<'PY'
import json
import sqlite3
import subprocess

db = sqlite3.connect('/opt/proxy-relay/relay.db')
live = db.execute("select count(*) from proxies where status in ('live','live_unverified') and enabled=1 and detected_protocol in ('http','socks5')").fetchone()[0]
with open('/opt/proxy-relay/relay.json', encoding='utf-8') as handle:
    relay = json.load(handle)
expected_ports = {int(entry['port']) for entry in relay.get('entries', [])}
listening_ports = set()
for line in subprocess.check_output(["ss", "-ltnH"], text=True).splitlines():
    fields = line.split()
    if len(fields) < 4:
        continue
    try:
        listening_ports.add(int(fields[3].rsplit(':', 1)[1]))
    except (IndexError, ValueError):
        continue
missing_ports = sorted(expected_ports - listening_ports)
print(live, len(expected_ports), len(expected_ports & listening_ports), len(missing_ports))
PY
)
if [[ "$live" != "$entries" ]]; then failures+=("database/listener config mismatch live=$live entries=$entries"); fi
if ((missing_ports > 0)); then failures+=("socket/config mismatch listeners=$listeners entries=$entries missing=$missing_ports"); fi

read -r cpu_percent memory_percent disk_percent < <(python3 - <<'PY'
import os
import time

def cpu_sample():
    values = [int(value) for value in open('/proc/stat').readline().split()[1:]]
    return sum(values), values[3] + values[4]

total_a, idle_a = cpu_sample()
time.sleep(0.25)
total_b, idle_b = cpu_sample()
delta_total = max(1, total_b - total_a)
delta_idle = max(0, idle_b - idle_a)
cpu = round(100 * (delta_total - delta_idle) / delta_total)
memory = {}
for line in open('/proc/meminfo'):
    key, value = line.split(':', 1)
    memory[key] = int(value.split()[0])
mem = round(100 * (memory['MemTotal'] - memory['MemAvailable']) / memory['MemTotal'])
disk = os.statvfs('/')
disk_used = round(100 * (disk.f_blocks - disk.f_bavail) / disk.f_blocks)
print(cpu, mem, disk_used)
PY
)
((cpu_percent >= CPU_WARN)) && failures+=("cpu=${cpu_percent}%")
((memory_percent >= MEMORY_WARN)) && failures+=("memory=${memory_percent}%")
((disk_percent >= DISK_WARN)) && failures+=("disk=${disk_percent}%")

if ((${#failures[@]})); then
    consecutive=$(cat "$STATE_FILE" 2>/dev/null || echo 0)
    [[ "$consecutive" =~ ^[0-9]+$ ]] || consecutive=0
    consecutive=$((consecutive+1))
    printf '%s\n' "$consecutive" > "$STATE_FILE"
    if ((consecutive >= ALERT_AFTER)); then log "ALERT ($consecutive consecutive checks): ${failures[*]}"; else log "WARN ($consecutive/$ALERT_AFTER): ${failures[*]}"; fi
else
    previous=$(cat "$STATE_FILE" 2>/dev/null || echo 0)
    printf '0\n' > "$STATE_FILE"
    log "OK: services=3 healthz=ok live=$live entries=$entries listeners=$listeners cpu=${cpu_percent}% memory=${memory_percent}% disk=${disk_percent}% recovered_after=$previous"
fi
exit 0
