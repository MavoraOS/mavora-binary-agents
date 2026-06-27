# TROUBLESHOOTING — Mavora Site Provisioning Agent

SP-T-219 / agent/07 §42. Decision trees for common failure modes.
Run `sudo bash scripts/doctor.sh` first for automated diagnostics.

---

## Key Distinction: install_timeout vs unreachable

| Status | Meaning |
|---|---|
| `pending_install` | Agent was never seen (no successful poll since install) |
| `unreachable` | Agent polled successfully at some point, then stopped sending heartbeat |
| `active` | Agent is polling and heartbeat is within threshold |

- `install_timeout` → agent never started or can't reach control-plane.
- `unreachable` → agent ran, then lost connectivity or crashed.

---

## Decision Tree: install_timeout (never went active)

```
install_timeout
│
├── Is the service running?
│     systemctl status mavora-agent
│
├── NO → Did the service fail to start?
│   │     journalctl -u mavora-agent -n 50
│   │
│   ├── "AGENT_SECRET_PERMISSION_UNSAFE"
│   │     → Fix: chmod 0600 /etc/mavora-agent/* ; chown mavora-agent
│   │       Then: systemctl start mavora-agent
│   │
│   ├── "AGENT_CONFIG_INVALID" or missing required field
│   │     → Fix: re-run installer or edit /etc/mavora-agent/config.yaml
│   │
│   ├── Binary not found / permission error
│   │     → Fix: check /opt/mavora-agent/mavora-agent exists, mode 0755
│   │
│   └── Other crash on startup
│         → Check full journalctl; re-run installer with --binary <new-build>
│
└── YES → Service is running but still pending_install
    │
    ├── Check egress (outbound 443):
    │     curl -v https://api.mavora.io/livez
    │   ├── Connection refused / timeout → firewall blocks outbound 443
    │   │     Fix: allow outbound TCP 443 in ufw/iptables
    │   └── 200 OK → egress fine; continue below
    │
    ├── Check clock (envelope ±5min):
    │     timedatectl | grep "NTP synchronized"
    │   ├── no → Fix: timedatectl set-ntp true ; wait for sync
    │   └── yes → clock OK
    │
    ├── Check bearer / mTLS (401 / 403 in logs):
    │     journalctl -u mavora-agent | grep -E "401|403|auth|bearer"
    │   ├── 401 → bearer token expired; re-run installer with new token
    │   ├── 403 → VPS IP doesn't match agent record; update IP on Mavora UI
    │   └── No auth errors → continue below
    │
    └── Check control_plane URL in config:
          grep control_plane /etc/mavora-agent/config.yaml
          → Must match exact URL Mavora issued (no trailing slash, HTTPS)
```

---

## Decision Tree: unreachable (was active, now not)

```
unreachable
│
├── Is service still running?
│     systemctl status mavora-agent
│
├── NO → Crashed or OOM-killed
│     journalctl -u mavora-agent -n 100
│     → Fix crash; restart: systemctl start mavora-agent
│
└── YES → Running but not polling
    │
    ├── Network/egress broken? (ISP/VPS maintenance)
    │     curl -v https://api.mavora.io/livez
    │     → If unreachable: wait for network restoration
    │
    ├── Credentials expired? (bearer rotation due)
    │     → Run: sudo bash scripts/rotate.sh --control-plane https://api.mavora.io
    │
    └── Clock drift > 5 min?
          timedatectl | grep "NTP synchronized"
          → If no: timedatectl set-ntp true
```

---

## Common Issues

### nginx -t fails after provisioning

```bash
nginx -t
# If FAIL:
journalctl -u mavora-agent | grep nginx
# Agent should have rolled back. If vhost left:
ls /etc/nginx/sites-available/*.conf | tail -5
# Remove the bad vhost:
rm /etc/nginx/sites-available/broken-domain.conf
rm /etc/nginx/sites-enabled/broken-domain.conf
nginx -t && systemctl reload nginx
```

### WP-CLI fails

```bash
# Test directly as www-data:
sudo -u www-data wp --path=/var/www site list --format=json
# Check WP network is initialized:
sudo -u www-data wp --path=/var/www core multisite-install --help
```

### AGENT_SECRET_PERMISSION_UNSAFE at startup

```bash
ls -la /etc/mavora-agent/
# Fix permissions:
sudo chmod 0700 /etc/mavora-agent
sudo chmod 0600 /etc/mavora-agent/client.key /etc/mavora-agent/client.crt \
                /etc/mavora-agent/bearer.token /etc/mavora-agent/signing.pub \
                /etc/mavora-agent/config.yaml
sudo chown -R mavora-agent:mavora-agent /etc/mavora-agent
sudo systemctl start mavora-agent
```

### Job rejected — AGENT_REPLAY_DETECTED

Clock is skewed by more than 5 minutes:
```bash
timedatectl
timedatectl set-ntp true
# Wait a minute, then:
timedatectl | grep "NTP synchronized"
```

### Logs show bearer or key values (RC-7 scrubber test)

This must not happen. If it does, it is a critical bug.
Run `sudo bash scripts/doctor.sh` to check permissions; file a bug with the log excerpt.

---

## Useful Commands

```bash
# Full status
systemctl status mavora-agent

# Follow logs (structured JSON)
journalctl -u mavora-agent -f --output=json | jq .

# Last 100 log lines
journalctl -u mavora-agent -n 100 --no-pager

# Diagnostic tool (read-only, no secrets printed)
sudo bash scripts/doctor.sh

# Restart
systemctl restart mavora-agent

# Stop
systemctl stop mavora-agent
```
