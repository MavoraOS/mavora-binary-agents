# INSTALL — Mavora Site Provisioning Agent

SP-T-219 / agent/07 §42. Model C: agent is outbound HTTPS-443 only.
NO SSL/certbot/Cloudflare/DNS-provider interaction. DNS and SSL are Customer-managed.

---

## Prerequisites

### Operating System

Ubuntu 22.04 LTS or Ubuntu 24.04 LTS (x86_64 or arm64).
Other distributions are not supported in Phase 1.

### Required Commands

The installer checks for these before proceeding:

- `openssl` — keypair + CSR generation (mTLS; private key stays on VPS)
- `sudo` + `visudo` — sudoers install (validated before placement)
- `systemd` / `systemctl` — service management
- `curl` — bootstrap exchange (outbound 443 only)

### Pre-installed VPS Stack

The agent does NOT install WordPress, nginx, or php-fpm.
These must be set up before the agent is installed (OPS Phase-1 runbook, SP-T-402):

- **WordPress Multisite** — WP network initialized; `wp_network_id` recorded
- **WP-CLI** — `wp` in PATH, accessible as `www-data`
- **nginx** — serving WordPress; `nginx -t` passes
- **php-fpm** — running; socket path known

### Network

- **Outbound TCP 443** to Mavora control-plane URL must be open.
- No inbound ports are required for the agent (port 80 inbound is nginx, not the agent).
- No SSH access from Mavora to the VPS (push model — agent polls outbound).

### Clock

- NTP must be synchronized (`timedatectl | grep "NTP synchronized: yes"`).
- Agent envelope validation requires clock within ±5 minutes of Mavora time.
- Skewed clock causes job rejection (`AGENT_REPLAY_DETECTED`).

---

## Step 1 — Create Agent Record + Install Token (Mavora UI)

1. Log into Mavora dashboard as super_admin.
2. Navigate to **Agents → Add Agent**.
3. Fill in: Name, VPS IP (must match egress IP), optional `max_subsite_limit`.
4. Click **Create** — the UI generates a **one-time install token** (show-once).
5. Copy or save the token to a secure file (`/tmp/mavora-token`, mode 0600).

> The install token is single-use and expires in 1 hour. If it expires, generate a new one.

---

## Step 2 — Run install.sh

### Option A: One-liner (recommended)

```bash
sudo bash install.sh \
  --token-file /tmp/mavora-token \
  --control-plane https://api.mavora.io
```

- `--token-file` reads the token from a file and deletes it (keeps token off shell history).
- Never pass `--token` directly on the command line in production (shell history risk).

### Option B: From release bundle

```bash
tar xzf mavora-agent_v1.0.0_linux_amd64.tar.gz
cd mavora-agent_v1.0.0_linux_amd64/

sudo bash scripts/install.sh \
  --token-file /tmp/mavora-token \
  --control-plane https://api.mavora.io \
  --webroot /var/www/html \
  --nginx-available /etc/nginx/sites-available \
  --nginx-enabled /etc/nginx/sites-enabled
```

### Available Flags

| Flag | Default | Description |
|---|---|---|
| `--token-file <path>` | — | Read install token from file (RC-7: keeps off history) |
| `--token <value>` | — | Install token inline (avoid on production) |
| `--control-plane <url>` | — | Mavora API base URL (required) |
| `--binary <path>` | (fetched) | Use local-built binary instead of downloading |
| `--webroot <path>` | `/var/www` | WordPress Multisite root |
| `--user <name>` | `mavora-agent` | Service account (no home, nologin) |
| `--nginx-available <path>` | `/etc/nginx/sites-available` | nginx sites-available dir |
| `--nginx-enabled <path>` | `/etc/nginx/sites-enabled` | nginx sites-enabled dir |

---

## What the Installer Does

1. **OS check** — Ubuntu 22.04/24.04 only; fail fast on others.
2. **Prereq check** — openssl, sudo, visudo, curl, systemctl present.
3. **Create user** `mavora-agent` — system user, no home, nologin.
4. **Create directories** — `/etc/mavora-agent` (0700), `/var/lib/mavora-agent`, `/var/log/mavora-agent`.
5. **Install binary** — from `--binary` or fetched from control-plane.
6. **Generate mTLS keypair + CSR on this VPS** — private key NEVER leaves the machine.
7. **Bootstrap exchange** — POST `{install_token, csr}` to `/agent/v1/bootstrap`; receive `{signed_cert, ca, connection_key, ed25519_pubkey}`.
8. **Verify cert ↔ key** — cert returned by Mavora is checked against local private key before starting.
9. **Store credentials** (0600 owner mavora-agent): `client.key`, `client.crt`, `bearer.token`, `signing.pub`; `ca.crt` (0644).
10. **Write config** — `/etc/mavora-agent/config.yaml` (0600).
11. **Install sudoers** — only after `visudo -c` passes (refuses on syntax error).
12. **Enable + start** — `systemctl enable --now mavora-agent`.
13. **Verify first poll** — waits for agent to flip `pending_install → active`.

---

## Step 3 — Verify Active

After the installer completes:

```bash
# Check service
systemctl status mavora-agent

# Watch logs
journalctl -u mavora-agent -f

# Quick diagnostics
sudo bash scripts/doctor.sh
```

On Mavora UI: **Agents → [This Agent]** should show status **active**.

### Idempotent Rerun

Running install.sh again is safe:
- Existing user/dirs skipped.
- Existing creds + valid config: warns, does not overwrite.
- Systemd unit/sudoers re-validated and re-written safely.
- Re-run with an expired token → bootstrap fails (need a new token or `--rotate`).

---

## Troubleshooting Quick Reference

| Symptom | Likely Cause | Action |
|---|---|---|
| `pending_install` never → `active` | Binary won't start / egress blocked | See TROUBLESHOOTING.md |
| HTTP 401 during bootstrap | Token expired or wrong | Revoke + issue new token on UI |
| HTTP 403 during bootstrap | VPS IP not matching agent record | Update agent IP on UI |
| `AGENT_SECRET_PERMISSION_UNSAFE` | Wrong file mode | Re-run installer |
| Clock skew messages | NTP not synced | `timedatectl set-ntp true` |

Full decision tree: **TROUBLESHOOTING.md**.
