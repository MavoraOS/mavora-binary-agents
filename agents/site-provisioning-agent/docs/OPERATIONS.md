# OPERATIONS — Mavora Site Provisioning Agent

SP-T-219 / agent/07 §42. Day-2 operations: rotate, rebuild, backup, uninstall.

---

## Rotate Credentials (~90 Days or Suspected Compromise)

Rotate proactively every ~90 days. Rotate immediately if credentials suspected compromised.

### Step 1: Generate a rotate token on Mavora UI

Log in → Agents → [This Agent] → Rotate → Copy token to `/tmp/rotate-token` (0600).

### Step 2: Run rotate.sh

```bash
sudo bash scripts/rotate.sh \
  --control-plane https://api.mavora.io \
  --token-file /tmp/rotate-token
```

### What happens:
- New mTLS keypair + CSR generated on-VPS (private key stays here).
- Rotate token + CSR exchanged for: new signed cert + bearer + Ed25519 pubkey.
- Cert ↔ key verified before applying.
- New credentials written 0600.
- Service reloaded.
- **Grace window: 15 minutes** — agent holds both old and new Ed25519 public keys so in-flight jobs signed with the old key still verify.
- After grace: old key removed automatically (background process).

### Verify after rotation:

```bash
systemctl status mavora-agent
journalctl -u mavora-agent -n 20
# Confirm "active" on Mavora UI
```

---

## Rebuild VPS (Suspected Compromise or Migration)

Per master-spec §26.6. Blast radius = 1 VPS.

### Step 1: Revoke on Mavora UI

Log in → Agents → [This Agent] → Revoke.
This invalidates the bearer token, mTLS cert, and Ed25519 public key.
After revoke, the old agent CANNOT authenticate even if the VPS is still running.

### Step 2: Rebuild VPS

Use your VPS provider to reinstall Ubuntu 22.04/24.04.
Reinstall the WP Multisite stack (OPS runbook SP-T-402).

### Step 3: Create a new agent record (or reuse)

On Mavora UI: Agents → Add Agent (or reactivate if same IP).
Generate a new install token.

### Step 4: Reinstall the agent

```bash
sudo bash scripts/install.sh \
  --token-file /tmp/mavora-token \
  --control-plane https://api.mavora.io
```

### Step 5: Re-provision sites

The new agent will receive provision jobs from the backend.
`Reconcile()` on agent startup is passive (no double-vhost/subsite).

---

## Backup — WordPress Multisite (RPO ≤24h / RTO ≤4h)

The agent does NOT manage backups. Customer/OPS is responsible for:

| Component | Backup method | RPO target |
|---|---|---|
| WordPress database | mysqldump / automated DB snapshots | ≤24h |
| WordPress uploads + files | Filesystem snapshot / rsync | ≤24h |
| nginx config | `/etc/nginx/` in system snapshot | ≤24h |
| Agent credentials | **NOT backed up in plaintext** (see below) |

**Agent credentials (`/etc/mavora-agent/`) MUST NOT be included in plaintext backups** (RC-7).
If credentials are lost (VPS rebuild), revoke + reinstall (see Rebuild above).

---

## Deprovision / Delete Agent

Agent record on Mavora cannot be deleted if it has provisioned sites (`AGENT_HAS_REFERENCES`).

### To delete an agent:
1. Deprovision all sites on this agent (Mavora UI or API).
2. Confirm `current_subsite_count = 0`.
3. Uninstall agent: `sudo bash scripts/uninstall.sh`.
4. Revoke on Mavora UI.
5. Delete agent record.

---

## Uninstall

Does NOT touch WordPress, nginx, php-fpm, or site data:

```bash
sudo bash scripts/uninstall.sh
```

Then: revoke agent on Mavora UI (see SECURITY.md — revoke credentials).

### What uninstall removes:
- `systemctl disable --now mavora-agent`
- `/etc/systemd/system/mavora-agent.service`
- `/etc/sudoers.d/mavora-agent`
- `/opt/mavora-agent/` (binary + helpers)
- `/etc/mavora-agent/` (credentials + config)
- `/var/lib/mavora-agent/` (idempotency store)
- `/var/log/mavora-agent/` (logs)

### What uninstall DOES NOT touch:
- `/etc/nginx/` — nginx configs and vhosts
- `/var/www/` — WordPress files
- MySQL / MariaDB — WordPress database
- php-fpm — PHP process
- Any site data

---

## Optional Firewall (SP-BR-17)

Default: OFF. Only relevant for Mavora-provided VPS where Customer uses a known proxy.

To enable:
1. Set `firewall_enabled: true` in `/etc/mavora-agent/config.yaml`.
2. Add proxy CIDRs under `firewall_proxy_cidrs:`.
3. Restart: `systemctl restart mavora-agent`.

Provisioning does NOT fail if the optional firewall step fails (`AGENT_FIREWALL_LOCK_FAILED` is non-blocking).

---

## Resource Admission (RC-5 / SP-ADR-012)

The agent reports resource stats via heartbeat. Mavora uses these for admission control:

| Threshold | Effect |
|---|---|
| Disk > 85% of webroot partition | Step-2 rejected with `AGENT_RESOURCE_EXHAUSTED` |
| RAM used > 90% | Step-2 rejected |
| load5 > cores × 1.5 | Step-2 rejected |

When rejected: Mavora selects a different agent or waits for resource to free.
No action needed on the VPS unless the threshold persists.

---

## Monitoring

The agent logs structured JSON to stdout (captured by journald).

```bash
# Follow structured logs
journalctl -u mavora-agent -f --output=json | jq '.'

# Filter for errors only
journalctl -u mavora-agent | grep '"status":"failed"'

# Check heartbeat interval
journalctl -u mavora-agent | grep '"event":"heartbeat"'
```

No inbound Prometheus scrape endpoint is exposed (BL-13). Metrics are available via:
- Heartbeat payload (Mavora control-plane aggregates resource stats)
- Structured log analysis (optional node-exporter textfile if configured by OPS)
