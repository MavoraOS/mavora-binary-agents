# CONFIGURATION — Mavora Site Provisioning Agent

SP-T-219 / agent/07 §42. Model C.
NO SSL/AOP/Cloudflare/DNS-provider configuration fields.
Config file MUST be 0600; secret fields contain FILE PATHS only (never inline values).

---

## Config File Location

Default: `/etc/mavora-agent/config.yaml`

Override via environment variable: `MAVORA_AGENT_CONFIG=/path/to/config.yaml`

The installer generates this file from `configs/config.example.yaml`.

---

## File Permissions (CRITICAL)

| Path | Mode | Owner | Notes |
|---|---|---|---|
| `/etc/mavora-agent/` | 0700 | `mavora-agent` | Config dir — no world read |
| `/etc/mavora-agent/config.yaml` | 0600 | `mavora-agent` | Main config |
| `/etc/mavora-agent/client.key` | 0600 | `mavora-agent` | mTLS private key |
| `/etc/mavora-agent/client.crt` | 0600 | `mavora-agent` | mTLS client cert |
| `/etc/mavora-agent/bearer.token` | 0600 | `mavora-agent` | Runtime bearer |
| `/etc/mavora-agent/signing.pub` | 0600 | `mavora-agent` | Ed25519 verifying public key |
| `/etc/mavora-agent/ca.crt` | 0644 | `mavora-agent` | Mavora CA cert (not a secret) |
| `/var/lib/mavora-agent/` | 0755 | `mavora-agent` | Idempotency store |
| `/var/log/mavora-agent/` | 0755 | `mavora-agent` | Structured logs |

**Agent refuses to start if any secret file is not 0600 or not owned by mavora-agent.**
Error: `AGENT_SECRET_PERMISSION_UNSAFE` → exit non-zero.

---

## Full Field Reference

```yaml
# control_plane: Mavora API base URL (HTTPS only; outbound 443).
# The agent connects outbound to this address. NO inbound port opened.
control_plane: "https://api.mavora.io"

# agent_id: UUID assigned by Mavora when the agent record was created.
# Set by installer from bootstrap response.
agent_id: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# ── Secret file paths (all must be 0600 mavora-agent) ──────────────────────
# Values are NEVER stored inline. Only the FILE PATH is configured here.

# mTLS client certificate (signed by Mavora internal CA).
# Private key was generated on this VPS during install — it NEVER left.
tls_cert_path: "/etc/mavora-agent/client.crt"

# mTLS private key (generated on-VPS; never transmitted).
tls_key_path: "/etc/mavora-agent/client.key"

# Mavora internal CA certificate (used to pin control-plane TLS).
# 0644 — not a secret; used for TLS verification.
ca_cert_path: "/etc/mavora-agent/ca.crt"

# Runtime bearer token (connection_key, received during bootstrap).
# Loaded into memory at startup; NEVER logged.
bearer_path: "/etc/mavora-agent/bearer.token"

# Ed25519 VERIFYING public key from Mavora.
# Agent uses this to VERIFY signed job envelopes.
# The signing PRIVATE key stays at Mavora — the agent cannot forge jobs.
ed25519_public_key_path: "/etc/mavora-agent/signing.pub"

# signing_key_ids: list of accepted key IDs (old + new during rotation grace).
# Updated by rotate.sh during credential rotation.
signing_key_ids:
  - "key-id-1"
  # During rotation grace: both old and new key IDs are listed here.
  # - "key-id-2"

# ── VPS paths ──────────────────────────────────────────────────────────────
# webroot: WordPress Multisite root directory.
# Must be in ReadWritePaths (systemd unit) for WP-CLI write access.
webroot: "/var/www"

# nginx_sites_available / nginx_sites_enabled:
# nginx vhost config directories. Must be in ReadWritePaths.
nginx_sites_available: "/etc/nginx/sites-available"
nginx_sites_enabled: "/etc/nginx/sites-enabled"

# state_dir_path: Local idempotency store (JSON + flock).
# Must be in ReadWritePaths.
state_dir_path: "/var/lib/mavora-agent"

# ── Timing ─────────────────────────────────────────────────────────────────
# heartbeat_interval_sec: How often to POST /agent/v1/heartbeat.
# MUST be ≤30 (spec RC-3). Default: 30.
heartbeat_interval_sec: 30

# poll_timeout_sec: HTTP client timeout for long-poll.
# MUST be >30 (to exceed server hold of ≤30s). Default: 35.
poll_timeout_sec: 35

# ── Optional features ──────────────────────────────────────────────────────
# firewall_enabled: Enable optional IP-allowlist on inbound port 80 (SP-BR-17).
# Default: false (OFF). Only enable on Mavora-provided VPS with known proxy.
# Provisioning does NOT fail if this is false or if firewall application fails.
# NO Cloudflare, NO registrar, NO DNS-provider CIDRs here (Model C).
firewall_enabled: false

# firewall_proxy_cidrs: Proxy CIDR ranges to allowlist on port 80.
# Only used when firewall_enabled=true.
# Example — Customer-managed proxy IPs only:
# firewall_proxy_cidrs:
#   - "203.0.113.0/24"

# max_subsite_limit: Maximum number of subsites this agent will provision.
# Null / not set = unlimited. Set by Mavora from agent record (not usually
# configured here; the agent reads this from admission response).
# max_subsite_limit: 30
```

---

## Environment Variable Overrides

Only PATH overrides are allowed via environment (secret values are never env vars):

| Variable | Config key overridden |
|---|---|
| `MAVORA_AGENT_CONFIG` | Config file path |
| `MAVORA_AGENT_CONTROL_PLANE` | `control_plane` |
| `MAVORA_AGENT_ID` | `agent_id` |
| `MAVORA_AGENT_TLS_CERT_PATH` | `tls_cert_path` |
| `MAVORA_AGENT_TLS_KEY_PATH` | `tls_key_path` |
| `MAVORA_AGENT_BEARER_PATH` | `bearer_path` |
| `MAVORA_AGENT_ED25519_PUBLIC_KEY_PATH` | `ed25519_public_key_path` |
| `MAVORA_AGENT_STATE_DIR` | `state_dir_path` |

---

## What Is NOT in Config

- SSL certificate / ACME / certbot configuration — **out of scope** (Model C: Customer manages SSL)
- Cloudflare, registrar, or DNS-provider API keys — **out of scope** (Model C: Customer manages DNS)
- Inbound port or management listener — **not supported** (agent is outbound-only)
- WP App Passwords — **never stored on disk** (in-memory only, SP-ADR-009)
