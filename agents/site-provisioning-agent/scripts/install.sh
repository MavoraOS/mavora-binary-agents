#!/usr/bin/env bash
# install.sh — Mavora Site Provisioning Agent installer (SP-T-205)
#
# Automated install-token → cert exchange (SP-ADR-008).
# Generates mTLS keypair + CSR ON THIS HOST — private key NEVER leaves this machine.
# Exchanges one-time install token for: signed cert + CA + bearer (connection_key) + Ed25519 pubkey.
#
# Usage:
#   sudo bash install.sh --token-file /path/to/token --control-plane https://api.mavora.io
#   sudo bash install.sh --token <TOKEN>              --control-plane https://api.mavora.io
#   sudo bash install.sh --token-file /path/to/token --control-plane https://api.mavora.io --webroot /var/www/html
#
# Flags:
#   --token <value>          One-time install token (prefer --token-file to keep off shell history)
#   --token-file <path>      Read install token from file (RC-7: keeps token off shell history)
#   --control-plane <url>    Mavora control-plane base URL (HTTPS, port 443)
#   --binary <path>          Use local binary instead of downloading
#   --webroot <path>         WordPress webroot (default: /var/www)
#   --user <name>            Service account name (default: mavora-agent)
#   --nginx-available <path> nginx sites-available (default: /etc/nginx/sites-available)
#   --nginx-enabled <path>   nginx sites-enabled (default: /etc/nginx/sites-enabled)
#   --rotate                 Re-exchange credentials (rotate mode, preserves existing service)
#
# Security invariants:
#   - mTLS keypair generated ON this VPS; private key NEVER transmitted
#   - cert ↔ key verified before service start
#   - sudoers installed ONLY after visudo -c validation
#   - install_token never logged (kept in variable, file deleted after exchange)
#   - secret files stored 0600 owner mavora-agent
#   - idempotent: re-run does not destroy existing valid installation
#
# Model C constraints:
#   - NO SSL/certbot/Let's Encrypt/AOP
#   - NO Cloudflare/registrar/DNS-provider interaction
#   - NO inbound port opened (agent is outbound 443 only)

set -euo pipefail
IFS=$'\n\t'

# ─────────────────────────── constants ──────────────────────────────────────
AGENT_USER="mavora-agent"
AGENT_BIN_DIR="/opt/mavora-agent"
AGENT_BIN="${AGENT_BIN_DIR}/mavora-agent"
HELPER_BIN_DIR="${AGENT_BIN_DIR}/bin"
CONF_DIR="/etc/mavora-agent"
STATE_DIR="/var/lib/mavora-agent"
LOG_DIR="/var/log/mavora-agent"
SYSTEMD_UNIT="/etc/systemd/system/mavora-agent.service"
SUDOERS_DEST="/etc/sudoers.d/mavora-agent"
WEBROOT="/var/www"
NGINX_AVAILABLE="/etc/nginx/sites-available"
NGINX_ENABLED="/etc/nginx/sites-enabled"
INSTALL_TIMEOUT=60  # seconds to wait for first poll → active
ROTATE_GRACE_SEC=900  # 15 minutes

# Key files in CONF_DIR
TLS_KEY="${CONF_DIR}/client.key"
TLS_CERT="${CONF_DIR}/client.crt"
CA_CERT="${CONF_DIR}/ca.crt"
BEARER_FILE="${CONF_DIR}/bearer.token"
ED25519_PUB="${CONF_DIR}/signing.pub"

# ─────────────────────────── logging ────────────────────────────────────────
log()  { echo "[install] $*"; }
info() { echo "[install] INFO:  $*"; }
warn() { echo "[install] WARN:  $*" >&2; }
fail() { echo "[install] ERROR: $*" >&2; exit 1; }

# ─────────────────────────── parse flags ────────────────────────────────────
INSTALL_TOKEN=""
TOKEN_FILE=""
CONTROL_PLANE=""
LOCAL_BINARY=""
ROTATE=false

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --token)        INSTALL_TOKEN="${2:-}"; shift 2 ;;
            --token-file)   TOKEN_FILE="${2:-}"; shift 2 ;;
            --control-plane) CONTROL_PLANE="${2:-}"; shift 2 ;;
            --binary)       LOCAL_BINARY="${2:-}"; shift 2 ;;
            --webroot)      WEBROOT="${2:-}"; shift 2 ;;
            --user)         AGENT_USER="${2:-}"; shift 2 ;;
            --nginx-available) NGINX_AVAILABLE="${2:-}"; shift 2 ;;
            --nginx-enabled)   NGINX_ENABLED="${2:-}"; shift 2 ;;
            --rotate)       ROTATE=true; shift ;;
            *) fail "Unknown flag: $1 (see comments for usage)" ;;
        esac
    done
    # Load token from file if specified (RC-7: keeps token off shell history)
    if [[ -n "$TOKEN_FILE" ]]; then
        [[ -f "$TOKEN_FILE" ]] || fail "--token-file $TOKEN_FILE does not exist"
        INSTALL_TOKEN="$(cat "$TOKEN_FILE")"
        rm -f "$TOKEN_FILE"
        info "Install token loaded from file (file deleted)."
    fi
    [[ -n "$INSTALL_TOKEN" ]] || fail "Required: --token <value> or --token-file <path>"
    [[ -n "$CONTROL_PLANE" ]] || fail "Required: --control-plane <url>"
}

# ─────────────────────────── step 1: OS check ───────────────────────────────
check_os() {
    if [[ ! -f /etc/os-release ]]; then
        fail "Cannot detect OS. Supported: Ubuntu 22.04, Ubuntu 24.04."
    fi
    # shellcheck source=/dev/null
    source /etc/os-release
    if [[ "$ID" != "ubuntu" ]]; then
        fail "Unsupported OS: $ID. Supported: Ubuntu 22.04, Ubuntu 24.04."
    fi
    case "$VERSION_ID" in
        22.04|24.04) info "OS check PASS: Ubuntu $VERSION_ID" ;;
        *) fail "Unsupported Ubuntu version: $VERSION_ID. Supported: 22.04, 24.04." ;;
    esac
}

# ─────────────────────────── step 2: prerequisites ──────────────────────────
check_prereqs() {
    local missing=()
    for cmd in openssl sudo systemctl visudo curl; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        fail "Missing required commands: ${missing[*]}. Install them and retry."
    fi
    # Warn (don't fail) if WP stack not present — Phase 1 assumes stack pre-installed
    for cmd in wp nginx php-fpm; do
        command -v "$cmd" &>/dev/null || \
            warn "Optional stack component '$cmd' not found — install before running agents."
    done
    info "Prerequisites check PASS."
}

# ─────────────────────────── step 3: create user ────────────────────────────
create_user() {
    if id "$AGENT_USER" &>/dev/null; then
        info "User $AGENT_USER already exists — skipping."
    else
        useradd --system --no-create-home --shell /usr/sbin/nologin "$AGENT_USER"
        info "Created system user: $AGENT_USER (no home, nologin)."
    fi
}

# ─────────────────────────── step 4: directories ────────────────────────────
create_dirs() {
    install -d -m 0700 -o "$AGENT_USER" -g "$AGENT_USER" "$CONF_DIR"
    install -d -m 0755 -o "$AGENT_USER" -g "$AGENT_USER" "$STATE_DIR"
    install -d -m 0755 -o "$AGENT_USER" -g "$AGENT_USER" "$LOG_DIR"
    install -d -m 0755 -o root -g root "$AGENT_BIN_DIR"
    install -d -m 0755 -o root -g root "$HELPER_BIN_DIR"
    info "Directories created."
}

# ─────────────────────────── step 5: install binary ─────────────────────────
install_binary() {
    if [[ -n "$LOCAL_BINARY" ]]; then
        [[ -f "$LOCAL_BINARY" ]] || fail "--binary path $LOCAL_BINARY does not exist"
        install -m 0755 -o root -g root "$LOCAL_BINARY" "$AGENT_BIN"
        info "Binary installed from local path: $LOCAL_BINARY"
    else
        # In production this fetches from the control-plane release URL.
        # The CI dry-run test passes --binary, so this path is tested separately.
        ARCH="$(uname -m)"
        case "$ARCH" in
            x86_64) GOARCH="amd64" ;;
            aarch64) GOARCH="arm64" ;;
            *) fail "Unsupported architecture: $ARCH" ;;
        esac
        RELEASE_URL="${CONTROL_PLANE}/releases/latest/mavora-agent-linux-${GOARCH}"
        info "Downloading binary from $RELEASE_URL ..."
        curl --fail --silent --show-error --location \
            --max-time 120 \
            -o "$AGENT_BIN" \
            "$RELEASE_URL"
        chmod 0755 "$AGENT_BIN"
        chown root:root "$AGENT_BIN"
        info "Binary installed to $AGENT_BIN"
    fi
}

# ─────────────────────────── step 6: generate mTLS keypair + CSR ────────────
# SECURITY: private key generated ON this VPS; NEVER transmitted anywhere.
generate_mtls_keypair() {
    local key_tmp cert_tmp csr_file agent_id hostname_cn
    hostname_cn="$(hostname -f)"
    agent_id="$(generate_agent_id)"
    key_tmp="${CONF_DIR}/client.key.tmp"
    csr_file="${CONF_DIR}/client.csr"

    info "Generating mTLS keypair on this VPS (private key stays here)..."

    # Generate EC private key (P-256 — compact, strong)
    openssl ecparam -name prime256v1 -genkey -noout -out "$key_tmp"
    chmod 0600 "$key_tmp"
    chown "$AGENT_USER:$AGENT_USER" "$key_tmp"

    # Build CSR — CN = agent_id + hostname
    openssl req -new \
        -key "$key_tmp" \
        -out "$csr_file" \
        -subj "/CN=${agent_id}/O=MavoraAgent/OU=${hostname_cn}" \
        -sha256

    chmod 0600 "$csr_file"
    echo "$csr_file"
    # Export agent_id so the bootstrap step can use it
    AGENT_ID_GENERATED="$agent_id"
}

generate_agent_id() {
    # Use openssl for portability (no python/uuid dep required)
    openssl rand -hex 16 | sed 's/\(.\{8\}\)\(.\{4\}\)\(.\{4\}\)\(.\{4\}\)\(.\{12\}\)/\1-\2-\3-\4-\5/'
}

# ─────────────────────────── step 7: bootstrap exchange ──────────────────────
# POST {install_token, csr} → {signed_cert, ca, connection_key(once), ed25519_pubkey, signing_key_id}
# NEVER logs the install_token or any returned secrets.
bootstrap_exchange() {
    local csr_file="$1"
    local key_tmp="${CONF_DIR}/client.key.tmp"
    local csr_pem response_file

    csr_pem="$(cat "$csr_file")"
    response_file="$(mktemp /tmp/mavora-bootstrap-XXXXXX.json)"
    # Ensure temp response is deleted even on error
    trap 'rm -f "$response_file"' RETURN

    info "Exchanging install token for credentials (bootstrap)..."

    # Build JSON payload — install_token is NEVER logged (only used in this curl call)
    local payload
    payload="$(printf '{"install_token":%s,"csr":%s}' \
        "$(printf '%s' "$INSTALL_TOKEN" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().strip()))')" \
        "$(printf '%s' "$csr_pem" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')")"

    local http_code
    http_code="$(curl \
        --fail \
        --silent \
        --show-error \
        --max-time 30 \
        --write-out "%{http_code}" \
        --output "$response_file" \
        -X POST \
        -H "Content-Type: application/json" \
        "${CONTROL_PLANE}/agent/v1/bootstrap" \
        --data-binary "$payload" 2>&1)" || {
            fail "Bootstrap request to ${CONTROL_PLANE}/agent/v1/bootstrap failed (HTTP ${http_code:-unknown}). Check: egress 443 open, token not expired, control-plane reachable."
        }

    if [[ "$http_code" != "200" && "$http_code" != "201" ]]; then
        fail "Bootstrap returned HTTP $http_code. Check token validity and control-plane URL."
    fi

    # Parse response fields — never log raw values
    local signed_cert ca_cert connection_key ed25519_pubkey signing_key_id
    signed_cert="$(python3 -c "import json,sys; d=json.load(open('$response_file')); print(d.get('signed_cert',''))")"
    ca_cert="$(python3 -c "import json,sys; d=json.load(open('$response_file')); print(d.get('ca',''))")"
    connection_key="$(python3 -c "import json,sys; d=json.load(open('$response_file')); print(d.get('connection_key',''))")"
    ed25519_pubkey="$(python3 -c "import json,sys; d=json.load(open('$response_file')); print(d.get('ed25519_pubkey',''))")"
    signing_key_id="$(python3 -c "import json,sys; d=json.load(open('$response_file')); print(d.get('signing_key_id',''))")"

    [[ -n "$signed_cert" ]] || fail "Bootstrap response missing signed_cert."
    [[ -n "$ca_cert" ]] || fail "Bootstrap response missing ca (CA certificate)."
    [[ -n "$connection_key" ]] || fail "Bootstrap response missing connection_key."
    [[ -n "$ed25519_pubkey" ]] || fail "Bootstrap response missing ed25519_pubkey."

    # Store credentials — all 0600 owner mavora-agent (never log values)
    printf '%s\n' "$signed_cert" > "$TLS_CERT"
    printf '%s\n' "$ca_cert"     > "$CA_CERT"
    printf '%s\n' "$connection_key" > "$BEARER_FILE"
    printf '%s\n' "$ed25519_pubkey" > "$ED25519_PUB"

    # Promote temp key to final location
    mv "$key_tmp" "$TLS_KEY"

    chmod 0600 "$TLS_KEY" "$TLS_CERT" "$BEARER_FILE" "$ED25519_PUB"
    chmod 0644 "$CA_CERT"
    chown "$AGENT_USER:$AGENT_USER" "$TLS_KEY" "$TLS_CERT" "$CA_CERT" "$BEARER_FILE" "$ED25519_PUB"

    # Store signing_key_id for config (not secret)
    echo "$signing_key_id" > "${CONF_DIR}/signing_key_id"
    chmod 0644 "${CONF_DIR}/signing_key_id"

    # Clean up CSR (no longer needed after exchange)
    rm -f "$csr_file"
    # Clear the token from shell memory
    unset INSTALL_TOKEN connection_key

    info "Bootstrap PASS: credentials stored (secrets 0600)."
}

# ─────────────────────────── step 8: verify cert ↔ key ──────────────────────
# CRITICAL: verify the returned cert matches the local private key before starting.
verify_cert_key_match() {
    info "Verifying cert ↔ key match (pre-start safety check)..."
    local cert_pubkey key_pubkey
    cert_pubkey="$(openssl x509 -in "$TLS_CERT" -pubkey -noout 2>/dev/null)" \
        || fail "Cannot extract pubkey from cert: $TLS_CERT"
    key_pubkey="$(openssl ec -in "$TLS_KEY" -pubout 2>/dev/null)" \
        || fail "Cannot extract pubkey from key: $TLS_KEY"

    if [[ "$cert_pubkey" != "$key_pubkey" ]]; then
        fail "CERT ↔ KEY MISMATCH: the signed cert returned by Mavora does not match the local private key. Do NOT start the agent. Re-run the installer."
    fi
    info "Cert ↔ key match verified PASS."
}

# ─────────────────────────── step 9: write config ────────────────────────────
write_config() {
    local signing_key_id=""
    [[ -f "${CONF_DIR}/signing_key_id" ]] && signing_key_id="$(cat "${CONF_DIR}/signing_key_id")"

    cat > "${CONF_DIR}/config.yaml" <<CONFIG
# /etc/mavora-agent/config.yaml — generated by install.sh
# DO NOT EDIT MANUALLY — re-run the installer to regenerate.
# File permissions: 0600 (set by installer)
control_plane: "${CONTROL_PLANE}"
agent_id: "${AGENT_ID_GENERATED:-REPLACE_WITH_AGENT_UUID}"
tls_cert_path: "${TLS_CERT}"
tls_key_path: "${TLS_KEY}"
ca_cert_path: "${CA_CERT}"
bearer_path: "${BEARER_FILE}"
ed25519_public_key_path: "${ED25519_PUB}"
signing_key_ids:
  - "${signing_key_id}"
webroot: "${WEBROOT}"
nginx_sites_available: "${NGINX_AVAILABLE}"
nginx_sites_enabled: "${NGINX_ENABLED}"
state_dir_path: "${STATE_DIR}"
heartbeat_interval_sec: 30
poll_timeout_sec: 35
firewall_enabled: false
CONFIG
    chmod 0600 "${CONF_DIR}/config.yaml"
    chown "$AGENT_USER:$AGENT_USER" "${CONF_DIR}/config.yaml"
    info "Config written: ${CONF_DIR}/config.yaml (0600)"
}

# ─────────────────────────── step 10: install systemd unit ──────────────────
install_systemd() {
    local unit_src
    unit_src="$(dirname "$(realpath "$0")")/../deploy/systemd/mavora-agent.service"

    # If running from a release bundle, unit is alongside install.sh
    if [[ ! -f "$unit_src" ]]; then
        unit_src="$(dirname "$(realpath "$0")")/mavora-agent.service"
    fi
    [[ -f "$unit_src" ]] || fail "Cannot find mavora-agent.service (expected at deploy/systemd/ or alongside install.sh)"

    # Inject real paths into unit (replace PLACEHOLDER_ values)
    sed \
        -e "s|PLACEHOLDER_BINARY_PATH|${AGENT_BIN} --config ${CONF_DIR}/config.yaml|g" \
        -e "s|PLACEHOLDER_WEBROOT|${WEBROOT}|g" \
        -e "s|PLACEHOLDER_NGINX_SITES_AVAILABLE|${NGINX_AVAILABLE}|g" \
        -e "s|PLACEHOLDER_NGINX_SITES_ENABLED|${NGINX_ENABLED}|g" \
        -e "s|PLACEHOLDER_STATE_DIR|${STATE_DIR}|g" \
        "$unit_src" > "$SYSTEMD_UNIT"

    chmod 0644 "$SYSTEMD_UNIT"
    info "Systemd unit installed: $SYSTEMD_UNIT"
}

# ─────────────────────────── step 11: install sudoers (visudo-gated) ────────
# CRITICAL: ONLY install if visudo -c passes. Broken sudoers → refuse install.
install_sudoers() {
    local sudoers_src
    sudoers_src="$(dirname "$(realpath "$0")")/../deploy/sudoers/mavora-agent"
    if [[ ! -f "$sudoers_src" ]]; then
        sudoers_src="$(dirname "$(realpath "$0")")/sudoers.d-mavora-agent"
    fi
    [[ -f "$sudoers_src" ]] || fail "Cannot find sudoers file (expected at deploy/sudoers/mavora-agent)"

    # Install helpers first (sudoers references them by path)
    install_helpers

    # Validate before installing (refuse on any syntax error)
    if ! visudo -c -f "$sudoers_src" &>/dev/null; then
        fail "visudo -c FAILED for $sudoers_src — refusing to install sudoers. This is a bug; please report."
    fi

    install -m 0440 -o root -g root "$sudoers_src" "$SUDOERS_DEST"
    info "Sudoers installed after visudo -c PASS: $SUDOERS_DEST"
}

# Install helper scripts (root-owned 0755, validate argv)
install_helpers() {
    local helper_src_dir
    helper_src_dir="$(dirname "$(realpath "$0")")/../deploy/helpers"
    if [[ -d "$helper_src_dir" ]]; then
        for helper in write-vhost wp-safe; do
            if [[ -f "${helper_src_dir}/${helper}" ]]; then
                install -m 0755 -o root -g root "${helper_src_dir}/${helper}" "${HELPER_BIN_DIR}/${helper}"
                info "Helper installed: ${HELPER_BIN_DIR}/${helper} (root:root 0755)"
            else
                warn "Helper not found: ${helper_src_dir}/${helper} — skipping"
            fi
        done
    else
        warn "deploy/helpers/ directory not found — helpers not installed"
    fi
}

# ─────────────────────────── step 12: enable + start ────────────────────────
enable_start_service() {
    systemctl daemon-reload
    systemctl enable --now mavora-agent
    info "Service enabled and started."
}

# ─────────────────────────── step 13: verify first poll → active ─────────────
verify_active() {
    info "Waiting for agent to make first poll and flip to active (timeout: ${INSTALL_TIMEOUT}s)..."
    local end_time elapsed
    end_time=$(( $(date +%s) + INSTALL_TIMEOUT ))

    while [[ $(date +%s) -lt $end_time ]]; do
        if systemctl is-active --quiet mavora-agent; then
            # Check agent logs for successful poll indication
            if journalctl -u mavora-agent --since="5 minutes ago" -n 20 2>/dev/null \
               | grep -q '"status":"poll_ack"\|"event":"poll_lease"\|active'; then
                info "PASS: agent is polling. Verify 'active' status on Mavora UI."
                return 0
            fi
        fi
        sleep 3
    done

    warn "Timed out waiting for first poll. Check:"
    warn "  - systemctl status mavora-agent"
    warn "  - journalctl -u mavora-agent -n 50"
    warn "  - Egress port 443 open to $CONTROL_PLANE"
    warn "  - Clock NTP-synced (run: timedatectl)"
    warn "See TROUBLESHOOTING.md: install_timeout vs unreachable."
}

# ─────────────────────────── step 14: print next steps ──────────────────────
print_next_steps() {
    cat <<EOF

[install] ─────────────────────────────────────────────────────────────────────
[install] INSTALLATION COMPLETE
[install] ─────────────────────────────────────────────────────────────────────
[install]  1. Verify status:  systemctl status mavora-agent
[install]  2. View logs:      journalctl -u mavora-agent -f
[install]  3. Mavora UI:      Confirm agent shows "active" at Agents → This Agent
[install]  4. Diagnostics:    sudo bash ${0%/*}/doctor.sh
[install]
[install]  ROTATE CREDENTIALS (~90 days or if compromised):
[install]    sudo bash ${0%/*}/rotate.sh --control-plane ${CONTROL_PLANE}
[install]
[install]  UNINSTALL (does NOT remove WP/nginx stack):
[install]    sudo bash ${0%/*}/uninstall.sh
[install]    Then: revoke agent on Mavora UI
[install]
[install]  TROUBLESHOOTING: see docs/TROUBLESHOOTING.md
[install]    install_timeout → check egress/clock/perm
[install]    unreachable     → agent ran, then lost heartbeat
[install] ─────────────────────────────────────────────────────────────────────
EOF
}

# ─────────────────────────── main ───────────────────────────────────────────
main() {
    [[ "$EUID" -eq 0 ]] || fail "This installer must be run as root (sudo)."

    parse_args "$@"

    if [[ "$ROTATE" == "true" ]]; then
        # Delegate to rotate.sh for key rotation
        exec "$(dirname "$(realpath "$0")")/rotate.sh" \
            --control-plane "$CONTROL_PLANE" \
            --token "$INSTALL_TOKEN"
    fi

    log "=== Mavora Site Provisioning Agent — Installer ==="
    log "Control plane: $CONTROL_PLANE"
    log "User: $AGENT_USER | Webroot: $WEBROOT"
    log "SECURITY: mTLS private key will be generated here and NEVER transmitted."

    check_os
    check_prereqs
    create_user
    create_dirs
    install_binary

    # Generate keypair + CSR (private key stays on this VPS)
    csr_file="$(generate_mtls_keypair)"

    # Exchange token + CSR for credentials (token used once, cleared from memory)
    bootstrap_exchange "$csr_file"

    # CRITICAL: verify cert matches key before starting
    verify_cert_key_match

    write_config
    install_systemd
    install_sudoers
    enable_start_service
    verify_active
    print_next_steps
}

main "$@"
