#!/usr/bin/env bash
# uninstall.sh — Remove Mavora Site Provisioning Agent (SP-T-215)
#
# DOES NOT touch WP/nginx/php-fpm stack (Customer-managed — Model C).
# Idempotent: missing files/units are silently skipped.
# Prompts user to revoke agent credentials on Mavora UI.
#
# Usage:
#   sudo bash uninstall.sh [--yes]
#   --yes  : skip interactive confirmation

set -euo pipefail
IFS=$'\n\t'

AGENT_USER="mavora-agent"
AGENT_BIN_DIR="/opt/mavora-agent"
CONF_DIR="/etc/mavora-agent"
STATE_DIR="/var/lib/mavora-agent"
LOG_DIR="/var/log/mavora-agent"
SYSTEMD_UNIT="/etc/systemd/system/mavora-agent.service"
SUDOERS_DEST="/etc/sudoers.d/mavora-agent"

log()  { echo "[uninstall] $*"; }
fail() { echo "[uninstall] ERROR: $*" >&2; exit 1; }

YES=false
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --yes) YES=true; shift ;;
            *) fail "Unknown flag: $1" ;;
        esac
    done
}

confirm() {
    if [[ "$YES" == "true" ]]; then return 0; fi
    echo ""
    echo "This will remove the Mavora agent binary, config, credentials, and systemd unit."
    echo "It will NOT remove WordPress, nginx, php-fpm, or site data."
    echo ""
    read -rp "Proceed? [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] || { log "Aborted."; exit 0; }
}

remove_unit() {
    if systemctl is-active --quiet mavora-agent 2>/dev/null; then
        systemctl disable --now mavora-agent 2>/dev/null || true
        log "Service disabled and stopped."
    elif systemctl is-enabled --quiet mavora-agent 2>/dev/null; then
        systemctl disable mavora-agent 2>/dev/null || true
        log "Service disabled."
    else
        log "Service not active — skipping disable."
    fi

    rm -f "$SYSTEMD_UNIT"
    systemctl daemon-reload 2>/dev/null || true
    log "Systemd unit removed."
}

remove_sudoers() {
    rm -f "$SUDOERS_DEST"
    log "Sudoers removed (idempotent)."
}

remove_binaries_and_helpers() {
    rm -rf "$AGENT_BIN_DIR"
    log "Agent binary and helpers removed: $AGENT_BIN_DIR"
}

remove_secrets() {
    # Remove secret dir (credentials, config, keys)
    # State dir: remove by default (ask user)
    rm -rf "$CONF_DIR"
    log "Credential directory removed: $CONF_DIR (secrets wiped)"
    rm -rf "$STATE_DIR"
    log "State directory removed: $STATE_DIR"
    rm -rf "$LOG_DIR"
    log "Log directory removed: $LOG_DIR"
}

prompt_ui_revoke() {
    echo ""
    echo "─────────────────────────────────────────────────────────────────────"
    echo " ACTION REQUIRED: Revoke agent credentials on Mavora UI"
    echo "─────────────────────────────────────────────────────────────────────"
    echo " Log in to the Mavora dashboard → Agents → [This Agent] → Revoke"
    echo " This invalidates the bearer token, mTLS certificate, and Ed25519"
    echo " public key so this agent can never authenticate again."
    echo ""
    echo " If you skip revocation, the credentials remain valid until they"
    echo " expire. For security-sensitive uninstalls, revoke immediately."
    echo "─────────────────────────────────────────────────────────────────────"
}

main() {
    [[ "$EUID" -eq 0 ]] || fail "uninstall.sh must be run as root (sudo)."
    parse_args "$@"

    log "=== Mavora Site Provisioning Agent — Uninstaller ==="
    log "NOTE: WP/nginx/php-fpm stack will NOT be modified."

    confirm
    remove_unit
    remove_sudoers
    remove_binaries_and_helpers
    remove_secrets

    prompt_ui_revoke
    log "Uninstall complete."
}

main "$@"
