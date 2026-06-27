#!/usr/bin/env bash
# doctor.sh — Read-only diagnostics for Mavora Site Provisioning Agent (SP-T-215)
#
# Checks:
#   1. File permissions (/etc/mavora-agent/* = 0600 / 0700)
#   2. Egress to control-plane port 443
#   3. NTP clock sync (job envelope ±5min — if skewed, jobs get rejected)
#   4. Service active (systemctl)
#   5. Stack info (nginx/WP-CLI/php-fpm presence + nginx -t)
#   6. Config parse + required fields
#
# SECURITY: Reads no secret values. Prints only paths, modes, and statuses.
# NEVER prints key material, token values, or bearer content.

set -uo pipefail
IFS=$'\n\t'

CONF_DIR="/etc/mavora-agent"
STATE_DIR="/var/lib/mavora-agent"
PASS=0
FAIL=0
WARN=0

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}PASS${NC}  $*"; PASS=$(( PASS + 1 )); }
fail_check() { echo -e "  ${RED}FAIL${NC}  $*"; FAIL=$(( FAIL + 1 )); }
warn_check() { echo -e "  ${YELLOW}WARN${NC}  $*"; WARN=$(( WARN + 1 )); }

header() { echo ""; echo "── $* ──"; }

# ─────────────────────────── check 1: permissions ───────────────────────────
check_permissions() {
    header "File Permissions"

    if [[ ! -d "$CONF_DIR" ]]; then
        fail_check "Config directory $CONF_DIR does not exist (agent not installed?)"
        return
    fi

    # Check dir itself is 0700
    local dir_mode
    dir_mode="$(stat -c '%a' "$CONF_DIR" 2>/dev/null || echo "unknown")"
    if [[ "$dir_mode" == "700" ]]; then
        pass "$CONF_DIR mode=$dir_mode"
    else
        fail_check "$CONF_DIR mode=$dir_mode (want 700) — AGENT_SECRET_PERMISSION_UNSAFE"
    fi

    # Check secret files are 0600 (don't print values — only path+mode)
    for secret_file in client.key client.crt bearer.token signing.pub config.yaml; do
        local fpath="${CONF_DIR}/${secret_file}"
        if [[ ! -f "$fpath" ]]; then
            warn_check "$fpath not found (may be OK if agent not yet bootstrapped)"
            continue
        fi
        local mode owner
        mode="$(stat -c '%a' "$fpath" 2>/dev/null || echo "unknown")"
        owner="$(stat -c '%U' "$fpath" 2>/dev/null || echo "unknown")"
        if [[ "$mode" == "600" ]]; then
            pass "$secret_file mode=$mode owner=$owner"
        else
            fail_check "$secret_file mode=$mode (want 600) owner=$owner — AGENT_SECRET_PERMISSION_UNSAFE"
        fi
    done

    # CA cert is 0644 (not secret)
    local ca_path="${CONF_DIR}/ca.crt"
    if [[ -f "$ca_path" ]]; then
        local ca_mode
        ca_mode="$(stat -c '%a' "$ca_path" 2>/dev/null || echo "unknown")"
        pass "ca.crt mode=$ca_mode (CA is not a secret)"
    fi
}

# ─────────────────────────── check 2: egress to control-plane ───────────────
check_egress() {
    header "Egress (outbound 443 to control-plane)"

    # Read control-plane from config (path only printed, not values)
    local cp_url
    if [[ -f "${CONF_DIR}/config.yaml" ]]; then
        cp_url="$(grep '^control_plane:' "${CONF_DIR}/config.yaml" 2>/dev/null | awk '{print $2}' | tr -d '"' || echo "")"
    else
        cp_url=""
    fi

    if [[ -z "$cp_url" ]]; then
        warn_check "Cannot read control_plane from config — skipping egress check"
        return
    fi

    # Extract host from URL (strip protocol + path)
    local cp_host
    cp_host="$(echo "$cp_url" | sed 's|https\?://||' | cut -d/ -f1 | cut -d: -f1)"

    if curl --silent --max-time 5 --output /dev/null --write-out "%{http_code}" \
        "https://${cp_host}/livez" 2>/dev/null | grep -qE "^[2-5]"; then
        pass "Egress to $cp_host:443 reachable"
    else
        fail_check "Cannot reach $cp_host:443. Check: ufw/iptables allow outbound 443; NAT/proxy config."
    fi
}

# ─────────────────────────── check 3: NTP / clock sync ─────────────────────
check_clock() {
    header "Clock / NTP Sync"
    # Ed25519 envelope uses issued_at ±5min; skewed clock causes job rejection

    if command -v timedatectl &>/dev/null; then
        local ntp_sync
        ntp_sync="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo "unknown")"
        if [[ "$ntp_sync" == "yes" ]]; then
            pass "NTP synchronized (timedatectl)"
        else
            fail_check "NTP NOT synchronized ($ntp_sync). Clock skew > 5min causes job signature rejection. Run: timedatectl set-ntp true"
        fi
    else
        warn_check "timedatectl not available — cannot verify NTP sync. Ensure NTP is configured."
    fi

    # Sanity: current UTC time
    echo "         Current UTC: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
}

# ─────────────────────────── check 4: service status ────────────────────────
check_service() {
    header "Service Status"

    if systemctl is-active --quiet mavora-agent 2>/dev/null; then
        pass "mavora-agent is active (running)"
        # Show recent logs (no secret values — just status lines)
        echo "         Recent log (last 5 lines):"
        journalctl -u mavora-agent -n 5 --no-pager 2>/dev/null | sed 's/^/           /' || true
    elif systemctl is-enabled --quiet mavora-agent 2>/dev/null; then
        fail_check "mavora-agent is enabled but NOT active. Run: systemctl start mavora-agent"
        echo "         Last exit status:"
        systemctl show mavora-agent -p ExecMainStatus --no-pager 2>/dev/null | sed 's/^/           /' || true
    else
        fail_check "mavora-agent service not found or not enabled (agent not installed?)"
    fi
}

# ─────────────────────────── check 5: stack info ────────────────────────────
check_stack() {
    header "Stack Info (WP/nginx/php-fpm)"

    for cmd in nginx wp php-fpm; do
        if command -v "$cmd" &>/dev/null; then
            pass "$cmd found: $(command -v "$cmd")"
        else
            warn_check "$cmd not found — agent needs nginx + WP-CLI + php-fpm pre-installed"
        fi
    done

    # nginx config test (read-only)
    if command -v nginx &>/dev/null; then
        if nginx -t 2>/dev/null; then
            pass "nginx -t PASS (config valid)"
        else
            fail_check "nginx -t FAIL — run 'nginx -t' for details"
        fi
    fi

    # Check if nginx is active
    if systemctl is-active --quiet nginx 2>/dev/null; then
        pass "nginx service is active"
    else
        warn_check "nginx service is not active"
    fi
}

# ─────────────────────────── check 6: config parse ──────────────────────────
check_config() {
    header "Config Parse"

    local cfg="${CONF_DIR}/config.yaml"
    if [[ ! -f "$cfg" ]]; then
        fail_check "Config not found: $cfg (agent not installed?)"
        return
    fi

    # Check required fields are present (don't print values)
    local required=(control_plane agent_id tls_cert_path tls_key_path bearer_path
                     ed25519_public_key_path webroot)
    for field in "${required[@]}"; do
        if grep -q "^${field}:" "$cfg"; then
            pass "config.$field is set"
        else
            fail_check "config.$field is MISSING — AGENT_CONFIG_INVALID"
        fi
    done
}

# ─────────────────────────── summary ────────────────────────────────────────
print_summary() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo " Doctor Summary"
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "  ${GREEN}PASS${NC}: $PASS   ${RED}FAIL${NC}: $FAIL   ${YELLOW}WARN${NC}: $WARN"
    echo ""
    if [[ $FAIL -gt 0 ]]; then
        echo " Action required: fix FAIL items before running the agent."
        echo " See docs/TROUBLESHOOTING.md for decision trees."
    elif [[ $WARN -gt 0 ]]; then
        echo " No blocking issues. Review WARN items for completeness."
    else
        echo " All checks passed."
    fi
    echo "═══════════════════════════════════════════════════════════════"
    [[ $FAIL -eq 0 ]]  # exit non-zero if any FAIL
}

main() {
    echo "Mavora Site Provisioning Agent — Doctor (read-only diagnostics)"
    echo "SECURITY: This tool prints NO secret values, only paths and statuses."
    echo ""

    check_permissions
    check_egress
    check_clock
    check_service
    check_stack
    check_config
    print_summary
}

main "$@"
