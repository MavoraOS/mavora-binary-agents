#!/usr/bin/env bash
# rotate.sh — Re-exchange mTLS/bearer/Ed25519 credentials (SP-T-214)
#
# Generates a NEW mTLS keypair + CSR ON THIS VPS — private key NEVER transmitted.
# Exchanges for new signed cert + bearer + Ed25519 pubkey.
# Grace window: agent holds BOTH old and new Ed25519 public keys for GRACE_SECONDS
# (default 15 min = 900s) so in-flight jobs signed with the old key still verify.
#
# Usage:
#   sudo bash rotate.sh --control-plane https://api.mavora.io
#
# When to rotate:
#   - Every ~90 days (scheduled maintenance)
#   - Immediately if credentials suspected compromised
#   - After server migration / VPS rebuild
#
# SECURITY: This script generates a NEW keypair on-VPS. Old private key is
# overwritten only AFTER the new cert is verified against the new key.
# Bearer and Ed25519 public key are updated; old Ed25519 public is kept
# for the grace window then removed.

set -euo pipefail
IFS=$'\n\t'

AGENT_USER="mavora-agent"
CONF_DIR="/etc/mavora-agent"
AGENT_BIN_DIR="/opt/mavora-agent"
TLS_KEY="${CONF_DIR}/client.key"
TLS_CERT="${CONF_DIR}/client.crt"
CA_CERT="${CONF_DIR}/ca.crt"
BEARER_FILE="${CONF_DIR}/bearer.token"
ED25519_PUB="${CONF_DIR}/signing.pub"
ED25519_OLD="${CONF_DIR}/signing.pub.old"
GRACE_SECONDS=900  # 15 minutes (config-tunable)

log()  { echo "[rotate] $*"; }
info() { echo "[rotate] INFO:  $*"; }
warn() { echo "[rotate] WARN:  $*" >&2; }
fail() { echo "[rotate] ERROR: $*" >&2; exit 1; }

parse_args() {
    CONTROL_PLANE=""
    INSTALL_TOKEN=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --control-plane) CONTROL_PLANE="${2:-}"; shift 2 ;;
            --token)         INSTALL_TOKEN="${2:-}"; shift 2 ;;
            --token-file)
                local tf="${2:-}"
                [[ -f "$tf" ]] || fail "--token-file $tf does not exist"
                INSTALL_TOKEN="$(cat "$tf")"
                rm -f "$tf"
                shift 2 ;;
            --grace-seconds) GRACE_SECONDS="${2:-900}"; shift 2 ;;
            *) fail "Unknown flag: $1" ;;
        esac
    done
    [[ -n "$CONTROL_PLANE" ]] || {
        # Try to read from existing config
        if [[ -f "${CONF_DIR}/config.yaml" ]]; then
            CONTROL_PLANE="$(grep '^control_plane:' "${CONF_DIR}/config.yaml" | awk '{print $2}' | tr -d '"')"
        fi
    }
    [[ -n "$CONTROL_PLANE" ]] || fail "Required: --control-plane <url> (or config.yaml with control_plane set)"
    [[ -n "$INSTALL_TOKEN" ]] || fail "Required: --token <value> or --token-file <path> (new rotate token from Mavora UI)"
}

generate_new_keypair() {
    local key_new="${CONF_DIR}/client.key.new"
    local csr_new="${CONF_DIR}/client.csr.new"
    local hostname_cn agent_id

    hostname_cn="$(hostname -f)"
    agent_id="$(grep '^agent_id:' "${CONF_DIR}/config.yaml" | awk '{print $2}' | tr -d '"')"
    [[ -n "$agent_id" ]] || fail "Cannot read agent_id from config.yaml"

    info "Generating new mTLS keypair on this VPS (private key stays here)..."
    openssl ecparam -name prime256v1 -genkey -noout -out "$key_new"
    chmod 0600 "$key_new"
    chown "$AGENT_USER:$AGENT_USER" "$key_new"

    openssl req -new \
        -key "$key_new" \
        -out "$csr_new" \
        -subj "/CN=${agent_id}/O=MavoraAgent/OU=${hostname_cn}" \
        -sha256
    chmod 0600 "$csr_new"
    echo "$csr_new"
    NEW_KEY_PATH="$key_new"
}

# Embedded verbatim from scripts/lib/bootstrap-response.sh (same block as install.sh: both read the same bootstrap answer);
# tests/bootstrap_scripts_test.go fails if this copy differs from the source.
# BEGIN bootstrap-response
# bootstrap_field <response-file> <member>: prints one member of the (unwrapped) answer, empty when absent or not a string. Never logs it.
bootstrap_field() {
    python3 - "$1" "$2" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
inner = d.get('data')
if isinstance(inner, dict):
    d = inner
v = d.get(sys.argv[2], '')
sys.stdout.write(v if isinstance(v, str) else '')
PY
}

# bootstrap_ed25519_pem <base64url>: prints the PKIX PEM of a raw 32-byte Ed25519 public key; non-zero (and a message) when it is not 32 bytes.
bootstrap_ed25519_pem() {
    printf '%s' "$1" | python3 -c '
import base64, binascii, sys, textwrap
b64 = sys.stdin.read().strip()
try:
    raw = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
except (binascii.Error, ValueError):
    sys.stderr.write("ed25519 pubkey is not base64url\n"); sys.exit(1)
if len(raw) != 32:
    sys.stderr.write("ed25519 pubkey is %d bytes, want 32\n" % len(raw)); sys.exit(1)
der = bytes.fromhex("302a300506032b6570032100") + raw
print("-----BEGIN PUBLIC KEY-----")
print("\n".join(textwrap.wrap(base64.b64encode(der).decode(), 64)))
print("-----END PUBLIC KEY-----")
'
}

# parse_bootstrap_response <response-file>: sets BR_SIGNED_CERT BR_CA BR_CONNECTION_KEY BR_ED25519_PEM BR_SIGNING_KEY_ID.
# Non-zero (message on stderr) when signed_cert, connection_key or ed25519_pubkey is missing or the key is not a 32-byte Ed25519 key.
# `ca` is returned as it is (empty when the answer has none): install.sh requires it, rotate.sh keeps the CA it already trusts.
parse_bootstrap_response() {
    local file="$1" pub
    BR_SIGNED_CERT="$(bootstrap_field "$file" signed_cert)"
    BR_CA="$(bootstrap_field "$file" ca)"
    BR_CONNECTION_KEY="$(bootstrap_field "$file" connection_key)"
    BR_SIGNING_KEY_ID="$(bootstrap_field "$file" signing_key_id)"
    pub="$(bootstrap_field "$file" ed25519_pubkey)"
    [[ -n "$BR_SIGNED_CERT" ]] || { echo "bootstrap response missing signed_cert" >&2; return 1; }
    [[ -n "$BR_CONNECTION_KEY" ]] || { echo "bootstrap response missing connection_key" >&2; return 1; }
    [[ -n "$pub" ]] || { echo "bootstrap response missing ed25519_pubkey" >&2; return 1; }
    BR_ED25519_PEM="$(bootstrap_ed25519_pem "$pub")" || return 1
}
# END bootstrap-response

exchange_rotate() {
    local csr_file="$1"
    local csr_pem response_file http_code

    csr_pem="$(cat "$csr_file")"
    response_file="$(mktemp /tmp/mavora-rotate-XXXXXX.json)"
    trap 'rm -f "$response_file"' RETURN

    info "Exchanging rotate token for new credentials..."

    local payload
    payload="$(printf '{"install_token":%s,"csr":%s}' \
        "$(printf '%s' "$INSTALL_TOKEN" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().strip()))')" \
        "$(printf '%s' "$csr_pem" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')")"

    # The gateway's certificate is signed by the agent CA saved at install time; the agent trusts that CA and nothing else.
    [[ -s "$CA_CERT" ]] || fail "Agent CA ${CA_CERT} not found: cannot verify the control-plane gateway. Re-run install.sh."

    http_code="$(curl \
        --fail --silent --show-error --max-time 30 \
        --cacert "$CA_CERT" \
        --write-out "%{http_code}" \
        --output "$response_file" \
        -X POST \
        -H "Content-Type: application/json" \
        "${CONTROL_PLANE}/agent/v1/bootstrap" \
        --data-binary "$payload" 2>&1)" || {
            fail "Rotate exchange failed (HTTP ${http_code:-unknown})."
        }
    [[ "$http_code" == "200" || "$http_code" == "201" ]] || \
        fail "Rotate returned HTTP $http_code."

    # Same reader as install.sh: unwraps {"data":...}; NEW_ED25519 is the PEM PKIX the agent loads, not the raw base64url.
    parse_bootstrap_response "$response_file" || fail "Rotate response unusable (see message above). Old credentials are unchanged."
    NEW_CERT="$BR_SIGNED_CERT"
    NEW_BEARER="$BR_CONNECTION_KEY"
    NEW_ED25519="$BR_ED25519_PEM"
    NEW_SIGNING_KEY_ID="$BR_SIGNING_KEY_ID"

    rm -f "$csr_file"
    unset INSTALL_TOKEN
}

verify_new_cert_key() {
    info "Verifying new cert ↔ new key match..."
    local cert_tmp="${CONF_DIR}/client.crt.new"
    printf '%s\n' "$NEW_CERT" > "$cert_tmp"
    chmod 0600 "$cert_tmp"

    local cert_pub key_pub
    cert_pub="$(openssl x509 -in "$cert_tmp" -pubkey -noout)"
    key_pub="$(openssl ec -in "$NEW_KEY_PATH" -pubout)"

    if [[ "$cert_pub" != "$key_pub" ]]; then
        rm -f "$cert_tmp"
        fail "New cert ↔ key MISMATCH. Rotation aborted. Old credentials still active."
    fi

    printf '%s\n' "$cert_tmp" > /dev/null  # cert_tmp path captured separately
    echo "$cert_tmp"
}

apply_new_credentials() {
    local new_cert_file="$1"

    info "Applying new credentials (grace window: ${GRACE_SECONDS}s for old Ed25519 key)..."

    # Keep old Ed25519 pub for grace window (agent holds both during grace)
    cp "$ED25519_PUB" "$ED25519_OLD" 2>/dev/null || true
    chmod 0600 "$ED25519_OLD"

    # Atomically install new credentials
    mv "$new_cert_file" "$TLS_CERT"
    mv "$NEW_KEY_PATH"  "$TLS_KEY"
    printf '%s\n' "$NEW_BEARER"   > "$BEARER_FILE"
    printf '%s\n' "$NEW_ED25519"  > "$ED25519_PUB"

    chmod 0600 "$TLS_KEY" "$TLS_CERT" "$BEARER_FILE" "$ED25519_PUB"
    chown "$AGENT_USER:$AGENT_USER" "$TLS_KEY" "$TLS_CERT" "$BEARER_FILE" "$ED25519_PUB"

    # Update signing_key_ids in config (old + new for grace)
    if [[ -f "${CONF_DIR}/config.yaml" ]]; then
        local old_key_id
        old_key_id="$(cat "${CONF_DIR}/signing_key_id" 2>/dev/null || echo "")"
        # Write both old+new signing key IDs so agent holds grace
        python3 <<PYEOF
import yaml, sys
with open('${CONF_DIR}/config.yaml') as f:
    cfg = yaml.safe_load(f)
ids = []
if "$old_key_id":
    ids.append("$old_key_id")
if "$NEW_SIGNING_KEY_ID" and "$NEW_SIGNING_KEY_ID" not in ids:
    ids.append("$NEW_SIGNING_KEY_ID")
cfg['signing_key_ids'] = ids
with open('${CONF_DIR}/config.yaml', 'w') as f:
    yaml.dump(cfg, f, default_flow_style=False)
PYEOF
    fi
    echo "$NEW_SIGNING_KEY_ID" > "${CONF_DIR}/signing_key_id"
    chmod 0644 "${CONF_DIR}/signing_key_id"

    unset NEW_BEARER NEW_ED25519
}

reload_service() {
    if systemctl is-active --quiet mavora-agent; then
        systemctl reload-or-restart mavora-agent
        info "Service reloaded with new credentials."
    else
        systemctl start mavora-agent
        info "Service started with new credentials."
    fi
}

drop_old_key_after_grace() {
    info "Waiting ${GRACE_SECONDS}s grace window before removing old Ed25519 key..."
    sleep "$GRACE_SECONDS"

    # Remove old key from seen-set (agent config: only new key remains)
    if [[ -f "${CONF_DIR}/config.yaml" ]] && [[ -n "$NEW_SIGNING_KEY_ID" ]]; then
        python3 <<PYEOF
import yaml
with open('${CONF_DIR}/config.yaml') as f:
    cfg = yaml.safe_load(f)
cfg['signing_key_ids'] = ["$NEW_SIGNING_KEY_ID"]
with open('${CONF_DIR}/config.yaml', 'w') as f:
    yaml.dump(cfg, f, default_flow_style=False)
PYEOF
        systemctl reload-or-restart mavora-agent 2>/dev/null || true
    fi

    rm -f "$ED25519_OLD"
    info "Old Ed25519 key removed. Rotation complete."
}

main() {
    [[ "$EUID" -eq 0 ]] || fail "rotate.sh must be run as root (sudo)."
    parse_args "$@"

    log "=== Mavora Agent — Credential Rotation ==="
    log "SECURITY: new mTLS private key generated here; old key overwritten only after verify."

    local csr_file
    csr_file="$(generate_new_keypair)"
    exchange_rotate "$csr_file"
    local new_cert_file
    new_cert_file="$(verify_new_cert_key)"
    apply_new_credentials "$new_cert_file"
    reload_service

    info "New credentials active. Old Ed25519 key held for ${GRACE_SECONDS}s grace window."
    info "Running grace-window cleanup in background..."

    # Run grace-window drop in background (non-blocking for caller)
    drop_old_key_after_grace &
    disown $!

    log "Rotation initiated. Both old+new Ed25519 keys accepted for ${GRACE_SECONDS}s."
    log "After grace: only new key accepted. Monitor: journalctl -u mavora-agent -f"
}

main "$@"
