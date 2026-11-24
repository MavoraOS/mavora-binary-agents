#!/usr/bin/env bash
# bootstrap-response.sh — the ONE place that reads the answer of POST /agent/v1/bootstrap.
#
# Used by install.sh and rotate.sh: both exchange a token for credentials at the same endpoint, so both must read the answer the same way.
#   - The control plane wraps the answer in {"data": {...}} (ADR-030); a flat object is accepted too.
#   - ed25519_pubkey arrives as base64url (no padding) of the RAW 32-byte key; the agent loads a PEM PKIX file (auth.loadOnePEMKey).
#
# `curl | bash` installs have no file next to install.sh, so the block between the BEGIN/END markers is EMBEDDED verbatim in install.sh and
# rotate.sh. This file is the source of truth; tests/bootstrap_scripts_test.go fails if an embedded copy differs from it.
# Edit only this block, then copy it into both scripts.

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
