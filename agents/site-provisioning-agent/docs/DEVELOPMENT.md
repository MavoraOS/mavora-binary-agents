# DEVELOPMENT — Mavora Site Provisioning Agent

SP-T-219 / agent/07 §42. Build, test, extend. Model C.

---

## Prerequisites

- Go 1.26+
- Docker (for system tests with testcontainers)
- `golangci-lint` v1.64+
- `gosec`, `govulncheck` (install via `go install`)
- `gitleaks` (for local secret scan)
- `cosign` (for release signing, optional locally)

---

## Build

```bash
# Dev build (host arch)
make build

# Static linux/amd64
make build-amd64

# Static linux/arm64
make build-arm64

# Both arches + checksums
make release
```

Build flags: `CGO_ENABLED=0 -trimpath -ldflags="-s -w"` — produces fully static binaries with no glibc dependency.

---

## Test

```bash
# Unit tests (fast, no external deps, -short -race)
make test-unit

# Unit + coverage report
make coverage

# Integration tests (uses fake-Mavora harness)
make test-integration

# Security behavior tests
make test-security

# Error registry contract test (⊆ spec §15.2)
make contract-test

# All tests
go test -count=1 -timeout 15m ./...
```

### Fake-Mavora Harness (SP-T-241)

`internal/testutil/fake_mavora.go` provides a stub control-plane:
- Signs job envelopes with a test Ed25519 key
- Handles: `/agent/v1/jobs/poll`, `/agent/v1/jobs/:id/ack`, `/agent/v1/jobs/:id/result`, `/agent/v1/heartbeat`, `/agent/v1/bootstrap`
- Returns 204 (no job), 200 (lease), 409 (stale lease), idempotent-replay responses

Use in integration tests:
```go
srv := testutil.NewFakeMavora(t)
defer srv.Close()
// srv.URL is the base URL to configure the agent client against
```

### WP Multisite Prerequisites for Local Dev

System tests require nginx + WP Multisite. Use testcontainers:
```go
//go:build system
// +build system

// Tests in tests/system/ use testcontainers to spin up nginx + mock WP
```

Or manually: install WP Multisite locally and point `webroot` config at it.

---

## Lint + Vet

```bash
make lint      # golangci-lint
make vet       # go vet
```

golangci-lint config: `.golangci.yml` in repo root.

---

## Security Scan

```bash
make security       # gosec -severity high + govulncheck
make secret-scan    # gitleaks (local, requires gitleaks installed)
```

---

## Error Registry

The agent error code set MUST be ⊆ the spec set in `docs/site-provisioning/implementation/10-error-registry.md §15.2`.

Error registry: `internal/errors/registry.go`
Contract test: `internal/errors/registry_test.go::TestAgentCodeSetSubsetOfSpec`

### Adding a new error code

1. Add it to `SpecCodeSet` in `internal/errors/registry.go` only if it is already in `10-error-registry.md §15.2`.
2. Define the `AgentError` struct entry.
3. Add to `AllAgentCodes` slice.
4. Run `make contract-test` — must pass.
5. If the code is new (not yet in the spec): update `10-error-registry.md §15.2` first, via a PR against the spec.

### Forbidden code prefixes (gate FAILS if present)

- `AGENT_AOP_*` (AOP out-of-scope)
- `CF_*` (Cloudflare — Model A, cut)
- `NC_*` (Namecheap — Model A, cut)
- `NS_VERIFY_*` (nameserver verify — Model A, cut)

---

## Adding a New Handler (Command Type)

1. Add the command type constant to `internal/protocol/envelope.go`.
2. Add to the `AllowedCommandTypes` set in `protocol`.
3. Implement handler in `internal/handlers/<name>/<name>.go`.
4. Register in `internal/jobs/dispatch.go`.
5. Add to the sudoers allowlist (if new privileged operation needed) → update `deploy/sudoers/mavora-agent` + validate with `visudo -c`.
6. Add to exec allowlist in `internal/system/exec.go` (if new binary needed).
7. Write unit + integration + security tests.
8. Run full CI suite.

**NEVER add `sh -c` or shell-string invocations.** All exec must go through the allowlist + argv slice pattern.

---

## CI Pipeline (SP-T-220)

See `.github/workflows/ci.yaml` for the full pipeline.

Key stages:
1. `secret-scan` — gitleaks + trufflehog (GATE: must pass before build)
2. `anti-regression` — grep for forbidden Model-A tokens
3. `build` — static amd64 + arm64
4. `lint` + `vet`
5. `test-unit` — -short -race, coverage ≥80%
6. `test-integration` — fake-Mavora
7. `security-gosec` + `security-govulncheck`
8. `security-behavior` — invalid-sig / replay / perm / injection + secret-not-logged grep + sudoers scope
9. `installer-compat` — dry-run + bootstrap contract checks
10. `checksum-cosign` — SHA256 + cosign keyless/OIDC sign (on push to main/site-provisioning)

---

## Release

Release is via GoReleaser + GitHub Actions release pipeline (`.github/workflows/release.yml`).

```bash
# Tag and push (triggers release pipeline)
git tag v1.0.0
git push origin v1.0.0
```

Release artifacts:
- `mavora-agent_v1.0.0_linux_amd64.tar.gz` (binary + scripts + docs)
- `mavora-agent_v1.0.0_linux_arm64.tar.gz`
- `checksums.txt` + `.sig` (cosign keyless OIDC — BL-18)

---

## Observability / Structured Logs

Log fields: `trace_id`, `job_id`, `provisioning_id`, `site_id`, `domain`, `job_type`, `status`, `error_code`, `duration_ms`, `agent_id`, `hostname`.

Secret scrubber in `internal/logging/scrubber.go` redacts any field matching `*key*|*token*|*password*|*secret*|authorization|credential*`.

NEVER log these values (RC-7):
- `connection_key` (bearer)
- mTLS private key
- WP Application Password
- `install_token`
- Authorization header raw value

See SECURITY.md §NEVER LOG List for the full list.

---

## Out of Scope for This Repo

- SSL/TLS certificate management / Let's Encrypt / certbot / AOP
- Cloudflare, registrar, or DNS-provider API integration
- Inbound HTTP/management listener (agent is outbound HTTPS-443 only)
- Ed25519 SIGNING (signing private key is at Mavora; this repo is VERIFY-only)
- WP/nginx/php-fpm installation (OPS pre-installs these; agent assumes they exist)
