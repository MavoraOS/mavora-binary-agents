# mavora-binary-agents

Pre-built, version-pinned binaries for the Mavora **agents** that run on a
**Client VPS** — distributed via git so a VPS can `git clone` / `git pull` and
install **without** a Go toolchain or Docker.

> These are **native Linux binaries** run as hardened **systemd** services (not
> containers). Each agent runs under its own non-root user with a narrow sudoers
> allowlist — see each agent's `docs/SECURITY.md`.

## Quick start (on a Client VPS)

```bash
git clone <this-repo-url> mavora-binary-agents
cd mavora-binary-agents

# see what's available + this host's arch
./mavora-agents list

# install the site-provisioning agent as a systemd service
sudo ./mavora-agents install site-provisioning-agent -- \
     --token-file /root/install-token \
     --control-plane https://api.mavoraos.com
```

The dispatcher auto-detects the host OS/arch (`linux/amd64` or `linux/arm64`),
picks the matching binary, and runs that agent's own installer
(`scripts/install.sh --binary <picked>`) which sets up the systemd unit,
sudoers, root-helpers, config, and the mTLS bootstrap.

## Commands

| Command | What it does |
|---|---|
| `./mavora-agents list` | list agents + versions + available arches |
| `./mavora-agents info <agent>` | show `BUILD_INFO` + checksums |
| `./mavora-agents verify [<agent>]` | verify binary `SHA256SUMS` |
| `./mavora-agents run <agent> [-- args]` | launch the binary in the foreground (manual/debug; reads config) |
| `sudo ./mavora-agents install <agent> -- <args>` | install as a systemd service |

`run` / `install` pass everything after `--` straight to the agent binary /
installer, so you select the agent by **name** and the right binary is chosen
for you.

## Layout

```
mavora-binary-agents/
├── mavora-agents                 # ← your entry point (dispatcher)
├── README.md
└── agents/
    └── site-provisioning-agent/
        ├── bin/
        │   ├── mavora-agent_linux_amd64
        │   └── mavora-agent_linux_arm64
        ├── scripts/{install,uninstall,doctor,rotate}.sh
        ├── deploy/{systemd,sudoers,helpers}/…
        ├── configs/config.example.yaml
        ├── docs/                  # INSTALL · CONFIGURATION · OPERATIONS · SECURITY · …
        ├── BUILD_INFO             # version · git sha · build date · go version · flags
        └── SHA256SUMS
```

Adding another agent later = drop its `bin/` + assets under a new
`agents/<name>/` and it shows up in `./mavora-agents list` automatically.

## Provenance & integrity

Binaries are built from the agent source repos with `CGO_ENABLED=0 -trimpath`
and version metadata baked in via `-ldflags`. Each agent's `BUILD_INFO` records
the exact **source git SHA**, build date, Go version, and flags; `SHA256SUMS`
lets you verify integrity:

```bash
./mavora-agents verify site-provisioning-agent
```

> Source of truth for the site-provisioning agent: `MavoraOS/site-provisioning-agent`.
> Its official tagged release artifacts are additionally **cosign-signed**
> (keyless). The binaries here are a convenience build for git-based VPS install.

## Rebuild / update an agent

From the agent source repo:

```bash
SHA=$(git rev-parse --short HEAD); VER="0.1.0-$SHA"
LD="-s -w -X main.AgentVersion=$VER -X main.ProtocolVersion=1 \
    -X main.MinProtocolVersion=1 -X main.MaxProtocolVersion=1"
for A in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH=$A go build -trimpath -ldflags "$LD" \
    -o <this-repo>/agents/<name>/bin/mavora-agent_linux_$A ./cmd/mavora-agent
done
# then refresh scripts/ deploy/ configs/ docs/, regenerate SHA256SUMS + BUILD_INFO, commit.
```

> Binaries are committed directly to git. For frequent updates, consider
> **git-LFS** to keep history small.

## Notes

- Agents are only provisioned/used when the Mavora control-plane feature flag
  `MAVORA_SITE_PROVISIONING_ENABLED` is **on**. Installing an agent before the
  flag is enabled is harmless — it will bootstrap and idle.
- `--token-file` is preferred over `--token` (keeps the one-time install token
  off shell history).
