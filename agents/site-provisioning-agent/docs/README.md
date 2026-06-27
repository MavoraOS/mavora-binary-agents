# Mavora Site Provisioning Agent — Docs

Full runbook documentation ships in W7 (SP-T-219).

| Document | Status |
|---|---|
| INSTALL.md | W7 |
| CONFIGURATION.md | W7 |
| TROUBLESHOOTING.md | W7 |
| SECURITY.md | W7 |
| OPERATIONS.md | W7 |
| DEVELOPMENT.md | W7 |

## Model C — What the agent does NOT do

- Does NOT manage DNS (Customer's responsibility).
- Does NOT obtain SSL certificates (Customer's responsibility).
- Does NOT configure Cloudflare or any managed-DNS provider.
- Does NOT open an inbound management port.
- Serves sites over HTTP port 80 (origin); HTTPS is the Customer's SSL layer.
