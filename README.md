# Firewall Audit Dashboard

Dark-themed web dashboard that connects live to a **Check Point Management API** and audits all access rules for security issues.

## Features

- Live connection to Check Point R80.x / R81.x / R82 Management API
- Supports Standalone and Multi-Domain (MDS) servers
- Fetches all access layers and policies
- Flags: any-source, any-destination, any-service, zero hit count, disabled rules, broad subnets, missing comments
- Severity scoring: Critical / High / Medium / Low / Clean
- Filterable, sortable, paginated rule table
- Export flagged rules to CSV
- Offline sample data mode (no firewall needed to try it)

## Quick Start (Docker)

```bash
# Pull and run
git clone https://github.com/MarkoO81/fw-audit-dashboard.git
cd fw-audit-dashboard

docker compose up -d --build

# Open in browser
open http://localhost:3737
```

## Network Requirements

The container uses `network_mode: host` so it can reach your Check Point management server directly.  
If your Docker host can ping the management server, the dashboard will work.

## Check Point API Requirements

- API must be enabled on the management server (`cpconfig` → API)
- User needs at least **Read-Only** access to the policy domain
- Self-signed certificates are accepted automatically

## Ports

| Port | Service |
|------|---------|
| 3737 | Dashboard (HTTP) |

To change the port, edit `docker-compose.yml` and set `PORT` env var.
