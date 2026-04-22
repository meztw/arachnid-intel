# FediSec CVE Feed Explorer

A self-hosted web dashboard for browsing the [FediSec CVE Feed](https://github.com/fedisecfeeds/fedisecfeeds.github.io). Fetches the live JSON feed and provides sorting, filtering, and drill-down into CVE details including Fediverse posts, GitHub repos, and Nuclei templates.

## Prerequisites

- **Docker Desktop for Windows** — download from https://www.docker.com/products/docker-desktop/
- Make sure Docker Desktop is **running** (whale icon in system tray) before proceeding

## Quick Start (PowerShell)

```powershell
# 1. Extract the archive and navigate into the project
cd cve-feed-explorer

# 2. One-click deploy (builds, starts, and opens browser)
.\deploy.ps1

# Or manually:
docker compose up -d --build
```

The app will be available at **http://localhost:8082**

## Features

- **Sort** by CVSS score, CVE year, post count, repo count, Nuclei update date, EPSS severity
- **Filter** by CVSS severity (Critical/High/Medium/Low) and EPSS severity
- **Search** across CVE IDs, descriptions, and post content
- **Expand** any row to see full description, Fediverse posts, linked repos, and Nuclei template info
- **Paginated** — 30 results per page

## Architecture

```
┌─────────────────────────────┐
│  Browser (client-side)      │
│  React SPA fetches JSON     │
│  directly from GitHub raw   │
└──────────┬──────────────────┘
           │ port 8082
┌──────────▼──────────────────┐
│  Nginx (Alpine container)   │
│  Serves static build files  │
│  Gzip + security headers    │
│  /health endpoint           │
└─────────────────────────────┘
```

## PowerShell Commands

```powershell
# Build and start
docker compose up -d --build

# View live logs
docker compose logs -f cve-feed

# Stop the container
docker compose down

# Rebuild after code changes
docker compose up -d --build --force-recreate

# Check container status
docker ps --filter "name=cve-feed-explorer"

# Health check
Invoke-WebRequest http://localhost:8082/health | Select-Object -ExpandProperty Content
```

## Configuration

### Change the port

Edit `docker-compose.yml`:

```yaml
ports:
  - "3000:80"   # Change 3000 to your desired port
```

### Update the feed URL

Edit `src\App.js` line 3 — change `FEED_URL` to your own mirror or local endpoint.

### Use behind a reverse proxy (Traefik, Caddy, etc.)

Remove the `ports` mapping and connect via Docker network. Example with Traefik labels:

```yaml
services:
  cve-feed:
    build: .
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.cvefeed.rule=Host(`cve.yourdomain.com`)"
      - "traefik.http.services.cvefeed.loadbalancer.server.port=80"
    networks:
      - proxy

networks:
  proxy:
    external: true
```

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `deploy.ps1 cannot be loaded because running scripts is disabled` | Run `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` then retry |
| `error during connect: This error may indicate that the docker daemon is not running` | Open Docker Desktop and wait for it to fully start |
| Port 8082 already in use | Change the port in `docker-compose.yml` or stop the conflicting service |
| Build fails on `npm install` | Ensure Docker Desktop has internet access (check proxy settings in Docker Desktop → Settings → Resources → Proxies) |
| Container starts but page won't load | Check Windows Firewall: allow inbound on port 8082, or try `http://127.0.0.1:8082` |
