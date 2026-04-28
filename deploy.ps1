# deploy.ps1 — Arachnid Intel deployment script for Windows
# Run from the cve-feed-explorer directory in PowerShell

Write-Host ""
Write-Host "  * Arachnid Intel - Docker Deployment" -ForegroundColor Cyan
Write-Host "  ======================================" -ForegroundColor DarkGray
Write-Host ""

# Check Docker is running
try {
    $dockerVersion = docker version --format '{{.Server.Version}}' 2>$null
    if (-not $dockerVersion) { throw "Docker not responding" }
    Write-Host "  [+] Docker Engine $dockerVersion detected" -ForegroundColor Green
} catch {
    Write-Host "  [x] Docker Desktop is not running. Start it first." -ForegroundColor Red
    exit 1
}

# Clean rebuild
Write-Host ""
Write-Host "  Building image (no-cache) and starting container..." -ForegroundColor Yellow
Write-Host "  This may take 5-10 minutes on first build (Suricata + dependencies)" -ForegroundColor DarkGray
Write-Host ""

docker compose build --no-cache
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "  [x] Build failed. Check the output above." -ForegroundColor Red
    exit 1
}

docker compose up -d --force-recreate
if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "  [+] Deployment successful!" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Open: http://localhost:8082" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Commands:" -ForegroundColor DarkGray
    Write-Host "    docker compose logs -f cve-feed     # view logs" -ForegroundColor DarkGray
    Write-Host "    docker compose down                 # stop" -ForegroundColor DarkGray
    Write-Host "    docker compose up -d --build        # quick rebuild" -ForegroundColor DarkGray
    Write-Host ""
    Start-Process "http://localhost:8082"
} else {
    Write-Host "  [x] Container failed to start." -ForegroundColor Red
    exit 1
}
