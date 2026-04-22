# deploy.ps1 — FediSec CVE Feed Explorer deployment script for Windows
# Run from the cve-feed-explorer directory in PowerShell

Write-Host ""
Write-Host "  ◈ FediSec CVE Feed Explorer — Docker Deployment" -ForegroundColor Cyan
Write-Host "  ================================================" -ForegroundColor DarkGray
Write-Host ""

# Check Docker is running
try {
    $dockerVersion = docker version --format '{{.Server.Version}}' 2>$null
    if (-not $dockerVersion) { throw "Docker not responding" }
    Write-Host "  [✓] Docker Engine $dockerVersion detected" -ForegroundColor Green
} catch {
    Write-Host "  [✗] Docker Desktop is not running. Start it first." -ForegroundColor Red
    Write-Host "      Open Docker Desktop from the Start Menu and wait for it to initialize." -ForegroundColor Yellow
    exit 1
}

# Build and launch
Write-Host ""
Write-Host "  Building image and starting container..." -ForegroundColor Yellow
Write-Host ""

docker compose up -d --build

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────────────┐" -ForegroundColor Green
    Write-Host "  │  ✓ Deployment successful!                   │" -ForegroundColor Green
    Write-Host "  │                                             │" -ForegroundColor Green
    Write-Host "  │  Open: http://localhost:8082                │" -ForegroundColor Green
    Write-Host "  │  Health: http://localhost:8082/health       │" -ForegroundColor Green
    Write-Host "  │                                             │" -ForegroundColor Green
    Write-Host "  │  Commands:                                  │" -ForegroundColor Green
    Write-Host "  │    docker compose logs -f cve-feed          │" -ForegroundColor Green
    Write-Host "  │    docker compose down                      │" -ForegroundColor Green
    Write-Host "  │    docker compose up -d --build             │" -ForegroundColor Green
    Write-Host "  └─────────────────────────────────────────────┘" -ForegroundColor Green
    Write-Host ""

    # Open browser
    Start-Process "http://localhost:8082"
} else {
    Write-Host ""
    Write-Host "  [✗] Build failed. Check the output above for errors." -ForegroundColor Red
    Write-Host "      Common fixes:" -ForegroundColor Yellow
    Write-Host "        - Ensure Docker Desktop is fully started" -ForegroundColor Yellow
    Write-Host "        - Check Windows Firewall isn't blocking port 8082" -ForegroundColor Yellow
    Write-Host "        - Try: docker compose down; docker compose up -d --build" -ForegroundColor Yellow
    exit 1
}
