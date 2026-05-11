# deploy.ps1 — Arachnid Intel deployment for Windows Docker Desktop
Write-Host "`n  * Arachnid Intel - Docker Deployment" -ForegroundColor Cyan
try { $v = docker version --format '{{.Server.Version}}' 2>$null; if (-not $v) { throw }; Write-Host "  [+] Docker $v" -ForegroundColor Green } catch { Write-Host "  [x] Docker not running" -ForegroundColor Red; exit 1 }
Write-Host "`n  Building (first build takes 10-20min for Suricata compile)..." -ForegroundColor Yellow
docker compose build --no-cache
if ($LASTEXITCODE -ne 0) { Write-Host "  [x] Build failed" -ForegroundColor Red; exit 1 }
docker compose up -d --force-recreate
if ($LASTEXITCODE -eq 0) { Write-Host "`n  [+] Running at http://localhost:8082`n" -ForegroundColor Green; Start-Process "http://localhost:8082" }
else { Write-Host "  [x] Failed to start" -ForegroundColor Red; exit 1 }
