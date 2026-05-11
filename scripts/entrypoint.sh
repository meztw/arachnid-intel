#!/bin/bash
echo "=== Arachnid Intel Starting ==="
echo "[entrypoint] Fetching enrichment data..."
/usr/local/bin/fetch-data.sh || echo "[entrypoint] WARNING: Some data fetches failed"
echo "0 3 * * * /usr/local/bin/fetch-data.sh >> /var/log/cve-data-cron.log 2>&1" | crontab -
service cron start 2>/dev/null || true
echo "[entrypoint] Starting API server..."
cd /opt/api && gunicorn -w 2 -b 0.0.0.0:5000 --timeout 660 --access-logfile /var/log/api-access.log --error-logfile /var/log/api-error.log server:app &
echo "[entrypoint] Waiting for API..."
for i in $(seq 1 15); do curl -sf http://127.0.0.1:5000/api/analysis/status >/dev/null 2>&1 && echo "[entrypoint] API is ready" && break; sleep 1; done
echo "[entrypoint] Starting Nginx..."
exec nginx -g 'daemon off;'
