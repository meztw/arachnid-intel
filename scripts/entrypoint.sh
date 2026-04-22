#!/bin/sh
# entrypoint.sh — Fetch all data on boot, schedule daily cron, start Nginx

echo "=== CVE Feed Explorer Starting ==="

echo "[entrypoint] Running initial data fetch..."
/usr/local/bin/fetch-data.sh || echo "[entrypoint] WARNING: Initial fetch had errors"

# Daily cron at 3:00 AM UTC
echo "0 3 * * * /usr/local/bin/fetch-data.sh >> /var/log/cve-data-cron.log 2>&1" > /etc/crontabs/root
crond -b -l 8

echo "[entrypoint] Cron scheduled (daily 03:00 UTC). Starting Nginx..."
exec nginx -g 'daemon off;'
