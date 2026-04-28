#!/bin/bash
# patch-suricata-yaml.sh — Patch default suricata.yaml for profiling
YAML="/etc/suricata/suricata.yaml"
[ ! -f "$YAML" ] && echo "[patch] ERROR: $YAML not found" && exit 1

# Enable rule profiling
sed -i '/profiling:/,/rules:/{/rules:/,/enabled:/{s/enabled: no/enabled: yes/}}' "$YAML"

# Set limit to 0 (all rules)
sed -i '/profiling:/,/rules:/{/rules:/,/limit:/{s/limit: [0-9]*/limit: 0/}}' "$YAML"

# Set json to no (plain text table format)
sed -i '/profiling:/,/rules:/{/rules:/,/json:/{s/json: yes/json: no/}}' "$YAML"

# Disable checksum validation for pcap replay
sed -i 's/checksum-validation: yes/checksum-validation: no/g' "$YAML"

echo "[patch] suricata.yaml patched for profiling"
grep -A8 "profiling:" "$YAML" | head -12
