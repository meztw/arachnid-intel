#!/bin/bash
YAML="/etc/suricata/suricata.yaml"
[ ! -f "$YAML" ] && echo "[patch] ERROR: $YAML not found" && exit 1
sed -i '/profiling:/,/rules:/{/rules:/,/enabled:/{s/enabled: no/enabled: yes/}}' "$YAML"
sed -i '/profiling:/,/rules:/{/rules:/,/limit:/{s/limit: [0-9]*/limit: 0/}}' "$YAML"
sed -i '/profiling:/,/rules:/{/rules:/,/json:/{s/json: yes/json: no/}}' "$YAML"
sed -i 's/checksum-validation: yes/checksum-validation: no/g' "$YAML"
echo "[patch] suricata.yaml patched"
