#!/bin/sh
# fetch-data.sh — Downloads and caches all enrichment data
# Runs on startup and daily via cron
# Outputs JSON files to /var/cache/cve-data/

CACHE="/var/cache/cve-data"
mkdir -p "$CACHE"

log() { echo "[$(date -Iseconds)] $1"; }

# ─── 1. EPSS Scores ───────────────────────────────────────────────
fetch_epss() {
  log "Fetching EPSS scores..."
  local GZ="$CACHE/epss.csv.gz"
  local CSV="$CACHE/epss.csv"

  curl -sfL -o "$GZ" "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz" || { log "ERROR: EPSS download failed"; return 1; }
  gunzip -f "$GZ" 2>/dev/null || gzip -d -f "$GZ" 2>/dev/null

  python3 << 'PYEOF'
import json, sys
out = {}
with open("/var/cache/cve-data/epss.csv", encoding="utf-8", errors="replace") as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("cve,"):
            continue
        parts = line.split(",")
        if len(parts) >= 3 and parts[0].startswith("CVE-"):
            try:
                out[parts[0]] = {"epss": float(parts[1]), "percentile": float(parts[2])}
            except ValueError:
                continue
with open("/var/cache/cve-data/epss.json", "w") as f:
    json.dump(out, f, separators=(",", ":"))
print(f"EPSS: {len(out)} scores cached")
PYEOF
  rm -f "$CSV"
}

# ─── 2. Nuclei Templates ──────────────────────────────────────────
fetch_nuclei() {
  log "Fetching Nuclei templates..."
  local RAW="$CACHE/nuclei_raw.ndjson"

  curl -sfL -o "$RAW" "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/refs/heads/main/cves.json" || { log "ERROR: Nuclei download failed"; return 1; }

  python3 << 'PYEOF'
import json, sys
out = {}
with open("/var/cache/cve-data/nuclei_raw.ndjson", encoding="utf-8", errors="replace") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        cve_id = obj.get("ID", "")
        if not cve_id.startswith("CVE-"):
            continue
        info = obj.get("Info", {})
        classification = info.get("Classification", {})
        out[cve_id] = {
            "name": info.get("Name", ""),
            "severity": info.get("Severity", ""),
            "cvss": classification.get("CVSSScore", ""),
            "file_path": obj.get("file_path", "")
        }
with open("/var/cache/cve-data/nuclei.json", "w") as f:
    json.dump(out, f, separators=(",", ":"))
print(f"Nuclei: {len(out)} templates cached")
PYEOF
  rm -f "$RAW"
}

# ─── 3. Metasploit Modules ────────────────────────────────────────
fetch_metasploit() {
  log "Fetching Metasploit module metadata..."
  local RAW="$CACHE/msf_raw.json"

  curl -sfL -o "$RAW" "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json" || { log "ERROR: Metasploit download failed"; return 1; }

  python3 << 'PYEOF'
import json, sys
try:
    with open("/var/cache/cve-data/msf_raw.json", encoding="utf-8", errors="replace") as f:
        data = json.load(f)
except Exception as e:
    print(f"ERROR parsing MSF JSON: {e}")
    sys.exit(1)

cve_map = {}
for key, mod in data.items():
    refs = mod.get("references", [])
    cves = [r for r in refs if r.startswith("CVE-")]
    if not cves:
        continue
    entry = {
        "name": mod.get("name", ""),
        "path": mod.get("path", key),
        "rank": mod.get("rank", 0)
    }
    for cve in cves:
        cve_map.setdefault(cve, []).append(entry)

with open("/var/cache/cve-data/metasploit.json", "w") as f:
    json.dump(cve_map, f, separators=(",", ":"))
print(f"Metasploit: {len(cve_map)} CVEs with modules cached")
PYEOF
  rm -f "$RAW"
}

# ─── 4. Exploit-DB ────────────────────────────────────────────────
fetch_exploitdb() {
  log "Fetching Exploit-DB CSV..."
  local CSV="$CACHE/exploitdb.csv"

  curl -sfL -o "$CSV" "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv" || { log "ERROR: ExploitDB download failed"; return 1; }

  python3 << 'PYEOF'
import csv, json, re, sys

cve_map = {}
with open("/var/cache/cve-data/exploitdb.csv", encoding="utf-8", errors="replace") as f:
    reader = csv.reader(f)
    header = next(reader, None)
    if not header:
        print("ERROR: empty CSV")
        sys.exit(1)

    # Find the codes column
    codes_idx = None
    for i, h in enumerate(header):
        if "codes" in h.lower():
            codes_idx = i
            break
    if codes_idx is None:
        codes_idx = 11

    for row in reader:
        try:
            if len(row) <= codes_idx:
                continue
            edb_id = row[0].strip()
            desc = row[2].strip() if len(row) > 2 else ""
            date_pub = row[3].strip() if len(row) > 3 else ""
            codes = row[codes_idx]
            cves = re.findall(r"CVE-\d{4}-\d+", codes)
            for cve in cves:
                cve_map.setdefault(cve, []).append({
                    "id": edb_id,
                    "title": desc,
                    "date": date_pub,
                    "url": f"https://www.exploit-db.com/exploits/{edb_id}"
                })
        except Exception:
            continue

with open("/var/cache/cve-data/exploitdb.json", "w") as f:
    json.dump(cve_map, f, separators=(",", ":"))
print(f"ExploitDB: {len(cve_map)} CVEs with exploits cached")
PYEOF
  rm -f "$CSV"
}

# ─── 5. Emerging Threats Suricata Rules ────────────────────────────
fetch_et_rules() {
  log "Fetching Emerging Threats rules..."
  local RULES="$CACHE/emerging-all.rules"

  curl -sfL -o "$RULES" "https://rules.emergingthreats.net/open/suricata-5.0/emerging-all.rules" || { log "ERROR: ET rules download failed"; return 1; }

  python3 << 'PYEOF'
import re, json

cve_map = {}
with open("/var/cache/cve-data/emerging-all.rules", encoding="utf-8", errors="replace") as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Extract CVEs from reference:cve,YYYY-NNNNN
        cves = re.findall(r"reference:\s*cve\s*,\s*(\d{4}-\d+)", line, re.IGNORECASE)
        if not cves:
            continue
        # Extract msg
        msg_m = re.search(r'msg:\s*"([^"]*)"', line)
        msg = msg_m.group(1) if msg_m else ""
        # Extract sid
        sid_m = re.search(r'\bsid:\s*(\d+)', line)
        sid = sid_m.group(1) if sid_m else ""
        # Extract classtype
        ct_m = re.search(r'classtype:\s*([^;]+)', line)
        classtype = ct_m.group(1).strip() if ct_m else ""

        entry = {"sid": sid, "msg": msg, "classtype": classtype}
        for cve_num in cves:
            cve_id = f"CVE-{cve_num}"
            cve_map.setdefault(cve_id, []).append(entry)

with open("/var/cache/cve-data/et_rules.json", "w") as f:
    json.dump(cve_map, f, separators=(",", ":"))
print(f"ET Rules: {len(cve_map)} CVEs with rules cached")
PYEOF
  rm -f "$RULES"
}

# ─── Run all fetchers ─────────────────────────────────────────────
log "=== Starting data fetch ==="
fetch_epss || log "EPSS fetch failed, continuing..."
fetch_nuclei || log "Nuclei fetch failed, continuing..."
fetch_metasploit || log "Metasploit fetch failed, continuing..."
fetch_exploitdb || log "ExploitDB fetch failed, continuing..."
fetch_et_rules || log "ET rules fetch failed, continuing..."
log "=== Data fetch complete ==="
