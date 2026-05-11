# Arachnid Intel — Claude Code Handoff

## Project Overview

Arachnid Intel is a Dockerized web application for the SLR (Security Lab Research) team that provides:
1. **CVE Feed** — Live CVE intelligence from FediSec feed enriched with EPSS, CVSS, Nuclei, Metasploit, ExploitDB, ET Rules, CISA KEV
2. **CVE Lookup** — Upload a list of CVE IDs and get enrichment data for each
3. **Ruleset Analysis** — Upload Suricata rules + PCAP, run Suricata 5.0.10 (compiled with `--enable-profiling`), score rules with Rubric v3, identify retirement candidates

## Architecture

```
Docker Container (Ubuntu 22.04)
├── Nginx (port 80) — serves frontend + proxies /api/* to Flask
├── Flask/Gunicorn (port 5000) — API backend
├── Suricata 5.0.10 (compiled from source with --enable-profiling)
├── Cron (daily 03:00 UTC) — refreshes enrichment data
└── /var/cache/cve-data/ — cached JSON files from external sources
```

### Data Sources (fetched daily by scripts/fetch-data.sh)
- **EPSS** — https://epss.empiricalsecurity.com/epss_scores-current.csv.gz → epss.json
- **Nuclei** — https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/refs/heads/main/cves.json → nuclei.json  
- **Metasploit** — https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json → metasploit.json
- **ExploitDB** — https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv → exploitdb.json
- **ET Rules** — https://rules.emergingthreats.net/open/suricata-5.0/emerging-all.rules → et_rules.json
- **CISA KEV** — https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json → kev.json

### API Endpoints
- `GET /api/epss` — static JSON (EPSS scores)
- `GET /api/nuclei` — static JSON (Nuclei templates)
- `GET /api/metasploit` — static JSON (MSF modules by CVE)
- `GET /api/exploitdb` — static JSON (EDB entries by CVE)
- `GET /api/et-rules` — static JSON (ET rules by CVE)
- `GET /api/kev` — static JSON (CISA KEV by CVE)
- `GET /api/cache/timestamps` — last update time for each data source
- `POST /api/cache/refresh` — manually trigger data refresh
- `POST /api/inhouse/upload` — upload .rules file, returns CVE→SID coverage map
- `POST /api/analysis/upload-rules` — upload ruleset for analysis
- `POST /api/analysis/upload-pcap` — upload PCAP file
- `POST /api/analysis/run` — run Suricata + Rubric v3 scoring
- `GET /api/analysis/status` — check upload status

## Frontend (React + Vite)

### Tech Stack
- React 18 + Vite 5
- No UI library — all inline styles
- Theme: LevelBlue/SpiderLabs inspired dark navy (`#080c1a`) with blue accents (`#2563eb`)
- Font: Inter (Google Fonts)

### Three Tabs
1. **📡 CVE Feed** — FediSec feed with all enrichment columns, inhouse rules overlay, severity/EPSS filters, page size selector, sortable columns
2. **🔍 CVE Lookup** — Upload CVE list (.txt), enrich each CVE against all cached data
3. **🔬 Ruleset Analysis** — Upload rules + PCAP, run Suricata, view scored results with charts

## Rubric v3 (Aggressive) — Scoring Logic

### CVE-based rules (has CVE reference + non-zero cvssv3 metadata)
Pure age-vs-retention check:
- Critical (CVSS 9.0-10.0): 5 year retention
- High (CVSS 7.0-8.9): 3 year retention  
- Medium (CVSS 4.0-6.9): 1 year retention
- If age > retention → RETIRE, else KEEP

### Malware/Non-CVSS rules (max score: 17)
| Category | Values |
|----------|--------|
| Campaign | Active(+3), Inactive(+2), Unknown(-1), No PoC(-3) |
| Target | Server(+3), Client(+2) |
| Asset Value | Enterprise(+2), Mid(+1), Low(0) |
| Performance | Low(+3), Moderate(+2), High(-1), Critical(-5) |
| Severity | Critical(+2), Major(+1), Minor/None(-2) |
| FP Rate | Default Low(+1) |
| Threat Age | 0-2yr(+3), 2-4yr(+2), 4-6yr(-1), 7+yr(-3) |

Thresholds: ≥11 KEEP, 9-10 REVIEW, <9 RETIRE

### Protection Rules
- KEV or EPSS ≥ 0.15 → NEVER retire (override to KEEP)

## Rule Type Classification (3-way)
- **CVE** — has CVE reference, no malware indicators
- **MALWARE** — no CVE, or tag=malware, or classtype=domain-c2/trojan-activity
- **CVE+MALWARE** — has CVE AND (tag=malware OR classtype=domain-c2/trojan-activity)

## Flowbit Tracking
Rules using `flowbits:set`, `flowbits:isset`, `flowbits:unset`, `flowbits:toggle`, `flowbits:noalert` are parsed. A bidirectional dependency map is built:
- Rules that SET a flowbit → linked to rules that ISSET the same flowbit
- When expanding a rule row, connected rules are shown
- **Critical for retirement decisions**: disabling a SET rule breaks all ISSET rules that depend on it

## Key Files

```
cve-feed-explorer/
├── Dockerfile              # 3-stage: node build, suricata compile, runtime
├── docker-compose.yml      # Port 8082, 2GB memory limit
├── nginx.conf              # Static APIs + Flask proxy
├── package.json            # Vite + React
├── vite.config.js
├── index.html
├── deploy.ps1              # PowerShell deployment script
├── .dockerignore
├── api/
│   ├── server.py           # Flask API (analysis, inhouse, cache management)
│   └── requirements.txt
├── scripts/
│   ├── entrypoint.sh       # Container startup (fetch data, start cron, gunicorn, nginx)
│   ├── fetch-data.sh       # Downloads all enrichment data
│   ├── patch-suricata-yaml.sh  # Enables profiling in suricata.yaml
│   └── suricata-analysis.yaml  # (may exist) custom suricata config
└── src/
    ├── main.jsx            # React entry point
    └── App.jsx             # All UI components
```

## Current State & Pending Changes

The `api/server.py` has been updated with ALL backend changes. The `src/App.jsx` needs to be rebuilt to match. Here's what needs to change in the frontend:

### Ruleset Analysis Tab Changes Needed:
1. **Reverted retire logic** — no perf log gate, all rubric RETIRE candidates show as RETIRE (backend done)
2. **Pie chart**: 3-way — CVE, MALWARE, CVE+MALWARE (backend returns `type_counts` with all 3)
3. **Line chart**: 4 lines — Total, CVE, MALWARE, CVE+MALWARE (backend returns `growth` with all 4 per year)
4. **Summary cards**: Total Rules, Active Rules, Disabled Rules, Profiled, Alerts, Retire, Review, Keep, CISA KEV, Suricata Runtime
5. **All columns sortable**: SID, Score, Verdict, Type, Checks, Message, Flowbit, CVEs, EPSS, KEV
6. **Flowbit column**: Shows flowbit indicator, expanded row shows connected rules (set↔isset dependencies)
7. **Disabled rules** appear in the table with verdict="DISABLED"

### CVE Feed Tab Changes Needed:
1. **Remove CVE list upload** (moved to CVE Lookup tab)
2. **Add data freshness display** above inhouse rules upload — show when each data source was last updated
3. **Add "Refresh Data" button** that calls `POST /api/cache/refresh`

### CVE Lookup Tab:
- Already implemented, no changes needed

## Docker Build Notes
- Suricata 5.0.10 compiled from source with `--enable-profiling` in stage 2
- Source: https://www.openinfosecfoundation.org/download/suricata-5.0.10.tar.gz
- `./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --enable-profiling --disable-gccmarch-native`
- Runtime passes `--set profiling.rules.limit=99999 --set profiling.rules.json=no` to get plain text rule_perf.log
- If profiling still outputs JSON, parser handles both formats
- First build takes 10-20 minutes (compiling Suricata)

## Theme Constants (use in App.jsx)
```javascript
const T = {
  bg:"#080c1a", bgC:"#0c1228", bgH:"#111936", bgX:"#0e1530",
  bd:"#1a2347", ac:"#2563eb", al:"#3b82f6", ag:"rgba(37,99,235,.12)",
  tx:"#c7d2e0", tm:"#5b6b82", td:"#3a4a63", wh:"#e8edf5",
  r:"#ef4444", o:"#f59e0b", y:"#eab308", g:"#22c55e", p:"#a855f7", cy:"#06b6d4",
};
```

## API Response Format for /api/analysis/run

```json
{
  "summary": {
    "total_rules": 3485,
    "active_rules": 3400,
    "disabled_rules": 85,
    "total_alerts": 0,
    "suricata_elapsed_sec": 6.3,
    "suricata_ok": true,
    "profiled_rules": 150,
    "retire_count": 1200,
    "review_count": 500,
    "keep_count": 1700,
    "kev_hits": 497,
    "type_counts": {"CVE": 1500, "MALWARE": 1800, "CVE+MALWARE": 185},
    "growth": [
      {"year": 2017, "total": 50, "cve": 30, "malware": 15, "both": 5},
      {"year": 2018, "total": 150, "cve": 80, "malware": 55, "both": 15}
    ]
  },
  "rules": [
    {
      "sid": "4102357",
      "msg": "SLR Alert - ...",
      "cves": ["CVE-2014-2820"],
      "classtype": "attempted-admin",
      "created_at": "2019_02_16",
      "signature_severity": "Major",
      "affected_product": "Windows_XP_Vista_7_8_10",
      "target_type": "Server",
      "sig_type": "CVE",
      "checks": 41,
      "alerts": 0,
      "verdict": "RETIRE",
      "rubric_score": null,
      "rubric_detail": {"type":"CVSS","cvss":9.3,...,"exceeded":true},
      "rubric_breakdown": null,
      "flowbits": {"set":[],"isset":["http.host.found"],"unset":[],"toggle":[],"noalert":false},
      "has_flowbits": true,
      "flowbit_connections": [{"sid":"4100001","rel":"set","flowbit":"http.host.found"}],
      "disabled": false,
      "enrichment": {"epss_score":0.16,"is_kev":false,"has_nuclei":true,...}
    }
  ]
}
```

## Running Locally for Development

```powershell
# Extract and enter project
cd cve-feed-explorer

# Docker build + run
docker compose down
docker compose build --no-cache  # first time or after Dockerfile changes
docker compose up -d

# Quick rebuild (frontend/API only, cached Suricata layer)
docker compose up -d --build

# View logs
docker compose logs -f cve-feed

# Debug API
docker exec cve-feed-explorer cat /var/log/api-error.log
docker exec cve-feed-explorer cat /var/data/analysis/suricata-logs/suricata-debug.log

# Check profiling
docker exec cve-feed-explorer head -5 /var/data/analysis/suricata-logs/rule_perf.log

# Port: http://localhost:8082
```

## SID Conventions (SLRIDS)
- CVE-based: CVE number with dashes removed (e.g., CVE-2021-40000 → sid:202140000)
- Malware with no CVE: creation date as YYYYMMDD
- SLR inhouse rules: SID range 4100000–4199999
