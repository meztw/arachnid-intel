#!/bin/sh
CACHE="/var/cache/cve-data"
mkdir -p "$CACHE"
log() { echo "[$(date -Iseconds)] $1"; }

fetch_epss() {
  log "Fetching EPSS scores..."
  curl -sfL -o "$CACHE/epss.csv.gz" "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz" || return 1
  gunzip -f "$CACHE/epss.csv.gz" 2>/dev/null
  python3 << 'PY'
import json
out={}
with open("/var/cache/cve-data/epss.csv",encoding="utf-8",errors="replace") as f:
    for l in f:
        l=l.strip()
        if not l or l.startswith("#") or l.startswith("cve,"): continue
        p=l.split(",")
        if len(p)>=3 and p[0].startswith("CVE-"):
            try: out[p[0]]={"epss":float(p[1]),"percentile":float(p[2])}
            except: pass
with open("/var/cache/cve-data/epss.json","w") as f: json.dump(out,f,separators=(",",":"))
print(f"EPSS: {len(out)} scores cached")
PY
  rm -f "$CACHE/epss.csv"
}
fetch_nuclei() {
  log "Fetching Nuclei templates..."
  curl -sfL -o "$CACHE/nuclei_raw.ndjson" "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/refs/heads/main/cves.json" || return 1
  python3 << 'PY'
import json
out={}
with open("/var/cache/cve-data/nuclei_raw.ndjson",encoding="utf-8",errors="replace") as f:
    for l in f:
        l=l.strip()
        if not l: continue
        try: obj=json.loads(l)
        except: continue
        cid=obj.get("ID","")
        if not cid.startswith("CVE-"): continue
        info=obj.get("Info",{});cl=info.get("Classification",{})
        out[cid]={"name":info.get("Name",""),"severity":info.get("Severity",""),"cvss":cl.get("CVSSScore",""),"file_path":obj.get("file_path","")}
with open("/var/cache/cve-data/nuclei.json","w") as f: json.dump(out,f,separators=(",",":"))
print(f"Nuclei: {len(out)} templates cached")
PY
  rm -f "$CACHE/nuclei_raw.ndjson"
}
fetch_metasploit() {
  log "Fetching Metasploit..."
  curl -sfL -o "$CACHE/msf_raw.json" "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json" || return 1
  python3 << 'PY'
import json
with open("/var/cache/cve-data/msf_raw.json",encoding="utf-8",errors="replace") as f: data=json.load(f)
cm={}
for k,mod in data.items():
    refs=mod.get("references",[]);cves=[r for r in refs if r.startswith("CVE-")]
    if not cves: continue
    entry={"name":mod.get("name",""),"path":mod.get("path",k),"rank":mod.get("rank",0)}
    for c in cves: cm.setdefault(c,[]).append(entry)
with open("/var/cache/cve-data/metasploit.json","w") as f: json.dump(cm,f,separators=(",",":"))
print(f"Metasploit: {len(cm)} CVEs cached")
PY
  rm -f "$CACHE/msf_raw.json"
}
fetch_exploitdb() {
  log "Fetching Exploit-DB..."
  curl -sfL -o "$CACHE/exploitdb.csv" "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv" || return 1
  python3 << 'PY'
import csv,json,re
cm={}
with open("/var/cache/cve-data/exploitdb.csv",encoding="utf-8",errors="replace") as f:
    reader=csv.reader(f);header=next(reader,None)
    ci=None
    for i,h in enumerate(header or []):
        if "codes" in h.lower(): ci=i; break
    if ci is None: ci=11
    for row in reader:
        try:
            if len(row)<=ci: continue
            eid=row[0].strip();desc=row[2].strip() if len(row)>2 else "";dt=row[3].strip() if len(row)>3 else ""
            for c in re.findall(r"CVE-\d{4}-\d+",row[ci]):
                cm.setdefault(c,[]).append({"id":eid,"title":desc,"date":dt,"url":f"https://www.exploit-db.com/exploits/{eid}"})
        except: pass
with open("/var/cache/cve-data/exploitdb.json","w") as f: json.dump(cm,f,separators=(",",":"))
print(f"ExploitDB: {len(cm)} CVEs cached")
PY
  rm -f "$CACHE/exploitdb.csv"
}
fetch_et_rules() {
  log "Fetching ET rules..."
  curl -sfL -o "$CACHE/emerging-all.rules" "https://rules.emergingthreats.net/open/suricata-5.0/emerging-all.rules" || return 1
  python3 << 'PY'
import re,json
cm={}
with open("/var/cache/cve-data/emerging-all.rules",encoding="utf-8",errors="replace") as f:
    for l in f:
        l=l.strip()
        if not l or l.startswith("#"): continue
        cves=re.findall(r"reference:\s*cve\s*,\s*(\d{4}-\d+)",l,re.I)
        if not cves: continue
        msg_m=re.search(r'msg:\s*"([^"]*)"',l);msg=msg_m.group(1) if msg_m else ""
        sid_m=re.search(r'\bsid:\s*(\d+)',l);sid=sid_m.group(1) if sid_m else ""
        ct_m=re.search(r'classtype:\s*([^;]+)',l);ct=ct_m.group(1).strip() if ct_m else ""
        for c in cves: cm.setdefault(f"CVE-{c}",[]).append({"sid":sid,"msg":msg,"classtype":ct})
with open("/var/cache/cve-data/et_rules.json","w") as f: json.dump(cm,f,separators=(",",":"))
print(f"ET Rules: {len(cm)} CVEs cached")
PY
  rm -f "$CACHE/emerging-all.rules"
}
fetch_kev() {
  log "Fetching CISA KEV..."
  curl -sfL -o "$CACHE/kev_raw.json" "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" || return 1
  python3 << 'PY'
import json
with open("/var/cache/cve-data/kev_raw.json",encoding="utf-8",errors="replace") as f: data=json.load(f)
km={}
for v in data.get("vulnerabilities",[]):
    c=v.get("cveID","")
    if c.startswith("CVE-"):
        km[c]={"vendor":v.get("vendorProject",""),"product":v.get("product",""),"name":v.get("vulnerabilityName",""),"dateAdded":v.get("dateAdded",""),"dueDate":v.get("dueDate",""),"ransomware":v.get("knownRansomwareCampaignUse","Unknown")}
with open("/var/cache/cve-data/kev.json","w") as f: json.dump(km,f,separators=(",",":"))
print(f"CISA KEV: {len(km)} cached")
PY
  rm -f "$CACHE/kev_raw.json"
}

log "=== Starting data fetch ==="
fetch_epss || log "EPSS failed"
fetch_nuclei || log "Nuclei failed"
fetch_metasploit || log "Metasploit failed"
fetch_exploitdb || log "ExploitDB failed"
fetch_et_rules || log "ET rules failed"
fetch_kev || log "CISA KEV failed"
log "=== Data fetch complete ==="
