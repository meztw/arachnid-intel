#!/usr/bin/env python3
"""
Arachnid Intel — API
Suricata 5.0.10 with --enable-profiling
Rubric v3, flowbit tracking, 3-way type classification
"""

import os, json, re, subprocess, shutil, time, collections
from datetime import date
from flask import Flask, request, jsonify

app = Flask(__name__)

UPLOAD_DIR = "/var/data/analysis"
CACHE_DIR = "/var/cache/cve-data"
SURICATA_BIN = "/usr/bin/suricata"
SURICATA_YAML = "/etc/suricata/suricata.yaml"
MAX_UPLOAD_MB = 600
CY = date.today().year

os.makedirs(UPLOAD_DIR, exist_ok=True)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

@app.after_request
def after(r):
    if request.path.startswith("/api/"): r.headers["Content-Type"] = "application/json"
    return r
@app.errorhandler(413)
def e413(e): return jsonify({"error": "File too large"}), 413
@app.errorhandler(Exception)
def eall(e): return jsonify({"error": str(e)}), 500

def load_cache(n):
    try:
        with open(os.path.join(CACHE_DIR, f"{n}.json")) as f: return json.load(f)
    except: return {}

def get_cache_timestamps():
    ts = {}
    for name in ["epss","nuclei","metasploit","exploitdb","et_rules","kev"]:
        path = os.path.join(CACHE_DIR, f"{name}.json")
        try:
            ts[name] = os.path.getmtime(path)
        except: ts[name] = None
    return ts

def xm(line, field):
    m = re.search(rf'{field}\s+([^,;)\s]+)', line)
    return m.group(1).strip() if m else ""

def parse_rules_full(content):
    """Parse rules including disabled (commented) rules and flowbits."""
    active = []; disabled = []; all_rules = []
    for line in content.splitlines():
        line = line.strip()
        if not line: continue
        is_disabled = line.startswith("#")
        raw = line.lstrip("# ") if is_disabled else line

        r = {"raw": raw, "disabled": is_disabled}
        m = re.search(r'\bsid:\s*(\d+)', raw)
        r["sid"] = m.group(1) if m else None
        if not r["sid"]: continue

        m = re.search(r'msg:\s*"([^"]*)"', raw)
        r["msg"] = m.group(1) if m else ""
        r["cves"] = [f"CVE-{c}" for c in re.findall(r'reference:\s*cve\s*,\s*(\d{4}-\d+)', raw, re.I)]
        m = re.search(r'classtype:\s*([^;]+)', raw)
        r["classtype"] = m.group(1).strip() if m else ""
        r["created_at"] = xm(raw, "created_at") or None
        r["signature_severity"] = xm(raw, "signature_severity") or None
        r["affected_product"] = xm(raw, "affected_product") or None
        r["attack_target"] = xm(raw, "attack_target") or None
        r["performance_impact"] = xm(raw, "performance_impact") or "Low"
        r["tag"] = xm(raw, r"\btag") or ""
        r["cvssv3"] = xm(raw, "cvssv3") or None

        hdr = re.match(r'(\w+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)', raw)
        r["dst_net"] = hdr.group(6) if hdr else ""
        atk = r.get("attack_target") or ""
        dst = r.get("dst_net") or ""
        r["target_type"] = "Server" if ("$HOME_NET" in dst or "Server" in atk or "Web_Server" in atk) else "Client"
        r["has_pcre"] = "pcre:" in raw

        # Flowbits
        fb_set = re.findall(r'flowbits:\s*set\s*,\s*([^;,]+)', raw, re.I)
        fb_isset = re.findall(r'flowbits:\s*isset\s*,\s*([^;,]+)', raw, re.I)
        fb_unset = re.findall(r'flowbits:\s*unset\s*,\s*([^;,]+)', raw, re.I)
        fb_toggle = re.findall(r'flowbits:\s*toggle\s*,\s*([^;,]+)', raw, re.I)
        fb_noalert = bool(re.search(r'flowbits:\s*noalert', raw, re.I))
        r["flowbits"] = {
            "set": [x.strip() for x in fb_set],
            "isset": [x.strip() for x in fb_isset],
            "unset": [x.strip() for x in fb_unset],
            "toggle": [x.strip() for x in fb_toggle],
            "noalert": fb_noalert,
        }
        r["has_flowbits"] = bool(fb_set or fb_isset or fb_unset or fb_toggle or fb_noalert)

        # Type classification: CVE, MALWARE, or CVE+MALWARE
        has_cve = len(r["cves"]) > 0
        tag_lower = (r["tag"] or "").lower()
        ct_lower = (r["classtype"] or "").lower()
        is_malware = tag_lower in ("malware",) or ct_lower in ("domain-c2", "trojan-activity")
        if has_cve and is_malware:
            r["sig_type"] = "CVE+MALWARE"
        elif has_cve:
            r["sig_type"] = "CVE"
        else:
            r["sig_type"] = "MALWARE"

        all_rules.append(r)
        if is_disabled:
            disabled.append(r)
        else:
            active.append(r)

    return all_rules, active, disabled

def get_year(rule, field="created_at"):
    v = rule.get(field) or ""
    m = re.match(r'(\d{4})', v)
    return int(m.group(1)) if m else None

def get_cve_year(rule):
    yrs = [int(m) for c in rule.get("cves", []) for m in re.findall(r'CVE-(\d{4})', c)]
    return min(yrs) if yrs else None

def is_cvss(rule):
    try: return get_cve_year(rule) is not None and float(rule.get("cvssv3") or 0) > 0
    except: return False

def eval_cvss(rule):
    try: cvss = float(rule.get("cvssv3") or 0)
    except: cvss = 0.0
    cy2, sy = get_cve_year(rule), get_year(rule)
    yr = min(x for x in [cy2, sy] if x) if any(x for x in [cy2, sy] if x) else None
    if yr is None: return "KEEP", {"type": "CVSS", "cvss": cvss, "detail": "No date"}
    age = CY - yr
    ret = 5 if cvss >= 9 else 3 if cvss >= 7 else 1 if cvss >= 4 else 0
    sl = "Critical" if cvss >= 9 else "High" if cvss >= 7 else "Medium" if cvss >= 4 else "Low"
    return ("RETIRE" if age > ret else "KEEP"), {"type": "CVSS", "cvss": cvss, "severity_label": sl, "sig_year": yr, "age_years": age, "retention_years": ret, "exceeded": age > ret}

def eval_malware(rule, en):
    s = 0; bd = {}
    hx = en.get("has_nuclei") or en.get("has_msf") or en.get("has_edb")
    kv = en.get("is_kev"); ep = en.get("epss_score")
    if kv or hx or (ep and ep >= .15): v, l = 3, "Active"
    elif ep and ep >= .02: v, l = 2, "Inactive"
    elif ep is not None: v, l = -1, "Unknown"
    else: v, l = -3, "Unknown(-3)"
    s += v; bd["campaign"] = {"score": v, "label": l}
    atk = (rule.get("attack_target") or "").strip()
    v, l = (3, "Server") if atk in ("Web_Server", "Server") else (2, "Client")
    s += v; bd["target"] = {"score": v, "label": l}
    prod = (rule.get("affected_product") or "").strip()
    ent = ["Microsoft","Windows","Cisco","Apache","Oracle","VMware","Fortinet","Palo_Alto","Adobe","SAP","Citrix","F5","Ivanti","Atlassian"]
    if any(prod.startswith(k) for k in ent) or kv: v, l = 2, "Enterprise"
    elif prod and prod not in ("NONE","Unknown",""): v, l = 1, "Mid"
    else: v, l = 0, "Low"
    s += v; bd["asset_value"] = {"score": v, "label": l}
    pf = (rule.get("performance_impact") or "").strip()
    if pf == "Low": v, l = 3, "Low"
    elif pf in ("Medium","Moderate"): v, l = 2, "Moderate"
    elif pf == "High": v, l = -1, "High"
    elif pf == "Critical": v, l = -5, "Critical"
    else: v, l = 2, "Default"
    s += v; bd["performance"] = {"score": v, "label": l}
    sv = (rule.get("signature_severity") or "").strip()
    if sv == "Critical": v, l = 2, "Critical"
    elif sv == "Major": v, l = 1, "Major"
    elif sv in ("Minor","Audit","Informational","NONE",""): v, l = -2, "Minor/None"
    else: v, l = 1, "Default"
    s += v; bd["severity"] = {"score": v, "label": l}
    v, l = 1, "Default(Low)"; s += v; bd["fp_rate"] = {"score": v, "label": l}
    cy2 = get_year(rule)
    if cy2:
        age = CY - cy2
        if age <= 2: v, l = 3, f"0-2yr ({age}yr)"
        elif age <= 4: v, l = 2, f"2-4yr ({age}yr)"
        elif age <= 6: v, l = -1, f"4-6yr ({age}yr)"
        else: v, l = -3, f"7+yr ({age}yr)"
        s += v; bd["threat_age"] = {"score": v, "label": l, "age_years": age}
    else:
        bd["threat_age"] = {"score": 0, "label": "Unknown", "age_years": None}
    return s, bd

def enrich_rule(rule, epss, nuclei, msf, edb, kev, et):
    e = {"cvss3": None, "epss_score": None, "epss_percentile": None,
         "has_nuclei": False, "has_msf": False, "has_edb": False,
         "has_et": False, "is_kev": False, "kev_info": None}
    for c in rule.get("cves", []):
        ep2 = epss.get(c)
        if ep2 and (e["epss_score"] is None or ep2["epss"] > e["epss_score"]):
            e["epss_score"] = ep2["epss"]; e["epss_percentile"] = ep2.get("percentile")
        if nuclei.get(c): e["has_nuclei"] = True
        if msf.get(c): e["has_msf"] = True
        if edb.get(c): e["has_edb"] = True
        if et.get(c): e["has_et"] = True
        if kev.get(c): e["is_kev"] = True; e["kev_info"] = kev[c]
    return e

def parse_perf(log_dir):
    perf = {}
    log_path = None
    for root, _, files in os.walk(log_dir):
        for f in files:
            if "rule_perf" in f:
                log_path = os.path.join(root, f); break
        if log_path: break
    if not log_path: return perf
    with open(log_path) as f: content = f.read().strip()
    if content.startswith("{"):
        decoder = json.JSONDecoder(); pos = 0
        while pos < len(content):
            try:
                obj, end = decoder.raw_decode(content, pos)
                for rule in obj.get("rules", []):
                    sid = str(rule.get("signature_id", ""))
                    if sid:
                        checks = rule.get("checks", 0)
                        if sid not in perf or checks > perf[sid].get("checks", 0):
                            perf[sid] = {"checks": checks, "matches": rule.get("matches", 0), "avgticks": str(rule.get("ticks_avg", 0))}
                pos = end
                while pos < len(content) and content[pos] in ' \n\r\t': pos += 1
            except json.JSONDecodeError: pos += 1
    else:
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("-") or line.startswith("N") or line.startswith("=") or line.startswith("Date"): continue
            parts = line.split()
            if len(parts) < 8: continue
            try: int(parts[0]); sid = parts[1]; int(sid)
            except ValueError: continue
            try: perf[sid] = {"checks": int(parts[6]), "matches": int(parts[7]), "avgticks": parts[9] if len(parts) > 9 else "0"}
            except: continue
    return perf

def build_flowbit_map(rules):
    """Build bidirectional flowbit dependency map: set→isset and isset→set."""
    set_map = {}   # flowbit_name → [sids that SET it]
    isset_map = {} # flowbit_name → [sids that ISSET it]
    for r in rules:
        sid = r["sid"]
        fb = r.get("flowbits", {})
        for name in fb.get("set", []):
            set_map.setdefault(name, []).append(sid)
        for name in fb.get("isset", []):
            isset_map.setdefault(name, []).append(sid)
    # For each rule, find connected rules
    connections = {}
    for r in rules:
        sid = r["sid"]; fb = r.get("flowbits", {}); conn = []
        for name in fb.get("set", []):
            for dep_sid in isset_map.get(name, []):
                if dep_sid != sid: conn.append({"sid": dep_sid, "rel": "isset", "flowbit": name})
        for name in fb.get("isset", []):
            for src_sid in set_map.get(name, []):
                if src_sid != sid: conn.append({"sid": src_sid, "rel": "set", "flowbit": name})
        if conn: connections[sid] = conn
    return connections


# ── Routes ──

@app.route("/api/cache/timestamps")
def cache_timestamps():
    ts = get_cache_timestamps()
    result = {}
    for k, v in ts.items():
        if v:
            import datetime
            result[k] = datetime.datetime.fromtimestamp(v).isoformat()
        else:
            result[k] = None
    return jsonify(result)

@app.route("/api/cache/refresh", methods=["POST"])
def cache_refresh():
    try:
        res = subprocess.run(["/usr/local/bin/fetch-data.sh"], capture_output=True, text=True, timeout=300)
        return jsonify({"ok": res.returncode == 0, "output": (res.stdout or "")[-1000:]})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/inhouse/upload", methods=["POST"])
def upload_inhouse():
    if "file" not in request.files: return jsonify({"error": "No file"}), 400
    f = request.files["file"]
    content = f.read().decode("utf-8", errors="replace")
    _, active, _ = parse_rules_full(content)
    cve_map = {}
    for r in active:
        for cve in r.get("cves", []):
            cve_map.setdefault(cve, []).append({"sid": r["sid"], "msg": r["msg"], "classtype": r["classtype"], "severity": r.get("signature_severity", "")})
    return jsonify({"filename": f.filename, "rule_count": len(active), "cve_count": len(cve_map), "cve_coverage": cve_map})

@app.route("/api/analysis/upload-rules", methods=["POST"])
def upload_rules():
    if "file" not in request.files: return jsonify({"error": "No file"}), 400
    f = request.files["file"]
    content = f.read().decode("utf-8", errors="replace")
    all_r, active, disabled = parse_rules_full(content)
    # Save only active rules for Suricata run
    active_content = "\n".join(r["raw"] for r in active)
    with open(os.path.join(UPLOAD_DIR, "current.rules"), "w") as out: out.write(active_content)
    # Save full content for analysis
    with open(os.path.join(UPLOAD_DIR, "current_full.rules"), "w") as out: out.write(content)
    return jsonify({"filename": f.filename, "total": len(all_r), "active": len(active), "disabled": len(disabled)})

@app.route("/api/analysis/upload-pcap", methods=["POST"])
def upload_pcap():
    if "file" not in request.files: return jsonify({"error": "No file"}), 400
    f = request.files["file"]
    path = os.path.join(UPLOAD_DIR, "current.pcap")
    f.save(path)
    return jsonify({"filename": f.filename, "size_mb": round(os.path.getsize(path) / 1048576, 1)})

@app.route("/api/analysis/run", methods=["POST"])
def run_analysis():
    rp = os.path.join(UPLOAD_DIR, "current.rules")
    rp_full = os.path.join(UPLOAD_DIR, "current_full.rules")
    pp = os.path.join(UPLOAD_DIR, "current.pcap")
    if not os.path.exists(rp): return jsonify({"error": "No ruleset uploaded."}), 400
    if not os.path.exists(pp): return jsonify({"error": "No PCAP uploaded."}), 400

    # Parse full ruleset (active + disabled)
    with open(rp_full if os.path.exists(rp_full) else rp) as f:
        all_rules, active_rules, disabled_rules = parse_rules_full(f.read())

    # Build flowbit connections
    fb_conn = build_flowbit_map(all_rules)

    ld = os.path.join(UPLOAD_DIR, "suricata-logs")
    if os.path.exists(ld): shutil.rmtree(ld)
    os.makedirs(ld)

    t0 = time.time()
    try:
        res = subprocess.run([
            SURICATA_BIN, "-c", SURICATA_YAML,
            "-r", pp, "-S", rp, "-l", ld, "-k", "none", "-v",
            "--set", "profiling.rules.limit=99999",
            "--set", "profiling.rules.json=no",
        ], capture_output=True, text=True, timeout=600)
        sok = res.returncode == 0
        serr = (res.stderr or "")[-2000:]
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Suricata timed out (10min)"}), 500
    except FileNotFoundError:
        return jsonify({"error": "Suricata not found"}), 500
    elapsed = round(time.time() - t0, 1)

    ac = {}
    ep = os.path.join(ld, "eve.json")
    if os.path.exists(ep):
        with open(ep) as ef:
            for line in ef:
                try:
                    ev = json.loads(line)
                    if ev.get("event_type") == "alert":
                        sid = str(ev.get("alert", {}).get("signature_id", ""))
                        ac[sid] = ac.get(sid, 0) + 1
                except: continue

    perf = parse_perf(ld)
    ed = {k: load_cache(k) for k in ["epss", "nuclei", "metasploit", "exploitdb", "kev", "et_rules"]}

    scored = []; rc = rv = kc = 0
    yc_total = collections.Counter()
    yc_cve = collections.Counter()
    yc_mal = collections.Counter()
    yc_both = collections.Counter()
    tc = {"CVE": 0, "MALWARE": 0, "CVE+MALWARE": 0}

    for rule in active_rules:
        sid = rule["sid"]
        en = enrich_rule(rule, ed["epss"], ed["nuclei"], ed["metasploit"], ed["exploitdb"], ed["kev"], ed["et_rules"])
        alerts = ac.get(sid, 0)
        prof = perf.get(sid, {})
        checks = prof.get("checks", 0)

        cy2 = get_year(rule)
        st = rule["sig_type"]
        tc[st] = tc.get(st, 0) + 1
        if cy2:
            yc_total[cy2] += 1
            if st == "CVE": yc_cve[cy2] += 1
            elif st == "MALWARE": yc_mal[cy2] += 1
            else: yc_both[cy2] += 1

        if is_cvss(rule):
            verdict, rd = eval_cvss(rule)
            rs2 = None; rb = None
        else:
            rs2, rb = eval_malware(rule, en)
            rd = None
            verdict = "KEEP" if rs2 >= 11 else "REVIEW" if rs2 >= 9 else "RETIRE"

        if verdict == "RETIRE":
            if en.get("is_kev") or (en.get("epss_score") is not None and en["epss_score"] >= 0.15):
                verdict = "KEEP"

        if verdict == "RETIRE": rc += 1
        elif verdict == "REVIEW": rv += 1
        else: kc += 1

        scored.append({
            "sid": sid, "msg": rule["msg"], "cves": rule["cves"],
            "classtype": rule["classtype"], "created_at": rule["created_at"],
            "signature_severity": rule["signature_severity"],
            "affected_product": rule["affected_product"],
            "target_type": rule["target_type"],
            "performance_impact": rule["performance_impact"],
            "has_pcre": rule["has_pcre"], "tag": rule["tag"],
            "sig_type": st, "checks": checks, "alerts": alerts,
            "enrichment": en, "verdict": verdict,
            "rubric_score": rs2, "rubric_breakdown": rb, "rubric_detail": rd,
            "flowbits": rule["flowbits"],
            "has_flowbits": rule["has_flowbits"],
            "flowbit_connections": fb_conn.get(sid, []),
            "disabled": False,
        })

    # Add disabled rules to the list
    for rule in disabled_rules:
        scored.append({
            "sid": rule["sid"], "msg": rule["msg"], "cves": rule["cves"],
            "classtype": rule["classtype"], "created_at": rule["created_at"],
            "signature_severity": rule["signature_severity"],
            "affected_product": rule["affected_product"],
            "target_type": rule["target_type"],
            "sig_type": rule["sig_type"], "checks": 0, "alerts": 0,
            "enrichment": {}, "verdict": "DISABLED",
            "rubric_score": None, "rubric_breakdown": None, "rubric_detail": None,
            "flowbits": rule["flowbits"],
            "has_flowbits": rule["has_flowbits"],
            "flowbit_connections": fb_conn.get(rule["sid"], []),
            "disabled": True,
        })

    order = {"RETIRE": 0, "REVIEW": 1, "KEEP": 2, "DISABLED": 3}
    scored.sort(key=lambda r: (order.get(r["verdict"], 9), r.get("rubric_score") or 0))

    all_years = sorted(set(list(yc_total.keys()) + list(yc_cve.keys()) + list(yc_mal.keys()) + list(yc_both.keys())))
    growth = []
    cum_t = cum_c = cum_m = cum_b = 0
    for y in all_years:
        cum_t += yc_total[y]; cum_c += yc_cve[y]; cum_m += yc_mal[y]; cum_b += yc_both[y]
        growth.append({"year": y, "total": cum_t, "cve": cum_c, "malware": cum_m, "both": cum_b})

    return jsonify({
        "summary": {
            "total_rules": len(all_rules), "active_rules": len(active_rules),
            "disabled_rules": len(disabled_rules),
            "total_alerts": sum(ac.values()),
            "suricata_elapsed_sec": elapsed, "suricata_ok": sok,
            "profiled_rules": len(perf),
            "retire_count": rc, "review_count": rv, "keep_count": kc,
            "kev_hits": sum(1 for r in scored if r.get("enrichment", {}).get("is_kev")),
            "type_counts": tc, "growth": growth,
        },
        "rules": scored,
    })

@app.route("/api/analysis/status")
def status():
    return jsonify({
        "rules_uploaded": os.path.exists(os.path.join(UPLOAD_DIR, "current.rules")),
        "pcap_uploaded": os.path.exists(os.path.join(UPLOAD_DIR, "current.pcap")),
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
