#!/usr/bin/env python3
"""
Arachnid Intel — API
Suricata 5.0.10 compiled with --enable-profiling for rule_perf.log
Rubric v3 scoring, inhouse rules coverage
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

def xm(line, field):
    m = re.search(rf'{field}\s+([^,;)\s]+)', line)
    return m.group(1).strip() if m else ""

def parse_rules(content):
    rules = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        r = {"raw": line}
        m = re.search(r'\bsid:\s*(\d+)', line)
        r["sid"] = m.group(1) if m else None
        if not r["sid"]: continue
        m = re.search(r'msg:\s*"([^"]*)"', line)
        r["msg"] = m.group(1) if m else ""
        r["cves"] = [f"CVE-{c}" for c in re.findall(r'reference:\s*cve\s*,\s*(\d{4}-\d+)', line, re.I)]
        m = re.search(r'classtype:\s*([^;]+)', line)
        r["classtype"] = m.group(1).strip() if m else ""
        r["created_at"] = xm(line, "created_at") or None
        r["signature_severity"] = xm(line, "signature_severity") or None
        r["affected_product"] = xm(line, "affected_product") or None
        r["attack_target"] = xm(line, "attack_target") or None
        r["performance_impact"] = xm(line, "performance_impact") or "Low"
        r["tag"] = xm(line, r"\btag") or ""
        r["cvssv3"] = xm(line, "cvssv3") or None
        hdr = re.match(r'(\w+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)', line)
        r["dst_net"] = hdr.group(6) if hdr else ""
        atk = r.get("attack_target") or ""
        dst = r.get("dst_net") or ""
        r["target_type"] = "Server" if ("$HOME_NET" in dst or "Server" in atk or "Web_Server" in atk) else "Client"
        r["has_pcre"] = "pcre:" in line
        rules.append(r)
    return rules

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
    """Parse rule_perf.log — handles both plain text table and JSON formats."""
    perf = {}
    log_path = None
    for root, _, files in os.walk(log_dir):
        for f in files:
            if "rule_perf" in f:
                log_path = os.path.join(root, f)
                break
        if log_path: break
    if not log_path: return perf

    with open(log_path) as f:
        content = f.read().strip()

    # JSON format: multiple JSON objects concatenated (one per sort order)
    if content.startswith("{"):
        decoder = json.JSONDecoder()
        pos = 0
        first_section = True
        while pos < len(content):
            try:
                obj, end = decoder.raw_decode(content, pos)
                # Only use the FIRST sort section (sorted by ticks = worst performers)
                if first_section:
                    for rule in obj.get("rules", []):
                        sid = str(rule.get("signature_id", ""))
                        if sid:
                            perf[sid] = {
                                "checks": rule.get("checks", 0),
                                "matches": rule.get("matches", 0),
                                "avgticks": str(rule.get("ticks_avg", rule.get("avgticks", 0))),
                            }
                    first_section = False
                pos = end
                while pos < len(content) and content[pos] in ' \n\r\t':
                    pos += 1
            except json.JSONDecodeError:
                pos += 1
        return perf

    # Plain text table format
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("-") or line.startswith("N") or line.startswith("=") or line.startswith("Date"):
            continue
        parts = line.split()
        if len(parts) < 8: continue
        try:
            int(parts[0])
            sid = parts[1]; int(sid)
        except ValueError: continue
        try:
            perf[sid] = {
                "checks": int(parts[6]),
                "matches": int(parts[7]),
                "avgticks": parts[9] if len(parts) > 9 else "0"
            }
        except (ValueError, IndexError): continue
    return perf


# ── Inhouse Rules ──

@app.route("/api/inhouse/upload", methods=["POST"])
def upload_inhouse():
    if "file" not in request.files: return jsonify({"error": "No file"}), 400
    f = request.files["file"]
    content = f.read().decode("utf-8", errors="replace")
    rules = parse_rules(content)
    cve_map = {}
    for r in rules:
        for cve in r.get("cves", []):
            cve_map.setdefault(cve, []).append({
                "sid": r["sid"], "msg": r["msg"],
                "classtype": r["classtype"], "severity": r.get("signature_severity", ""),
            })
    return jsonify({"filename": f.filename, "rule_count": len(rules), "cve_count": len(cve_map), "cve_coverage": cve_map})


# ── Analysis Routes ──

@app.route("/api/analysis/upload-rules", methods=["POST"])
def upload_rules():
    if "file" not in request.files: return jsonify({"error": "No file"}), 400
    f = request.files["file"]
    content = f.read().decode("utf-8", errors="replace")
    rules = parse_rules(content)
    with open(os.path.join(UPLOAD_DIR, "current.rules"), "w") as out: out.write(content)
    return jsonify({"filename": f.filename, "rule_count": len(rules)})

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
    pp = os.path.join(UPLOAD_DIR, "current.pcap")
    if not os.path.exists(rp): return jsonify({"error": "No ruleset uploaded."}), 400
    if not os.path.exists(pp): return jsonify({"error": "No PCAP uploaded."}), 400

    with open(rp) as f: rules = parse_rules(f.read())

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
        sout = (res.stdout or "")[-500:]
        # Save full stderr for debugging
        with open(os.path.join(ld, "suricata-debug.log"), "w") as dbg:
            dbg.write("=== STDOUT ===\n")
            dbg.write(res.stdout or "")
            dbg.write("\n=== STDERR ===\n")
            dbg.write(res.stderr or "")
            dbg.write(f"\n=== RETURN CODE: {res.returncode} ===\n")
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Suricata timed out (10min)"}), 500
    except FileNotFoundError:
        return jsonify({"error": "Suricata not found"}), 500
    elapsed = round(time.time() - t0, 1)

    # Parse alerts from eve.json
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

    # Parse rule profiling (checks/matches from rule_perf.log)
    perf = parse_perf(ld)

    # Load enrichment
    ed = {k: load_cache(k) for k in ["epss", "nuclei", "metasploit", "exploitdb", "kev", "et_rules"]}

    scored = []; rc = rv = kc = 0
    yc = collections.Counter()
    tc = {"CVE": 0, "MALWARE": 0}

    for rule in rules:
        sid = rule["sid"]
        en = enrich_rule(rule, ed["epss"], ed["nuclei"], ed["metasploit"], ed["exploitdb"], ed["kev"], ed["et_rules"])
        alerts = ac.get(sid, 0)
        prof = perf.get(sid, {})
        checks = prof.get("checks", 0)
        matches = prof.get("matches", 0)

        cy2 = get_year(rule)
        if cy2: yc[cy2] += 1

        if is_cvss(rule):
            st = "CVE"; tc["CVE"] += 1
            verdict, rd = eval_cvss(rule)
            rs2 = None; rb = None
        else:
            st = "MALWARE"; tc["MALWARE"] += 1
            rs2, rb = eval_malware(rule, en)
            rd = None
            verdict = "KEEP" if rs2 >= 11 else "REVIEW" if rs2 >= 9 else "RETIRE"

        # KEV or high EPSS: NEVER retire
        if verdict == "RETIRE":
            if en.get("is_kev") or (en.get("epss_score") is not None and en["epss_score"] >= 0.15):
                verdict = "KEEP"

        # Only RETIRE if the rule appears in the perf log (worst performers)
        # Rules that meet RETIRE criteria but aren't in perf log → REVIEW
        if verdict == "RETIRE" and sid not in perf:
            verdict = "REVIEW"

        if verdict == "RETIRE": rc += 1
        elif verdict == "REVIEW": rv += 1
        else: kc += 1

        scored.append({
            "sid": sid, "msg": rule["msg"], "cves": rule["cves"],
            "classtype": rule["classtype"], "created_at": rule["created_at"],
            "signature_severity": rule["signature_severity"],
            "affected_product": rule["affected_product"],
            "attack_target": rule["attack_target"], "target_type": rule["target_type"],
            "performance_impact": rule["performance_impact"],
            "has_pcre": rule["has_pcre"], "tag": rule["tag"],
            "sig_type": st, "checks": checks, "matches": matches, "alerts": alerts,
            "enrichment": en, "verdict": verdict,
            "rubric_score": rs2, "rubric_breakdown": rb, "rubric_detail": rd,
        })

    order = {"RETIRE": 0, "REVIEW": 1, "KEEP": 2}
    scored.sort(key=lambda r: (order.get(r["verdict"], 9), r.get("rubric_score") or 0))

    growth = [{"year": y, "count": yc[y]} for y in sorted(yc)]
    cum = 0
    for g in growth: cum += g["count"]; g["cumulative"] = cum

    return jsonify({
        "summary": {
            "total_rules": len(rules), "total_alerts": sum(ac.values()),
            "suricata_elapsed_sec": elapsed, "suricata_ok": sok,
            "suricata_errors": serr, "suricata_output": sout,
            "profiled_rules": len(perf),
            "retire_count": rc, "review_count": rv, "keep_count": kc,
            "kev_hits": sum(1 for r in scored if r["enrichment"]["is_kev"]),
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
