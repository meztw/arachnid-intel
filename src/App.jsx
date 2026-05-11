import React, { useState, useEffect, useMemo, useRef, useCallback } from "react";

const T = {
  bg:"#080c1a", bgC:"#0c1228", bgH:"#111936", bgX:"#0e1530",
  bd:"#1a2347", ac:"#2563eb", al:"#3b82f6", ag:"rgba(37,99,235,.12)",
  tx:"#c7d2e0", tm:"#5b6b82", td:"#3a4a63", wh:"#e8edf5",
  r:"#ef4444", o:"#f59e0b", y:"#eab308", g:"#22c55e", p:"#a855f7", cy:"#06b6d4",
};

const FEED_URL = "https://fedisecfeeds.github.io/fedi_cve_feed.json";

const sevColor = (s) => {
  const x = (s || "").toLowerCase();
  if (x.includes("critical")) return T.r;
  if (x.includes("high")) return T.o;
  if (x.includes("medium")) return T.y;
  if (x.includes("low")) return T.g;
  return T.tm;
};
const cvssSev = (c) => {
  const n = parseFloat(c);
  if (isNaN(n)) return "";
  if (n >= 9) return "Critical";
  if (n >= 7) return "High";
  if (n >= 4) return "Medium";
  return "Low";
};
const epssSev = (e) => {
  const n = parseFloat(e);
  if (isNaN(n)) return "";
  if (n >= 0.5) return "Critical";
  if (n >= 0.15) return "High";
  if (n >= 0.02) return "Medium";
  return "Low";
};
const verdictColor = (v) => ({RETIRE: T.r, REVIEW: T.o, KEEP: T.g, DISABLED: T.tm}[v] || T.tm);
const typeColor = (t) => ({CVE: T.ac, MALWARE: T.p, "CVE+MALWARE": T.cy}[t] || T.tm);
const fmtTime = (iso) => {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    const now = new Date();
    const diff = (now - d) / 1000;
    if (diff < 60) return "just now";
    if (diff < 3600) return Math.floor(diff/60) + "m ago";
    if (diff < 86400) return Math.floor(diff/3600) + "h ago";
    return Math.floor(diff/86400) + "d ago";
  } catch { return "—"; }
};

// ───────────────────────────── Styles ─────────────────────────────
const S = {
  page: { minHeight:"100vh", background:T.bg, color:T.tx, fontFamily:"'Inter',-apple-system,sans-serif", fontSize:13 },
  header: { padding:"20px 32px", borderBottom:`1px solid ${T.bd}`, background:T.bgC },
  title: { fontSize:22, fontWeight:800, color:T.wh, letterSpacing:.5, margin:0 },
  subtitle: { fontSize:12, color:T.tm, marginTop:4 },
  tabs: { display:"flex", gap:4, padding:"0 32px", borderBottom:`1px solid ${T.bd}`, background:T.bgC },
  tab: (active) => ({
    padding:"14px 22px", cursor:"pointer", fontSize:13, fontWeight:600,
    color: active ? T.wh : T.tm, borderBottom: `2px solid ${active ? T.ac : "transparent"}`,
    background: active ? T.ag : "transparent", transition:"all .15s",
  }),
  content: { padding:"24px 32px" },
  card: { background:T.bgC, border:`1px solid ${T.bd}`, borderRadius:8, padding:16, marginBottom:16 },
  cardTitle: { fontSize:11, fontWeight:700, textTransform:"uppercase", letterSpacing:.8, color:T.tm, marginBottom:10 },
  btn: (variant="primary") => ({
    padding:"8px 14px", fontSize:12, fontWeight:600, borderRadius:6, cursor:"pointer",
    border: variant === "primary" ? "none" : `1px solid ${T.bd}`,
    background: variant === "primary" ? T.ac : "transparent",
    color: variant === "primary" ? "#fff" : T.tx,
    transition:"all .15s",
  }),
  input: {
    padding:"8px 10px", fontSize:12, background:T.bgX, border:`1px solid ${T.bd}`,
    borderRadius:6, color:T.tx, outline:"none", fontFamily:"inherit",
  },
  select: {
    padding:"8px 10px", fontSize:12, background:T.bgX, border:`1px solid ${T.bd}`,
    borderRadius:6, color:T.tx, outline:"none", cursor:"pointer", fontFamily:"inherit",
  },
  table: { width:"100%", borderCollapse:"collapse", fontSize:12 },
  th: (sortable=true) => ({
    textAlign:"left", padding:"10px 12px", fontSize:11, fontWeight:700, textTransform:"uppercase",
    letterSpacing:.5, color:T.tm, borderBottom:`1px solid ${T.bd}`, background:T.bgH,
    cursor: sortable ? "pointer" : "default", userSelect:"none", whiteSpace:"nowrap",
  }),
  td: { padding:"10px 12px", borderBottom:`1px solid ${T.bd}`, verticalAlign:"top" },
  trH: { transition:"background .15s" },
  badge: (color) => ({
    display:"inline-block", padding:"2px 7px", fontSize:10, fontWeight:700,
    borderRadius:4, background:`${color}22`, color, border:`1px solid ${color}55`,
    textTransform:"uppercase", letterSpacing:.4, whiteSpace:"nowrap",
  }),
  pill: { display:"inline-block", padding:"2px 7px", fontSize:10, borderRadius:10, background:T.bgX, color:T.tx, border:`1px solid ${T.bd}` },
  link: { color:T.al, textDecoration:"none" },
  stat: { display:"flex", flexDirection:"column", gap:4, padding:"12px 14px", background:T.bgH, border:`1px solid ${T.bd}`, borderRadius:6, minWidth:110 },
  statLabel: { fontSize:10, fontWeight:700, textTransform:"uppercase", color:T.tm, letterSpacing:.5 },
  statValue: { fontSize:20, fontWeight:800, color:T.wh },
};

// ───────────────────────────── Reusable ─────────────────────────────
function SortHeader({ label, field, sortKey, sortDir, onSort }) {
  const active = sortKey === field;
  return (
    <th style={S.th(true)} onClick={() => onSort(field)}>
      <span style={{ color: active ? T.wh : T.tm }}>
        {label} {active ? (sortDir === "asc" ? "▲" : "▼") : ""}
      </span>
    </th>
  );
}

function Stat({ label, value, color }) {
  return (
    <div style={S.stat}>
      <div style={S.statLabel}>{label}</div>
      <div style={{ ...S.statValue, color: color || T.wh }}>{value}</div>
    </div>
  );
}

// ───────────────────────────── Charts ─────────────────────────────
function PieChart({ data, size = 180 }) {
  const total = data.reduce((s, d) => s + d.value, 0);
  if (!total) return <div style={{ color:T.tm, fontSize:12 }}>No data</div>;
  const r = size / 2 - 4;
  const cx = size / 2, cy = size / 2;
  let acc = 0;
  const slices = data.map((d, i) => {
    const a0 = (acc / total) * 2 * Math.PI - Math.PI / 2;
    acc += d.value;
    const a1 = (acc / total) * 2 * Math.PI - Math.PI / 2;
    const x0 = cx + r * Math.cos(a0), y0 = cy + r * Math.sin(a0);
    const x1 = cx + r * Math.cos(a1), y1 = cy + r * Math.sin(a1);
    const large = a1 - a0 > Math.PI ? 1 : 0;
    return (
      <path key={i}
        d={`M ${cx} ${cy} L ${x0} ${y0} A ${r} ${r} 0 ${large} 1 ${x1} ${y1} Z`}
        fill={d.color} stroke={T.bgC} strokeWidth={1.5} />
    );
  });
  return (
    <div style={{ display:"flex", alignItems:"center", gap:18 }}>
      <svg width={size} height={size}>{slices}</svg>
      <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
        {data.map((d, i) => (
          <div key={i} style={{ display:"flex", alignItems:"center", gap:8, fontSize:12 }}>
            <span style={{ width:10, height:10, borderRadius:2, background:d.color, display:"inline-block" }} />
            <span style={{ color:T.tx }}>{d.label}</span>
            <span style={{ color:T.tm }}>{d.value} ({total ? ((d.value/total)*100).toFixed(1) : 0}%)</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function LineChart({ series, width = 560, height = 240 }) {
  if (!series.length || !series[0].points.length) return <div style={{ color:T.tm }}>No data</div>;
  const all = series.flatMap(s => s.points);
  const xs = all.map(p => p.x), ys = all.map(p => p.y);
  const xMin = Math.min(...xs), xMax = Math.max(...xs);
  const yMin = 0, yMax = Math.max(...ys, 1);
  const pad = { l:42, r:14, t:12, b:28 };
  const W = width - pad.l - pad.r, H = height - pad.t - pad.b;
  const sx = (x) => pad.l + ((x - xMin) / Math.max(1, xMax - xMin)) * W;
  const sy = (y) => pad.t + H - ((y - yMin) / Math.max(1, yMax - yMin)) * H;

  const yTicks = 5;
  const tickVals = Array.from({ length: yTicks + 1 }, (_, i) => Math.round((yMax / yTicks) * i));

  return (
    <div>
      <svg width={width} height={height}>
        {tickVals.map((tv, i) => (
          <g key={i}>
            <line x1={pad.l} x2={pad.l + W} y1={sy(tv)} y2={sy(tv)} stroke={T.bd} strokeDasharray="2 3" />
            <text x={pad.l - 6} y={sy(tv) + 4} fill={T.tm} fontSize={10} textAnchor="end">{tv}</text>
          </g>
        ))}
        {Array.from({ length: xMax - xMin + 1 }, (_, i) => xMin + i).map((xv) => (
          <text key={xv} x={sx(xv)} y={height - 8} fill={T.tm} fontSize={10} textAnchor="middle">{xv}</text>
        ))}
        {series.map((s, si) => {
          const path = s.points.map((p, i) => `${i === 0 ? "M" : "L"} ${sx(p.x)} ${sy(p.y)}`).join(" ");
          return (
            <g key={si}>
              <path d={path} stroke={s.color} strokeWidth={2} fill="none" />
              {s.points.map((p, pi) => (
                <circle key={pi} cx={sx(p.x)} cy={sy(p.y)} r={2.5} fill={s.color} />
              ))}
            </g>
          );
        })}
      </svg>
      <div style={{ display:"flex", gap:16, paddingLeft:pad.l, flexWrap:"wrap" }}>
        {series.map((s, i) => (
          <div key={i} style={{ display:"flex", alignItems:"center", gap:6, fontSize:11 }}>
            <span style={{ width:14, height:2, background:s.color, display:"inline-block" }} />
            <span style={{ color:T.tx }}>{s.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ───────────────────────────── CVE Feed Tab ─────────────────────────────
function CveFeedTab() {
  const [feed, setFeed] = useState([]);
  const [feedLoading, setFeedLoading] = useState(true);
  const [feedError, setFeedError] = useState(null);

  const [epss, setEpss] = useState({});
  const [nuclei, setNuclei] = useState({});
  const [msf, setMsf] = useState({});
  const [edb, setEdb] = useState({});
  const [et, setEt] = useState({});
  const [kev, setKev] = useState({});
  const [timestamps, setTimestamps] = useState({});
  const [refreshing, setRefreshing] = useState(false);

  const [inhouseMap, setInhouseMap] = useState({});
  const [inhouseFile, setInhouseFile] = useState("");
  const inhouseRef = useRef(null);

  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState("");
  const [epssFilter, setEpssFilter] = useState("");
  const [kevOnly, setKevOnly] = useState(false);
  const [inhouseOnly, setInhouseOnly] = useState(false);
  const [sortKey, setSortKey] = useState("cvss");
  const [sortDir, setSortDir] = useState("desc");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(30);
  const [expanded, setExpanded] = useState(null);

  const loadAll = useCallback(async () => {
    setFeedLoading(true); setFeedError(null);
    const fetchJson = (u) => fetch(u).then(r => r.ok ? r.json() : {}).catch(() => ({}));
    try {
      const [f, e, n, m, x, etr, k, ts] = await Promise.all([
        fetch(FEED_URL).then(r => r.json()).catch(err => { throw err; }),
        fetchJson("/api/epss"),
        fetchJson("/api/nuclei"),
        fetchJson("/api/metasploit"),
        fetchJson("/api/exploitdb"),
        fetchJson("/api/et-rules"),
        fetchJson("/api/kev"),
        fetchJson("/api/cache/timestamps"),
      ]);
      // FediSec feed is an object keyed by CVE ID — convert to array with id baked in.
      let entries;
      if (Array.isArray(f)) entries = f;
      else if (f && typeof f === "object" && (f.entries || f.data)) entries = f.entries || f.data;
      else if (f && typeof f === "object") entries = Object.entries(f).map(([k, v]) => ({ cve_id: k, ...(v || {}) }));
      else entries = [];
      setFeed(entries);
      setEpss(e); setNuclei(n); setMsf(m); setEdb(x); setEt(etr); setKev(k);
      setTimestamps(ts);
    } catch (err) {
      setFeedError(String(err.message || err));
    } finally {
      setFeedLoading(false);
    }
  }, []);

  useEffect(() => { loadAll(); }, [loadAll]);

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await fetch("/api/cache/refresh", { method:"POST" });
      await loadAll();
    } catch {} finally { setRefreshing(false); }
  };

  const handleInhouse = async (e) => {
    const f = e.target.files?.[0]; if (!f) return;
    const fd = new FormData(); fd.append("file", f);
    try {
      const res = await fetch("/api/inhouse/upload", { method:"POST", body:fd });
      const j = await res.json();
      setInhouseMap(j.cve_coverage || {});
      setInhouseFile(`${j.filename} — ${j.rule_count} rules, ${j.cve_count} CVEs`);
    } catch (err) { setInhouseFile(`Error: ${err.message}`); }
  };

  const enriched = useMemo(() => {
    return (feed || []).map((row) => {
      const id = row.cve_id || row.id || row.cve || "";
      // Prefer cached EPSS API value; fall back to the feed's own epss field.
      const e = epss[id] || {};
      const feedEpss = row.epss != null ? parseFloat(row.epss) : null;
      const apiEpss = e.epss != null ? parseFloat(e.epss) : null;
      const n = nuclei[id];
      const m = msf[id];
      const x = edb[id];
      const k = kev[id];
      const etRow = et[id];
      const inhouse = inhouseMap[id];
      const cvss = parseFloat(row.cvss3 ?? row.cvss_score ?? row.cvss ?? row.cvssv3 ?? 0) || null;
      return {
        ...row,
        _id: id,
        _cvss: cvss,
        _epss: apiEpss != null ? apiEpss : feedEpss,
        _epss_pct: e.percentile != null ? parseFloat(e.percentile) : null,
        _nuclei: !!(n || row.nuclei), _msf: !!m, _edb: !!x, _kev: !!k, _et: !!etRow,
        _inhouse: inhouse,
        _year: (id.match(/CVE-(\d{4})/) || [])[1] || "",
        _desc: row.description || row.summary || "",
        _posts: row.posts || row.fediverse_posts || [],
        _repos: row.repos || row.github_repos || [],
        _updated: row.updated || row.updated_at || "",
      };
    });
  }, [feed, epss, nuclei, msf, edb, kev, et, inhouseMap]);

  const filtered = useMemo(() => {
    let r = enriched;
    if (search) {
      const q = search.toLowerCase();
      r = r.filter(x => (x._id || "").toLowerCase().includes(q) || (x._desc || "").toLowerCase().includes(q));
    }
    if (sevFilter) r = r.filter(x => cvssSev(x._cvss) === sevFilter);
    if (epssFilter) r = r.filter(x => epssSev(x._epss) === epssFilter);
    if (kevOnly) r = r.filter(x => x._kev);
    if (inhouseOnly) r = r.filter(x => x._inhouse);
    r = [...r].sort((a, b) => {
      const va = a[sortKey === "cvss" ? "_cvss" : sortKey === "epss" ? "_epss" : sortKey === "year" ? "_year" : sortKey === "cve" ? "_id" : "_id"];
      const vb = b[sortKey === "cvss" ? "_cvss" : sortKey === "epss" ? "_epss" : sortKey === "year" ? "_year" : sortKey === "cve" ? "_id" : "_id"];
      const na = va == null ? -Infinity : (typeof va === "string" ? va : Number(va));
      const nb = vb == null ? -Infinity : (typeof vb === "string" ? vb : Number(vb));
      if (na < nb) return sortDir === "asc" ? -1 : 1;
      if (na > nb) return sortDir === "asc" ? 1 : -1;
      return 0;
    });
    return r;
  }, [enriched, search, sevFilter, epssFilter, kevOnly, inhouseOnly, sortKey, sortDir]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const pageItems = filtered.slice((page - 1) * pageSize, page * pageSize);
  useEffect(() => { setPage(1); }, [search, sevFilter, epssFilter, kevOnly, inhouseOnly, pageSize]);

  const onSort = (f) => {
    if (sortKey === f) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortKey(f); setSortDir("desc"); }
  };

  const sources = [
    ["EPSS","epss"], ["Nuclei","nuclei"], ["Metasploit","metasploit"],
    ["ExploitDB","exploitdb"], ["ET Rules","et_rules"], ["CISA KEV","kev"],
  ];

  return (
    <div>
      {/* Data freshness */}
      <div style={S.card}>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:10 }}>
          <div style={S.cardTitle}>Data Freshness</div>
          <button style={S.btn("primary")} onClick={handleRefresh} disabled={refreshing}>
            {refreshing ? "Refreshing..." : "Refresh Data"}
          </button>
        </div>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fit, minmax(160px,1fr))", gap:8 }}>
          {sources.map(([label, key]) => (
            <div key={key} style={{ background:T.bgH, border:`1px solid ${T.bd}`, borderRadius:6, padding:"8px 10px" }}>
              <div style={{ fontSize:10, color:T.tm, fontWeight:700, textTransform:"uppercase" }}>{label}</div>
              <div style={{ fontSize:12, color:T.wh, marginTop:2 }}>{fmtTime(timestamps[key])}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Inhouse rules upload */}
      <div style={S.card}>
        <div style={S.cardTitle}>Inhouse Rules Overlay</div>
        <div style={{ display:"flex", gap:10, alignItems:"center" }}>
          <input ref={inhouseRef} type="file" accept=".rules,.txt" onChange={handleInhouse} style={{ display:"none" }} />
          <button style={S.btn("secondary")} onClick={() => inhouseRef.current?.click()}>Upload .rules file</button>
          <span style={{ color:T.tm, fontSize:12 }}>{inhouseFile || "No file uploaded"}</span>
        </div>
      </div>

      {/* Filters */}
      <div style={S.card}>
        <div style={{ display:"flex", gap:10, flexWrap:"wrap", alignItems:"center" }}>
          <input style={{ ...S.input, flex:1, minWidth:220 }} placeholder="Search CVE or description..." value={search} onChange={e => setSearch(e.target.value)} />
          <select style={S.select} value={sevFilter} onChange={e => setSevFilter(e.target.value)}>
            <option value="">All Severity</option>
            <option>Critical</option><option>High</option><option>Medium</option><option>Low</option>
          </select>
          <select style={S.select} value={epssFilter} onChange={e => setEpssFilter(e.target.value)}>
            <option value="">All EPSS</option>
            <option>Critical</option><option>High</option><option>Medium</option><option>Low</option>
          </select>
          <label style={{ display:"flex", alignItems:"center", gap:6, fontSize:12, color:T.tx }}>
            <input type="checkbox" checked={kevOnly} onChange={e => setKevOnly(e.target.checked)} /> KEV only
          </label>
          <label style={{ display:"flex", alignItems:"center", gap:6, fontSize:12, color:T.tx }}>
            <input type="checkbox" checked={inhouseOnly} onChange={e => setInhouseOnly(e.target.checked)} /> Inhouse only
          </label>
          <select style={S.select} value={pageSize} onChange={e => setPageSize(Number(e.target.value))}>
            <option value={10}>10 / page</option>
            <option value={30}>30 / page</option>
            <option value={50}>50 / page</option>
            <option value={100}>100 / page</option>
          </select>
        </div>
        <div style={{ marginTop:10, fontSize:11, color:T.tm }}>
          {feedLoading ? "Loading..." : `${filtered.length} of ${feed.length} entries`}
        </div>
      </div>

      {/* Table */}
      <div style={{ ...S.card, padding:0, overflow:"auto" }}>
        {feedError ? (
          <div style={{ padding:20, color:T.r }}>Feed error: {feedError}</div>
        ) : (
          <table style={S.table}>
            <thead>
              <tr>
                <th style={S.th(false)} />
                <SortHeader label="CVE" field="cve" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                <SortHeader label="Year" field="year" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                <SortHeader label="CVSS" field="cvss" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                <SortHeader label="EPSS" field="epss" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                <th style={S.th(false)}>KEV</th>
                <th style={S.th(false)}>Exploits</th>
                <th style={S.th(false)}>Inhouse</th>
                <th style={S.th(false)}>Description</th>
              </tr>
            </thead>
            <tbody>
              {pageItems.map((r, i) => {
                const isOpen = expanded === r._id;
                return (
                  <React.Fragment key={r._id || i}>
                    <tr style={S.trH} onMouseEnter={e => e.currentTarget.style.background = T.bgX} onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                      <td style={{ ...S.td, width:32, cursor:"pointer", color:T.tm }} onClick={() => setExpanded(isOpen ? null : r._id)}>{isOpen ? "▼" : "▶"}</td>
                      <td style={{ ...S.td, fontWeight:700, color:T.wh, whiteSpace:"nowrap" }}>{r._id}</td>
                      <td style={S.td}>{r._year}</td>
                      <td style={S.td}>
                        {r._cvss != null && <span style={S.badge(sevColor(cvssSev(r._cvss)))}>{r._cvss?.toFixed(1)}</span>}
                      </td>
                      <td style={S.td}>
                        {r._epss != null && <span style={S.badge(sevColor(epssSev(r._epss)))}>{(r._epss*100).toFixed(1)}%</span>}
                      </td>
                      <td style={S.td}>{r._kev && <span style={S.badge(T.r)}>KEV</span>}</td>
                      <td style={S.td}>
                        <div style={{ display:"flex", gap:4 }}>
                          {r._nuclei && <span style={S.badge(T.cy)}>N</span>}
                          {r._msf && <span style={S.badge(T.p)}>M</span>}
                          {r._edb && <span style={S.badge(T.o)}>E</span>}
                          {r._et && <span style={S.badge(T.al)}>ET</span>}
                        </div>
                      </td>
                      <td style={S.td}>
                        {r._inhouse && <span style={S.badge(T.g)}>{r._inhouse.length} rule{r._inhouse.length===1?"":"s"}</span>}
                      </td>
                      <td style={{ ...S.td, maxWidth:520, color:T.tx }}>
                        <div style={{ overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{r._desc}</div>
                      </td>
                    </tr>
                    {isOpen && (
                      <tr>
                        <td colSpan={9} style={{ ...S.td, background:T.bgX }}>
                          <div style={{ padding:8 }}>
                            {r._desc && <div style={{ marginBottom:10, color:T.tx, lineHeight:1.5 }}>{r._desc}</div>}
                            {r._inhouse && (
                              <div style={{ marginBottom:10 }}>
                                <div style={{ fontSize:11, fontWeight:700, color:T.g, marginBottom:4 }}>INHOUSE COVERAGE</div>
                                {r._inhouse.map((rule, ri) => (
                                  <div key={ri} style={{ fontSize:11, color:T.tx, marginLeft:8 }}>
                                    <span style={{ color:T.tm }}>SID {rule.sid}</span> — {rule.msg}
                                  </div>
                                ))}
                              </div>
                            )}
                            {r._posts?.length > 0 && (
                              <div style={{ marginBottom:10 }}>
                                <div style={{ fontSize:11, fontWeight:700, color:T.tm, marginBottom:4 }}>FEDIVERSE POSTS ({r._posts.length})</div>
                                {r._posts.slice(0,5).map((p, pi) => (
                                  <div key={pi} style={{ fontSize:11, color:T.tx, marginLeft:8, marginBottom:3 }}>
                                    {p.url ? <a href={p.url} target="_blank" rel="noreferrer" style={S.link}>{p.author || p.url}</a> : (p.author || JSON.stringify(p).slice(0,80))}
                                  </div>
                                ))}
                              </div>
                            )}
                            {r._repos?.length > 0 && (
                              <div>
                                <div style={{ fontSize:11, fontWeight:700, color:T.tm, marginBottom:4 }}>GITHUB REPOS ({r._repos.length})</div>
                                {r._repos.slice(0,10).map((p, pi) => (
                                  <div key={pi} style={{ fontSize:11, marginLeft:8 }}>
                                    {p.url ? <a href={p.url} target="_blank" rel="noreferrer" style={S.link}>{p.name || p.url}</a> : (p.name || JSON.stringify(p).slice(0,80))}
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination */}
      <div style={{ display:"flex", justifyContent:"center", alignItems:"center", gap:10, marginTop:16 }}>
        <button style={S.btn("secondary")} disabled={page === 1} onClick={() => setPage(p => Math.max(1, p-1))}>← Prev</button>
        <span style={{ fontSize:12, color:T.tx }}>Page {page} of {totalPages}</span>
        <button style={S.btn("secondary")} disabled={page === totalPages} onClick={() => setPage(p => Math.min(totalPages, p+1))}>Next →</button>
      </div>
    </div>
  );
}

// ───────────────────────────── CVE Lookup Tab ─────────────────────────────
function CveLookupTab() {
  const [cves, setCves] = useState([]);
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const fileRef = useRef(null);

  const handleFile = (e) => {
    const f = e.target.files?.[0]; if (!f) return;
    const reader = new FileReader();
    reader.onload = () => {
      const text = String(reader.result || "");
      const list = [...new Set(text.match(/CVE-\d{4}-\d{4,}/gi) || [])].map(s => s.toUpperCase());
      setCves(list);
    };
    reader.readAsText(f);
  };

  const lookup = async () => {
    if (!cves.length) return;
    setLoading(true); setError(null);
    try {
      const fetchJson = (u) => fetch(u).then(r => r.ok ? r.json() : {}).catch(() => ({}));
      const [epss, nuclei, msf, edb, et, kev] = await Promise.all([
        fetchJson("/api/epss"), fetchJson("/api/nuclei"), fetchJson("/api/metasploit"),
        fetchJson("/api/exploitdb"), fetchJson("/api/et-rules"), fetchJson("/api/kev"),
      ]);
      const out = cves.map(id => {
        const e = epss[id] || {};
        return {
          id, epss: e.epss != null ? parseFloat(e.epss) : null,
          epss_pct: e.percentile != null ? parseFloat(e.percentile) : null,
          nuclei: !!nuclei[id], msf: !!msf[id], edb: !!edb[id], et: !!et[id],
          kev: !!kev[id], kev_info: kev[id] || null,
        };
      });
      setResults(out);
    } catch (err) { setError(String(err.message || err)); }
    finally { setLoading(false); }
  };

  return (
    <div>
      <div style={S.card}>
        <div style={S.cardTitle}>Upload CVE List</div>
        <div style={{ display:"flex", gap:10, alignItems:"center", flexWrap:"wrap" }}>
          <input ref={fileRef} type="file" accept=".txt,.csv" onChange={handleFile} style={{ display:"none" }} />
          <button style={S.btn("secondary")} onClick={() => fileRef.current?.click()}>Choose .txt file</button>
          <span style={{ color:T.tm, fontSize:12 }}>{cves.length ? `${cves.length} CVE(s) parsed` : "No file selected"}</span>
          <button style={S.btn("primary")} onClick={lookup} disabled={!cves.length || loading}>
            {loading ? "Looking up..." : "Enrich"}
          </button>
        </div>
        {error && <div style={{ marginTop:10, color:T.r, fontSize:12 }}>{error}</div>}
      </div>

      {results.length > 0 && (
        <div style={{ ...S.card, padding:0, overflow:"auto" }}>
          <table style={S.table}>
            <thead>
              <tr>
                <th style={S.th(false)}>CVE</th>
                <th style={S.th(false)}>EPSS</th>
                <th style={S.th(false)}>Percentile</th>
                <th style={S.th(false)}>Nuclei</th>
                <th style={S.th(false)}>Metasploit</th>
                <th style={S.th(false)}>ExploitDB</th>
                <th style={S.th(false)}>ET Rules</th>
                <th style={S.th(false)}>CISA KEV</th>
              </tr>
            </thead>
            <tbody>
              {results.map((r, i) => (
                <tr key={i}>
                  <td style={{ ...S.td, color:T.wh, fontWeight:700 }}>{r.id}</td>
                  <td style={S.td}>{r.epss != null ? <span style={S.badge(sevColor(epssSev(r.epss)))}>{(r.epss*100).toFixed(1)}%</span> : <span style={{ color:T.tm }}>—</span>}</td>
                  <td style={S.td}>{r.epss_pct != null ? `${(r.epss_pct*100).toFixed(1)}%` : <span style={{ color:T.tm }}>—</span>}</td>
                  <td style={S.td}>{r.nuclei ? <span style={S.badge(T.cy)}>YES</span> : <span style={{ color:T.tm }}>—</span>}</td>
                  <td style={S.td}>{r.msf ? <span style={S.badge(T.p)}>YES</span> : <span style={{ color:T.tm }}>—</span>}</td>
                  <td style={S.td}>{r.edb ? <span style={S.badge(T.o)}>YES</span> : <span style={{ color:T.tm }}>—</span>}</td>
                  <td style={S.td}>{r.et ? <span style={S.badge(T.al)}>YES</span> : <span style={{ color:T.tm }}>—</span>}</td>
                  <td style={S.td}>{r.kev ? <span style={S.badge(T.r)}>KEV</span> : <span style={{ color:T.tm }}>—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ───────────────────────────── Ruleset Analysis Tab ─────────────────────────────
function RulesetAnalysisTab() {
  const [rulesInfo, setRulesInfo] = useState(null);
  const [pcapInfo, setPcapInfo] = useState(null);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const rulesRef = useRef(null);
  const pcapRef = useRef(null);

  // Table state
  const [sortKey, setSortKey] = useState("verdict");
  const [sortDir, setSortDir] = useState("asc");
  const [verdictFilter, setVerdictFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [expanded, setExpanded] = useState(null);

  const upload = async (file, endpoint, setter) => {
    const fd = new FormData(); fd.append("file", file);
    try {
      const res = await fetch(endpoint, { method:"POST", body:fd });
      const j = await res.json();
      if (!res.ok) throw new Error(j.error || "Upload failed");
      setter(j);
    } catch (err) { setError(String(err.message || err)); }
  };

  const runAnalysis = async () => {
    setRunning(true); setError(null); setResult(null);
    try {
      const res = await fetch("/api/analysis/run", { method:"POST" });
      const j = await res.json();
      if (!res.ok) throw new Error(j.error || "Run failed");
      setResult(j);
    } catch (err) { setError(String(err.message || err)); }
    finally { setRunning(false); }
  };

  const rules = result?.rules || [];
  const summary = result?.summary;

  const filtered = useMemo(() => {
    let r = rules;
    if (verdictFilter) r = r.filter(x => x.verdict === verdictFilter);
    if (typeFilter) r = r.filter(x => x.sig_type === typeFilter);
    if (search) {
      const q = search.toLowerCase();
      r = r.filter(x => (x.sid || "").includes(q) || (x.msg || "").toLowerCase().includes(q) || (x.cves || []).some(c => c.toLowerCase().includes(q)));
    }
    const get = (x, k) => {
      switch (k) {
        case "sid": return parseInt(x.sid) || 0;
        case "score": return x.rubric_score != null ? x.rubric_score : (x.rubric_detail?.cvss || 0);
        case "verdict": return ["RETIRE","REVIEW","KEEP","DISABLED"].indexOf(x.verdict);
        case "type": return x.sig_type || "";
        case "checks": return x.checks || 0;
        case "msg": return x.msg || "";
        case "flowbit": return x.has_flowbits ? 1 : 0;
        case "cves": return (x.cves || [])[0] || "";
        case "epss": return x.enrichment?.epss_score ?? -1;
        case "kev": return x.enrichment?.is_kev ? 1 : 0;
        default: return 0;
      }
    };
    return [...r].sort((a, b) => {
      const va = get(a, sortKey), vb = get(b, sortKey);
      if (va < vb) return sortDir === "asc" ? -1 : 1;
      if (va > vb) return sortDir === "asc" ? 1 : -1;
      return 0;
    });
  }, [rules, verdictFilter, typeFilter, search, sortKey, sortDir]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const pageItems = filtered.slice((page - 1) * pageSize, page * pageSize);
  useEffect(() => { setPage(1); }, [verdictFilter, typeFilter, search, pageSize]);

  const onSort = (f) => {
    if (sortKey === f) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortKey(f); setSortDir(f === "verdict" ? "asc" : "desc"); }
  };

  const ruleBySid = useMemo(() => {
    const m = {}; for (const r of rules) m[r.sid] = r; return m;
  }, [rules]);

  const pieData = summary ? [
    { label:"CVE", value:summary.type_counts?.CVE || 0, color:T.ac },
    { label:"MALWARE", value:summary.type_counts?.MALWARE || 0, color:T.p },
    { label:"CVE+MALWARE", value:summary.type_counts?.["CVE+MALWARE"] || 0, color:T.cy },
  ] : [];

  const lineSeries = summary?.growth?.length ? [
    { label:"Total", color:T.wh, points: summary.growth.map(p => ({ x:p.year, y:p.total })) },
    { label:"CVE", color:T.ac, points: summary.growth.map(p => ({ x:p.year, y:p.cve })) },
    { label:"MALWARE", color:T.p, points: summary.growth.map(p => ({ x:p.year, y:p.malware })) },
    { label:"CVE+MALWARE", color:T.cy, points: summary.growth.map(p => ({ x:p.year, y:p.both })) },
  ] : [];

  return (
    <div>
      {/* Upload zone */}
      <div style={S.card}>
        <div style={S.cardTitle}>Upload Files</div>
        <div style={{ display:"flex", gap:12, flexWrap:"wrap", alignItems:"center" }}>
          <input ref={rulesRef} type="file" accept=".rules,.txt" onChange={e => e.target.files?.[0] && upload(e.target.files[0], "/api/analysis/upload-rules", setRulesInfo)} style={{ display:"none" }} />
          <button style={S.btn("secondary")} onClick={() => rulesRef.current?.click()}>Upload Ruleset (.rules)</button>
          <span style={{ color: rulesInfo ? T.g : T.tm, fontSize:12 }}>
            {rulesInfo ? `${rulesInfo.filename} — ${rulesInfo.total} rules (${rulesInfo.active} active, ${rulesInfo.disabled} disabled)` : "No ruleset"}
          </span>
          <div style={{ flexBasis:"100%" }} />
          <input ref={pcapRef} type="file" accept=".pcap,.pcapng" onChange={e => e.target.files?.[0] && upload(e.target.files[0], "/api/analysis/upload-pcap", setPcapInfo)} style={{ display:"none" }} />
          <button style={S.btn("secondary")} onClick={() => pcapRef.current?.click()}>Upload PCAP</button>
          <span style={{ color: pcapInfo ? T.g : T.tm, fontSize:12 }}>
            {pcapInfo ? `${pcapInfo.filename} — ${pcapInfo.size_mb} MB` : "No PCAP"}
          </span>
          <div style={{ flexBasis:"100%" }} />
          <button style={S.btn("primary")} onClick={runAnalysis} disabled={!rulesInfo || !pcapInfo || running}>
            {running ? "Running Suricata..." : "Run Analysis"}
          </button>
        </div>
        {error && <div style={{ marginTop:10, color:T.r, fontSize:12 }}>{error}</div>}
      </div>

      {summary && (
        <>
          {/* Summary cards */}
          <div style={S.card}>
            <div style={S.cardTitle}>Summary</div>
            <div style={{ display:"flex", gap:10, flexWrap:"wrap" }}>
              <Stat label="Total Rules" value={summary.total_rules} />
              <Stat label="Active" value={summary.active_rules} color={T.g} />
              <Stat label="Disabled" value={summary.disabled_rules} color={T.tm} />
              <Stat label="Profiled" value={summary.profiled_rules} color={T.cy} />
              <Stat label="Alerts" value={summary.total_alerts} color={T.o} />
              <Stat label="Retire" value={summary.retire_count} color={T.r} />
              <Stat label="Review" value={summary.review_count} color={T.o} />
              <Stat label="Keep" value={summary.keep_count} color={T.g} />
              <Stat label="CISA KEV" value={summary.kev_hits} color={T.r} />
              <Stat label="Suricata Runtime" value={`${summary.suricata_elapsed_sec}s`} color={summary.suricata_ok ? T.g : T.r} />
            </div>
          </div>

          {/* Charts */}
          <div style={{ display:"flex", gap:16, flexWrap:"wrap" }}>
            <div style={{ ...S.card, flex:"0 0 auto" }}>
              <div style={S.cardTitle}>Rule Type Distribution</div>
              <PieChart data={pieData} />
            </div>
            <div style={{ ...S.card, flex:"1 1 400px" }}>
              <div style={S.cardTitle}>Ruleset Growth by Year (cumulative)</div>
              <LineChart series={lineSeries} />
            </div>
          </div>

          {/* Filters */}
          <div style={S.card}>
            <div style={{ display:"flex", gap:10, flexWrap:"wrap", alignItems:"center" }}>
              <input style={{ ...S.input, flex:1, minWidth:220 }} placeholder="Search SID, message, CVE..." value={search} onChange={e => setSearch(e.target.value)} />
              <select style={S.select} value={verdictFilter} onChange={e => setVerdictFilter(e.target.value)}>
                <option value="">All Verdicts</option>
                <option>RETIRE</option><option>REVIEW</option><option>KEEP</option><option>DISABLED</option>
              </select>
              <select style={S.select} value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
                <option value="">All Types</option>
                <option>CVE</option><option>MALWARE</option><option>CVE+MALWARE</option>
              </select>
              <select style={S.select} value={pageSize} onChange={e => setPageSize(Number(e.target.value))}>
                <option value={25}>25 / page</option>
                <option value={50}>50 / page</option>
                <option value={100}>100 / page</option>
                <option value={250}>250 / page</option>
              </select>
              <span style={{ fontSize:11, color:T.tm }}>{filtered.length} of {rules.length}</span>
            </div>
          </div>

          {/* Rules table */}
          <div style={{ ...S.card, padding:0, overflow:"auto" }}>
            <table style={S.table}>
              <thead>
                <tr>
                  <th style={S.th(false)} />
                  <SortHeader label="SID" field="sid" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                  <SortHeader label="Score" field="score" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                  <SortHeader label="Verdict" field="verdict" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                  <SortHeader label="Type" field="type" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                  <SortHeader label="Checks" field="checks" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                  <SortHeader label="Message" field="msg" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                  <SortHeader label="Flowbit" field="flowbit" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                  <SortHeader label="CVEs" field="cves" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                  <SortHeader label="EPSS" field="epss" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                  <SortHeader label="KEV" field="kev" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                </tr>
              </thead>
              <tbody>
                {pageItems.map((r, i) => {
                  const isOpen = expanded === r.sid;
                  const score = r.rubric_score != null ? r.rubric_score : (r.rubric_detail?.cvss);
                  return (
                    <React.Fragment key={r.sid + "-" + i}>
                      <tr style={S.trH}
                          onMouseEnter={e => e.currentTarget.style.background = T.bgX}
                          onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                        <td style={{ ...S.td, width:32, cursor:"pointer", color:T.tm }} onClick={() => setExpanded(isOpen ? null : r.sid)}>{isOpen ? "▼" : "▶"}</td>
                        <td style={{ ...S.td, color:T.wh, fontFamily:"monospace" }}>{r.sid}</td>
                        <td style={S.td}>{score != null ? score : <span style={{ color:T.tm }}>—</span>}</td>
                        <td style={S.td}><span style={S.badge(verdictColor(r.verdict))}>{r.verdict}</span></td>
                        <td style={S.td}><span style={S.badge(typeColor(r.sig_type))}>{r.sig_type}</span></td>
                        <td style={S.td}>{r.checks || 0}</td>
                        <td style={{ ...S.td, maxWidth:420, color:T.tx }}>
                          <div style={{ overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{r.msg}</div>
                        </td>
                        <td style={S.td}>{r.has_flowbits ? <span style={S.badge(T.y)}>FB</span> : ""}</td>
                        <td style={{ ...S.td, fontSize:11 }}>{(r.cves || []).slice(0,2).join(", ")}{(r.cves || []).length > 2 ? "..." : ""}</td>
                        <td style={S.td}>
                          {r.enrichment?.epss_score != null && (
                            <span style={S.badge(sevColor(epssSev(r.enrichment.epss_score)))}>{(r.enrichment.epss_score*100).toFixed(1)}%</span>
                          )}
                        </td>
                        <td style={S.td}>{r.enrichment?.is_kev && <span style={S.badge(T.r)}>KEV</span>}</td>
                      </tr>
                      {isOpen && (
                        <tr>
                          <td colSpan={11} style={{ ...S.td, background:T.bgX }}>
                            <div style={{ padding:10, display:"grid", gridTemplateColumns:"1fr 1fr", gap:16 }}>
                              <div>
                                <div style={{ fontSize:11, fontWeight:700, color:T.tm, marginBottom:6 }}>RULE DETAILS</div>
                                <KV k="SID" v={r.sid} />
                                <KV k="Message" v={r.msg} />
                                <KV k="Classtype" v={r.classtype} />
                                <KV k="Created" v={r.created_at} />
                                <KV k="Severity" v={r.signature_severity} />
                                <KV k="Affected Product" v={r.affected_product} />
                                <KV k="Target" v={r.target_type} />
                                <KV k="Disabled" v={r.disabled ? "Yes" : "No"} />
                                <KV k="Checks" v={r.checks} />
                                <KV k="Alerts" v={r.alerts} />
                              </div>
                              <div>
                                <div style={{ fontSize:11, fontWeight:700, color:T.tm, marginBottom:6 }}>RUBRIC</div>
                                {r.rubric_detail && (
                                  <div style={{ fontSize:11, color:T.tx }}>
                                    <KV k="Type" v="CVSS" />
                                    <KV k="CVSS" v={r.rubric_detail.cvss} />
                                    <KV k="Severity" v={r.rubric_detail.severity_label} />
                                    <KV k="Sig year" v={r.rubric_detail.sig_year} />
                                    <KV k="Age (yrs)" v={r.rubric_detail.age_years} />
                                    <KV k="Retention (yrs)" v={r.rubric_detail.retention_years} />
                                    <KV k="Exceeded" v={r.rubric_detail.exceeded ? "Yes" : "No"} />
                                  </div>
                                )}
                                {r.rubric_breakdown && (
                                  <div>
                                    {Object.entries(r.rubric_breakdown).map(([k, v]) => (
                                      <KV key={k} k={k} v={`${v.label} (${v.score >= 0 ? "+" : ""}${v.score})`} />
                                    ))}
                                    <KV k="Total" v={r.rubric_score} />
                                  </div>
                                )}
                                {r.cves?.length > 0 && (
                                  <div style={{ marginTop:8 }}>
                                    <div style={{ fontSize:11, fontWeight:700, color:T.tm, marginBottom:4 }}>CVES</div>
                                    {r.cves.map((c, ci) => <div key={ci} style={{ fontSize:11, color:T.tx }}>{c}</div>)}
                                  </div>
                                )}
                                {r.enrichment && (
                                  <div style={{ marginTop:8 }}>
                                    <div style={{ fontSize:11, fontWeight:700, color:T.tm, marginBottom:4 }}>ENRICHMENT</div>
                                    <KV k="EPSS" v={r.enrichment.epss_score != null ? `${(r.enrichment.epss_score*100).toFixed(2)}%` : "—"} />
                                    <KV k="KEV" v={r.enrichment.is_kev ? "Yes" : "No"} />
                                    <KV k="Nuclei" v={r.enrichment.has_nuclei ? "Yes" : "No"} />
                                    <KV k="Metasploit" v={r.enrichment.has_msf ? "Yes" : "No"} />
                                    <KV k="ExploitDB" v={r.enrichment.has_edb ? "Yes" : "No"} />
                                    <KV k="ET Rules" v={r.enrichment.has_et ? "Yes" : "No"} />
                                  </div>
                                )}
                              </div>
                              {r.has_flowbits && (
                                <div style={{ gridColumn:"1 / -1" }}>
                                  <div style={{ fontSize:11, fontWeight:700, color:T.y, marginBottom:6 }}>FLOWBITS</div>
                                  <div style={{ fontSize:11, color:T.tx, marginBottom:6 }}>
                                    {r.flowbits.set?.length > 0 && <div>SET: <span style={{ color:T.g }}>{r.flowbits.set.join(", ")}</span></div>}
                                    {r.flowbits.isset?.length > 0 && <div>ISSET: <span style={{ color:T.cy }}>{r.flowbits.isset.join(", ")}</span></div>}
                                    {r.flowbits.unset?.length > 0 && <div>UNSET: <span style={{ color:T.o }}>{r.flowbits.unset.join(", ")}</span></div>}
                                    {r.flowbits.toggle?.length > 0 && <div>TOGGLE: {r.flowbits.toggle.join(", ")}</div>}
                                    {r.flowbits.noalert && <div>noalert: yes</div>}
                                  </div>
                                  {r.flowbit_connections?.length > 0 && (
                                    <div>
                                      <div style={{ fontSize:11, fontWeight:700, color:T.tm, marginBottom:4 }}>
                                        CONNECTED RULES ({r.flowbit_connections.length})
                                      </div>
                                      <div style={{ display:"flex", flexDirection:"column", gap:3, maxHeight:200, overflowY:"auto" }}>
                                        {r.flowbit_connections.map((c, ci) => {
                                          const dep = ruleBySid[c.sid];
                                          return (
                                            <div key={ci} style={{ fontSize:11, color:T.tx, padding:"3px 6px", background:T.bgH, borderRadius:4 }}>
                                              <span style={{ color:T.tm }}>SID {c.sid}</span> {" "}
                                              <span style={S.pill}>{c.rel}: {c.flowbit}</span>
                                              {dep && <span style={{ marginLeft:8, color:T.td }}>— {dep.msg?.slice(0,80)}</span>}
                                            </div>
                                          );
                                        })}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div style={{ display:"flex", justifyContent:"center", alignItems:"center", gap:10, marginTop:16 }}>
            <button style={S.btn("secondary")} disabled={page === 1} onClick={() => setPage(p => Math.max(1, p-1))}>← Prev</button>
            <span style={{ fontSize:12, color:T.tx }}>Page {page} of {totalPages}</span>
            <button style={S.btn("secondary")} disabled={page === totalPages} onClick={() => setPage(p => Math.min(totalPages, p+1))}>Next →</button>
          </div>
        </>
      )}
    </div>
  );
}

function KV({ k, v }) {
  if (v == null || v === "") return null;
  return (
    <div style={{ display:"flex", gap:8, fontSize:11, padding:"2px 0" }}>
      <span style={{ color:T.tm, minWidth:110 }}>{k}</span>
      <span style={{ color:T.tx }}>{String(v)}</span>
    </div>
  );
}

// ───────────────────────────── App ─────────────────────────────
export default function App() {
  const [tab, setTab] = useState("feed");
  const tabs = [
    { id:"feed", label:"📡 CVE Feed" },
    { id:"lookup", label:"🔍 CVE Lookup" },
    { id:"analysis", label:"🔬 Ruleset Analysis" },
  ];

  return (
    <div style={S.page}>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet" />
      <div style={S.header}>
        <h1 style={S.title}>🕷 ARACHNID INTEL</h1>
        <div style={S.subtitle}>SLR Threat Intelligence · CVE enrichment · Ruleset analysis</div>
      </div>
      <div style={S.tabs}>
        {tabs.map(t => (
          <div key={t.id} style={S.tab(tab === t.id)} onClick={() => setTab(t.id)}>{t.label}</div>
        ))}
      </div>
      <div style={S.content}>
        {tab === "feed" && <CveFeedTab />}
        {tab === "lookup" && <CveLookupTab />}
        {tab === "analysis" && <RulesetAnalysisTab />}
      </div>
    </div>
  );
}
