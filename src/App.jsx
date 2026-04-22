import React, { useState, useEffect, useMemo, useCallback } from "react";

const FEED_URL = "https://raw.githubusercontent.com/fedisecfeeds/fedisecfeeds.github.io/refs/heads/main/fedi_cve_feed.json";

// LevelBlue / SpiderLabs inspired palette
const T = {
  bg: "#080c1a", bgCard: "#0c1228", bgHover: "#111936", bgExpand: "#0e1530",
  border: "#1a2347", borderActive: "#2563eb",
  accent: "#2563eb", accentLight: "#3b82f6", accentGlow: "rgba(37,99,235,.12)",
  text: "#c7d2e0", textMuted: "#5b6b82", textDim: "#3a4a63",
  white: "#e8edf5",
  red: "#ef4444", orange: "#f59e0b", yellow: "#eab308", green: "#22c55e",
  purple: "#a855f7", pink: "#ec4899", cyan: "#06b6d4",
};
const sevColor = {
  CRITICAL: { bg: "rgba(239,68,68,.12)", border: "#ef4444", text: "#fca5a5", badge: "#dc2626" },
  HIGH: { bg: "rgba(245,158,11,.1)", border: "#f59e0b", text: "#fcd34d", badge: "#d97706" },
  MEDIUM: { bg: "rgba(234,179,8,.1)", border: "#eab308", text: "#fde047", badge: "#a16207" },
  LOW: { bg: "rgba(34,197,94,.1)", border: "#22c55e", text: "#86efac", badge: "#16a34a" },
  NONE: { bg: "rgba(91,107,130,.08)", border: T.textDim, text: T.textMuted, badge: T.textDim },
};
const sc = s => sevColor[s?.toUpperCase()] || sevColor.NONE;
const extractYear = id => { const m = id.match(/CVE-(\d{4})/); return m ? +m[1] : 0; };
const strip = h => h ? h.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim() : "";
const timeAgo = d => { if (!d) return ""; const m = Math.floor((Date.now() - new Date(d)) / 60000); if (m < 60) return m + "m ago"; const h = Math.floor(m / 60); if (h < 24) return h + "h ago"; const dy = Math.floor(h / 24); return dy < 30 ? dy + "d ago" : Math.floor(dy / 30) + "mo ago"; };
const epsC = s => s == null ? T.textDim : s >= .5 ? T.red : s >= .15 ? T.orange : s >= .05 ? T.yellow : T.green;

function Badge({ severity }) { const c = sc(severity); return <span style={{ display: "inline-block", padding: "2px 10px", borderRadius: 4, background: c.badge, color: "#fff", fontSize: 10, fontWeight: 700, letterSpacing: ".06em", textTransform: "uppercase", whiteSpace: "nowrap" }}>{severity || "N/A"}</span> }
function CvssBar({ score }) { if (score == null) return <span style={{ color: T.textDim, fontSize: 13 }}>—</span>; const p = score / 10 * 100, c = score >= 9 ? T.red : score >= 7 ? T.orange : score >= 4 ? T.yellow : T.green; return <div style={{ display: "flex", alignItems: "center", gap: 8 }}><div style={{ width: 56, height: 5, background: "rgba(255,255,255,.05)", borderRadius: 3, overflow: "hidden" }}><div style={{ width: p + "%", height: "100%", background: c, borderRadius: 3 }} /></div><span style={{ color: c, fontSize: 12, fontWeight: 700, fontVariantNumeric: "tabular-nums", minWidth: 26 }}>{score.toFixed(1)}</span></div> }
function EpssCell({ epss, percentile }) { if (epss == null) return <span style={{ color: T.textDim, fontSize: 12 }}>—</span>; const c = epsC(epss), p = Math.min(epss * 100, 100); return <div style={{ display: "flex", flexDirection: "column", gap: 2 }}><div style={{ display: "flex", alignItems: "center", gap: 6 }}><div style={{ width: 44, height: 4, background: "rgba(255,255,255,.05)", borderRadius: 2, overflow: "hidden" }}><div style={{ width: p + "%", height: "100%", background: c, borderRadius: 2 }} /></div><span style={{ color: c, fontSize: 12, fontWeight: 700, fontVariantNumeric: "tabular-nums" }}>{(epss * 100).toFixed(2)}%</span></div>{percentile != null && <span style={{ fontSize: 9, color: T.textMuted }}>{(percentile * 100).toFixed(0)}th pctl</span>}</div> }
function Chip({ icon, count, color = T.textMuted }) { return <span style={{ display: "inline-flex", alignItems: "center", gap: 4, padding: "2px 7px", background: "rgba(255,255,255,.03)", borderRadius: 3, fontSize: 11, color }}>{icon} {count ?? "—"}</span> }

function ExploitBadges({ nuclei, msf, edb, et }) {
  if (!nuclei && !msf && !edb && !et) return <span style={{ color: T.textDim, fontSize: 11 }}>—</span>;
  return <div style={{ display: "flex", gap: 3, flexWrap: "wrap" }}>
    {nuclei && <span title="Nuclei template" style={{ padding: "1px 6px", borderRadius: 3, background: "rgba(168,85,247,.12)", border: "1px solid rgba(168,85,247,.25)", color: "#c084fc", fontSize: 9, fontWeight: 700 }}>NUCLEI</span>}
    {msf && <span title="Metasploit module" style={{ padding: "1px 6px", borderRadius: 3, background: "rgba(239,68,68,.12)", border: "1px solid rgba(239,68,68,.25)", color: "#f87171", fontSize: 9, fontWeight: 700 }}>MSF</span>}
    {edb && <span title="Exploit-DB" style={{ padding: "1px 6px", borderRadius: 3, background: "rgba(251,191,36,.12)", border: "1px solid rgba(251,191,36,.25)", color: "#fbbf24", fontSize: 9, fontWeight: 700 }}>EDB</span>}
    {et && <span title="Emerging Threats rule" style={{ padding: "1px 6px", borderRadius: 3, background: "rgba(6,182,212,.12)", border: "1px solid rgba(6,182,212,.25)", color: "#22d3ee", fontSize: 9, fontWeight: 700 }}>ET</span>}
  </div>;
}

const COLUMNS = [
  { key: "id", label: "CVE ID", sort: "year", align: "left" },
  { key: "sev", label: "Severity", sort: "sev", align: "left" },
  { key: "cvss", label: "CVSS 3", sort: "cvss", align: "left" },
  { key: "epss", label: "EPSS", sort: "epss", align: "left" },
  { key: "exploits", label: "Public Exploits", sort: "exploits", align: "left" },
  { key: "et", label: "ET Rules", sort: "et", align: "center" },
  { key: "posts", label: "Posts", sort: "posts", align: "center" },
  { key: "repos", label: "Repos", sort: "repos", align: "center" },
  { key: "nuclei", label: "Nuclei", sort: "nuclei", align: "left" },
  { key: "desc", label: "Description", sort: null, align: "left", min: 200 },
];
const SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
const FILTERS = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"];
const PAGE_SIZES = [5, 10, 15, 30, 50, 100, "All"];

async function fetchJson(url) { try { const r = await fetch(url); if (!r.ok) throw 0; return await r.json(); } catch { return null; } }

export default function App() {
  const [raw, setRaw] = useState(null);
  const [epssData, setEpss] = useState(null);
  const [nucleiData, setNuclei] = useState(null);
  const [msfData, setMsf] = useState(null);
  const [edbData, setEdb] = useState(null);
  const [etData, setEt] = useState(null);
  const [loading, setLoading] = useState(true);
  const [enrichLoading, setEnrich] = useState(true);
  const [error, setError] = useState(null);
  const [sortKey, setSortKey] = useState("cvss");
  const [sortDir, setSortDir] = useState("desc");
  const [sevFilter, setSevF] = useState("ALL");
  const [epssFilter, setEpssF] = useState("ALL");
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState(null);
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(30);

  useEffect(() => { (async () => { try { const r = await fetch(FEED_URL); if (!r.ok) throw new Error("HTTP " + r.status); setRaw(await r.json()) } catch (e) { setError(e.message) } finally { setLoading(false) } })() }, []);
  useEffect(() => { (async () => { const [e, n, m, d, et] = await Promise.all([fetchJson("/api/epss"), fetchJson("/api/nuclei"), fetchJson("/api/metasploit"), fetchJson("/api/exploitdb"), fetchJson("/api/et-rules")]); setEpss(e); setNuclei(n); setMsf(m); setEdb(d); setEt(et); setEnrich(false) })() }, []);

  const entries = useMemo(() => {
    if (!raw) return [];
    return Object.entries(raw).map(([id, d]) => {
      const ep = epssData?.[id], nu = nucleiData?.[id], ms = msfData?.[id], ed = edbData?.[id], et = etData?.[id];
      return {
        id, ...d, year: extractYear(id), postCount: d.posts?.length || 0, repoCount: d.repos?.length || 0,
        nucleiDate: nu ? (nu.name || "yes") : (d.nuclei?.updated || null),
        nucleiInfo: nu || d.nuclei || null,
        desc: d.description || "",
        epssScore: ep?.epss ?? null, epssPercentile: ep?.percentile ?? null,
        hasNuclei: !!nu, hasMsf: !!ms, hasEdb: !!ed, hasEt: !!et,
        msfModules: ms || null, edbEntries: ed || null, etRules: et || null,
        exploitCount: (nu ? 1 : 0) + (ms ? ms.length : 0) + (ed ? ed.length : 0),
        etCount: et ? et.length : 0,
      };
    });
  }, [raw, epssData, nucleiData, msfData, edbData, etData]);

  const handleSort = useCallback(k => { if (!k) return; sortKey === k ? setSortDir(d => d === "desc" ? "asc" : "desc") : (setSortKey(k), setSortDir("desc")) }, [sortKey]);

  const filtered = useMemo(() => {
    let f = entries;
    if (sevFilter !== "ALL") f = f.filter(e => (e.severity || "").toUpperCase() === sevFilter);
    if (epssFilter !== "ALL") f = f.filter(e => { const s = e.epssScore; if (s == null) return false; switch (epssFilter) { case "CRITICAL": return s >= .5; case "HIGH": return s >= .15 && s < .5; case "MEDIUM": return s >= .05 && s < .15; case "LOW": return s < .05; default: return true } });
    if (search.trim()) { const q = search.toLowerCase(); f = f.filter(e => e.id.toLowerCase().includes(q) || (e.desc || "").toLowerCase().includes(q) || (e.posts || []).some(p => strip(p.content).toLowerCase().includes(q))) }
    f.sort((a, b) => { let c = 0; switch (sortKey) { case "cvss": c = (b.cvss3 ?? -1) - (a.cvss3 ?? -1); break; case "year": c = b.year - a.year || b.id.localeCompare(a.id); break; case "sev": c = (SEV_RANK[b.severity?.toUpperCase()] || 0) - (SEV_RANK[a.severity?.toUpperCase()] || 0); break; case "epss": c = (b.epssScore ?? -1) - (a.epssScore ?? -1); break; case "posts": c = b.postCount - a.postCount; break; case "repos": c = b.repoCount - a.repoCount; break; case "nuclei": c = (b.nucleiDate || "").localeCompare(a.nucleiDate || ""); break; case "exploits": c = b.exploitCount - a.exploitCount; break; case "et": c = b.etCount - a.etCount; break; default: c = 0 } return sortDir === "asc" ? -c : c });
    return f;
  }, [entries, sevFilter, epssFilter, search, sortKey, sortDir]);

  const showAll = pageSize === "All";
  const effectivePS = showAll ? filtered.length : pageSize;
  const totalP = showAll ? 1 : Math.ceil(filtered.length / effectivePS);
  const paged = filtered.slice(page * effectivePS, (page + 1) * effectivePS);
  useEffect(() => { setPage(0) }, [sortKey, sortDir, sevFilter, epssFilter, search, pageSize]);
  const toggle = useCallback(id => setExpanded(p => p === id ? null : id), []);

  if (loading) return <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: T.bg, color: T.white, fontFamily: "'Inter',system-ui,sans-serif" }}><div style={{ textAlign: "center" }}><div style={{ fontSize: 32, marginBottom: 16 }}><svg width="40" height="40" viewBox="0 0 40 40" fill="none"><circle cx="20" cy="20" r="18" stroke={T.accent} strokeWidth="2" opacity=".3" /><circle cx="20" cy="20" r="18" stroke={T.accent} strokeWidth="2" strokeDasharray="28 85" style={{ animation: "spin 1s linear infinite" }} /></svg></div><div style={{ fontSize: 13, letterSpacing: 2, color: T.textMuted }}>LOADING INTELLIGENCE...</div><style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style></div></div>;
  if (error) return <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: T.bg, color: T.red, fontFamily: "monospace" }}><div>ERROR: {error}</div></div>;

  const FB = ({ label, value, onChange }) => <div style={{ display: "flex", alignItems: "center", gap: 5 }}><span style={{ fontSize: 10, color: T.textMuted, textTransform: "uppercase", letterSpacing: ".1em", fontWeight: 600 }}>{label}</span>{FILTERS.map(s => <button key={s} onClick={() => onChange(s)} style={{ padding: "3px 9px", borderRadius: 4, border: "1px solid", borderColor: value === s ? (s === "ALL" ? T.accent : sc(s).border) : T.border, background: value === s ? (s === "ALL" ? T.accentGlow : sc(s).bg) : "transparent", color: value === s ? (s === "ALL" ? T.accentLight : sc(s).text) : T.textDim, fontSize: 10, fontFamily: "inherit", cursor: "pointer", fontWeight: value === s ? 600 : 400, transition: "all .15s" }}>{s}</button>)}</div>;
  const PB = ({ disabled, onClick, children }) => <button disabled={disabled} onClick={onClick} style={{ padding: "4px 10px", borderRadius: 4, border: `1px solid ${T.border}`, background: "transparent", color: disabled ? T.textDim : T.textMuted, fontSize: 11, fontFamily: "inherit", cursor: disabled ? "default" : "pointer", transition: "color .15s" }}>{children}</button>;
  const Pager = () => totalP > 1 ? <div style={{ display: "flex", gap: 5, alignItems: "center" }}><PB disabled={page === 0} onClick={() => setPage(p => p - 1)}>← Prev</PB><span style={{ fontSize: 11, color: T.textMuted, fontVariantNumeric: "tabular-nums" }}>{page + 1} / {totalP}</span><PB disabled={page >= totalP - 1} onClick={() => setPage(p => p + 1)}>Next →</PB></div> : null;
  const Arrow = ({ k }) => { if (sortKey !== k) return <span style={{ color: T.textDim, marginLeft: 3, fontSize: 10 }}>⇅</span>; return <span style={{ color: T.accent, marginLeft: 3, fontSize: 10 }}>{sortDir === "desc" ? "↓" : "↑"}</span> };

  return <div style={{ minHeight: "100vh", background: T.bg, color: T.text, fontFamily: "'Inter','Segoe UI',system-ui,sans-serif" }}>
    <style>{`@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:${T.bg}}::-webkit-scrollbar-thumb{background:${T.border};border-radius:3px}::selection{background:rgba(37,99,235,.3)}input:focus,select:focus{outline:none;border-color:${T.accent}!important;box-shadow:0 0 0 2px ${T.accentGlow}}`}</style>

    {/* ── Header ── */}
    <header style={{ background: `linear-gradient(180deg,${T.bgCard} 0%,${T.bg} 100%)`, borderBottom: `1px solid ${T.border}`, padding: "20px 32px", position: "sticky", top: 0, zIndex: 50, backdropFilter: "blur(16px)" }}>
      <div style={{ maxWidth: 1600, margin: "0 auto" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 16 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
            {/* Spider/web icon */}
            <div style={{ width: 36, height: 36, borderRadius: 8, background: `linear-gradient(135deg, ${T.accent}, #1d4ed8)`, display: "flex", alignItems: "center", justifyContent: "center", boxShadow: `0 0 20px ${T.accentGlow}` }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round"><circle cx="12" cy="12" r="3" /><path d="M12 2v7M12 15v7M2 12h7M15 12h7M4.93 4.93l4.95 4.95M14.12 14.12l4.95 4.95M4.93 19.07l4.95-4.95M14.12 9.88l4.95-4.95" /></svg>
            </div>
            <div>
              <h1 style={{ fontSize: 20, fontWeight: 800, color: T.white, letterSpacing: "-.02em", lineHeight: 1.1 }}>
                Arachnid Intel
              </h1>
              <p style={{ fontSize: 11, color: T.textMuted, marginTop: 2, fontWeight: 500 }}>
                {entries.length} CVEs
                {epssData && " · EPSS"}{nucleiData && " · Nuclei"}{msfData && " · MSF"}{edbData && " · EDB"}{etData && " · ET Rules"}
                {enrichLoading && " · Loading..."}
              </p>
            </div>
          </div>
          <div style={{ position: "relative", width: 300 }}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={T.textDim} strokeWidth="2" style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)" }}><circle cx="11" cy="11" r="7" /><path d="M21 21l-4.35-4.35" /></svg>
            <input type="text" placeholder="Search CVE, description..." value={search} onChange={e => setSearch(e.target.value)} style={{ width: "100%", padding: "9px 12px 9px 34px", background: "rgba(255,255,255,.03)", border: `1px solid ${T.border}`, borderRadius: 6, color: T.white, fontSize: 12, fontFamily: "inherit" }} />
          </div>
        </div>
        <div style={{ display: "flex", gap: 12, marginTop: 14, flexWrap: "wrap", alignItems: "center" }}>
          <FB label="Severity" value={sevFilter} onChange={setSevF} />
          <div style={{ width: 1, height: 18, background: T.border }} />
          <FB label="EPSS" value={epssFilter} onChange={setEpssF} />
        </div>
      </div>
    </header>

    {/* ── Results bar ── */}
    <div style={{ maxWidth: 1600, margin: "0 auto", padding: "14px 32px 0" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ fontSize: 11, color: T.textMuted }}>Showing {paged.length} of {filtered.length}</span>
          <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
            <span style={{ fontSize: 10, color: T.textDim, textTransform: "uppercase", letterSpacing: ".08em" }}>Per page</span>
            {PAGE_SIZES.map(s => <button key={s} onClick={() => setPageSize(s)} style={{ padding: "2px 8px", borderRadius: 3, border: `1px solid ${pageSize === s ? T.accent : T.border}`, background: pageSize === s ? T.accentGlow : "transparent", color: pageSize === s ? T.accentLight : T.textDim, fontSize: 10, fontFamily: "inherit", cursor: "pointer", fontWeight: pageSize === s ? 600 : 400, transition: "all .15s" }}>{s}</button>)}
          </div>
        </div>
        <Pager />
      </div>
    </div>

    {/* ── Table ── */}
    <main style={{ maxWidth: 1600, margin: "0 auto", padding: "10px 32px 48px" }}>
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "separate", borderSpacing: "0 3px" }}>
          <thead><tr>
            {COLUMNS.map(col => <th key={col.key} onClick={() => col.sort && handleSort(col.sort)} style={{ textAlign: col.align, padding: "7px 10px", fontWeight: 600, fontSize: 10, color: sortKey === col.sort ? T.accentLight : T.textMuted, textTransform: "uppercase", letterSpacing: ".08em", cursor: col.sort ? "pointer" : "default", userSelect: "none", whiteSpace: "nowrap", minWidth: col.min, borderBottom: sortKey === col.sort ? `2px solid ${T.accent}` : "2px solid transparent", transition: "color .15s" }} onMouseEnter={e => { if (col.sort) e.currentTarget.style.color = T.accentLight }} onMouseLeave={e => { if (col.sort) e.currentTarget.style.color = sortKey === col.sort ? T.accentLight : T.textMuted }}>{col.label}{col.sort && <Arrow k={col.sort} />}</th>)}
          </tr></thead>
          <tbody>
            {paged.map(e => { const isX = expanded === e.id, c = sc(e.severity); return <React.Fragment key={e.id}>
              <tr onClick={() => toggle(e.id)} style={{ cursor: "pointer", background: isX ? T.bgExpand : T.bgCard, borderLeft: `3px solid ${c.border}`, transition: "background .15s" }} onMouseEnter={ev => { if (!isX) ev.currentTarget.style.background = T.bgHover }} onMouseLeave={ev => { ev.currentTarget.style.background = isX ? T.bgExpand : T.bgCard }}>
                <td style={{ padding: "9px 10px", whiteSpace: "nowrap" }}><span style={{ color: T.accentLight, fontWeight: 600, fontSize: 12 }}>{e.id}</span><div style={{ fontSize: 10, color: T.textDim }}>{e.year}</div></td>
                <td style={{ padding: "9px 10px" }}><Badge severity={e.severity} /></td>
                <td style={{ padding: "9px 10px" }}><CvssBar score={e.cvss3} /></td>
                <td style={{ padding: "9px 10px" }}><EpssCell epss={e.epssScore} percentile={e.epssPercentile} /></td>
                <td style={{ padding: "9px 10px" }}><ExploitBadges nuclei={e.hasNuclei} msf={e.hasMsf} edb={e.hasEdb} et={e.hasEt} /></td>
                <td style={{ padding: "9px 10px", textAlign: "center" }}>{e.etCount > 0 ? <span style={{ color: T.cyan, fontWeight: 700, fontSize: 12 }}>{e.etCount}</span> : <span style={{ color: T.textDim }}>—</span>}</td>
                <td style={{ padding: "9px 10px", textAlign: "center" }}><Chip icon="💬" count={e.postCount} color={e.postCount > 3 ? T.orange : T.textMuted} /></td>
                <td style={{ padding: "9px 10px", textAlign: "center" }}><Chip icon="📦" count={e.repoCount} color={e.repoCount > 0 ? T.purple : T.textMuted} /></td>
                <td style={{ padding: "9px 10px", fontSize: 11, maxWidth: 140 }}>{e.nucleiInfo ? <div><span style={{ color: T.green, fontWeight: 600 }}>{e.nucleiInfo.name ? e.nucleiInfo.name.slice(0, 28) + (e.nucleiInfo.name.length > 28 ? "…" : "") : "✓"}</span>{e.nucleiInfo.severity && <div style={{ fontSize: 9, color: T.textMuted, marginTop: 1 }}>{e.nucleiInfo.severity}</div>}</div> : <span style={{ color: T.textDim }}>—</span>}</td>
                <td style={{ padding: "9px 10px", fontSize: 11, color: T.textMuted, maxWidth: 300 }}><div style={{ overflow: "hidden", textOverflow: "ellipsis", display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", lineHeight: 1.5 }}>{e.desc || <span style={{ color: T.textDim, fontStyle: "italic" }}>No description</span>}</div></td>
              </tr>

              {/* ── Expanded detail ── */}
              {isX && <tr><td colSpan={10} style={{ padding: "0 10px 10px", background: T.bgExpand }}>
                <div style={{ padding: 16, background: "rgba(0,0,0,.25)", borderRadius: 8, border: `1px solid ${T.border}` }}>
                  {/* Scores row */}
                  <div style={{ marginBottom: 16, display: "flex", gap: 28, flexWrap: "wrap" }}>
                    {e.epssScore != null && <div><div style={{ fontSize: 10, color: T.textMuted, textTransform: "uppercase", letterSpacing: ".1em", marginBottom: 3, fontWeight: 600 }}>EPSS</div><span style={{ fontSize: 20, fontWeight: 800, color: epsC(e.epssScore) }}>{(e.epssScore * 100).toFixed(3)}%</span>{e.epssPercentile != null && <span style={{ fontSize: 11, color: T.textMuted, marginLeft: 8 }}>({(e.epssPercentile * 100).toFixed(1)}th pctl)</span>}</div>}
                    {e.cvss3 != null && <div><div style={{ fontSize: 10, color: T.textMuted, textTransform: "uppercase", letterSpacing: ".1em", marginBottom: 3, fontWeight: 600 }}>CVSS 3</div><span style={{ fontSize: 20, fontWeight: 800, color: e.cvss3 >= 9 ? T.red : e.cvss3 >= 7 ? T.orange : T.yellow }}>{e.cvss3.toFixed(1)}</span></div>}
                  </div>

                  {/* ET Rules */}
                  {e.etRules && <div style={{ marginBottom: 16 }}><div style={{ fontSize: 10, color: T.textMuted, textTransform: "uppercase", letterSpacing: ".1em", marginBottom: 8, fontWeight: 600 }}>Emerging Threats Rules ({e.etRules.length})</div>
                    {e.etRules.slice(0, 8).map((r, i) => <div key={i} style={{ padding: "7px 10px", background: "rgba(6,182,212,.04)", borderRadius: 5, border: "1px solid rgba(6,182,212,.1)", marginBottom: 3, fontSize: 11 }}>
                      <span style={{ color: T.cyan, fontWeight: 600 }}>SID:{r.sid}</span>
                      <span style={{ color: T.text, marginLeft: 8 }}>{r.msg}</span>
                      {r.classtype && <span style={{ color: T.textDim, marginLeft: 8, fontSize: 10 }}>({r.classtype})</span>}
                    </div>)}
                  </div>}

                  {/* Nuclei */}
                  {e.nucleiInfo && <div style={{ marginBottom: 16 }}><div style={{ fontSize: 10, color: T.textMuted, textTransform: "uppercase", letterSpacing: ".1em", marginBottom: 8, fontWeight: 600 }}>Nuclei Template</div><div style={{ padding: "8px 10px", background: "rgba(168,85,247,.04)", borderRadius: 5, border: "1px solid rgba(168,85,247,.12)", fontSize: 11 }}>
                    {e.nucleiInfo.name && <div style={{ color: "#c084fc", fontWeight: 600, marginBottom: 3 }}>{e.nucleiInfo.name}</div>}
                    {e.nucleiInfo.severity && <span style={{ color: T.textMuted }}>Severity: {e.nucleiInfo.severity} </span>}
                    {e.nucleiInfo.file_path && <div style={{ marginTop: 4 }}><a href={`https://github.com/projectdiscovery/nuclei-templates/blob/main/${e.nucleiInfo.file_path}`} target="_blank" rel="noopener noreferrer" style={{ color: T.purple, textDecoration: "none", fontSize: 10, fontWeight: 500 }}>View template →</a></div>}
                    {e.nucleiInfo.url && <div style={{ marginTop: 4 }}><a href={e.nucleiInfo.url} target="_blank" rel="noopener noreferrer" style={{ color: T.purple, textDecoration: "none", fontSize: 10 }}>{e.nucleiInfo.url}</a></div>}
                  </div></div>}

                  {/* Metasploit */}
                  {e.msfModules && <div style={{ marginBottom: 16 }}><div style={{ fontSize: 10, color: T.textMuted, textTransform: "uppercase", letterSpacing: ".1em", marginBottom: 8, fontWeight: 600 }}>Metasploit Modules ({e.msfModules.length})</div>
                    {e.msfModules.slice(0, 5).map((m, i) => <div key={i} style={{ padding: "7px 10px", background: "rgba(239,68,68,.04)", borderRadius: 5, border: "1px solid rgba(239,68,68,.1)", marginBottom: 3, fontSize: 11 }}>
                      <div style={{ color: "#f87171", fontWeight: 600 }}>{m.name}</div>
                      <div style={{ color: T.textDim, fontSize: 10, marginTop: 1 }}>{m.path}</div>
                    </div>)}
                  </div>}

                  {/* Exploit-DB */}
                  {e.edbEntries && <div style={{ marginBottom: 16 }}><div style={{ fontSize: 10, color: T.textMuted, textTransform: "uppercase", letterSpacing: ".1em", marginBottom: 8, fontWeight: 600 }}>Exploit-DB ({e.edbEntries.length})</div>
                    {e.edbEntries.slice(0, 5).map((x, i) => <div key={i} style={{ padding: "7px 10px", background: "rgba(251,191,36,.04)", borderRadius: 5, border: "1px solid rgba(251,191,36,.1)", marginBottom: 3, fontSize: 11 }}>
                      <a href={x.url} target="_blank" rel="noopener noreferrer" style={{ color: T.orange, textDecoration: "none", fontWeight: 600 }}>EDB-{x.id}</a>
                      <span style={{ color: T.textMuted, marginLeft: 8 }}>{x.title}</span>
                      {x.date && <span style={{ color: T.textDim, marginLeft: 6, fontSize: 10 }}>({x.date})</span>}
                    </div>)}
                  </div>}

                  {/* Description */}
                  {e.desc && <div style={{ marginBottom: 16 }}><div style={{ fontSize: 10, color: T.textMuted, textTransform: "uppercase", letterSpacing: ".1em", marginBottom: 8, fontWeight: 600 }}>Full Description</div><div style={{ fontSize: 12, color: T.text, lineHeight: 1.6 }}>{e.desc}</div></div>}

                  {/* Posts */}
                  {e.posts?.length > 0 && <div style={{ marginBottom: 16 }}><div style={{ fontSize: 10, color: T.textMuted, textTransform: "uppercase", letterSpacing: ".1em", marginBottom: 8, fontWeight: 600 }}>Fediverse Posts ({e.posts.length})</div>
                    {e.posts.slice(0, 5).map((p, i) => <div key={i} style={{ padding: "8px 10px", background: "rgba(255,255,255,.02)", borderRadius: 5, marginBottom: 4, borderLeft: `2px solid ${T.border}` }}>
                      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}><span style={{ color: T.accentLight, fontSize: 11 }}>@{p.account?.acct || "unknown"}</span><span style={{ color: T.textDim, fontSize: 10 }}>{timeAgo(p.created_at)}</span></div>
                      <div style={{ fontSize: 11, color: T.textMuted, lineHeight: 1.5 }}>{strip(p.content).slice(0, 280)}{strip(p.content).length > 280 ? "…" : ""}</div>
                      {p.url && <a href={p.url} target="_blank" rel="noopener noreferrer" style={{ fontSize: 10, color: T.accent, textDecoration: "none", marginTop: 3, display: "inline-block" }}>View post →</a>}
                    </div>)}
                  </div>}

                  {/* Repos */}
                  {e.repos?.length > 0 && <div><div style={{ fontSize: 10, color: T.textMuted, textTransform: "uppercase", letterSpacing: ".1em", marginBottom: 8, fontWeight: 600 }}>Repositories ({e.repos.length})</div>
                    {e.repos.slice(0, 5).map((r, i) => <div key={i} style={{ padding: "6px 10px", background: "rgba(255,255,255,.02)", borderRadius: 5, marginBottom: 3 }}><a href={r.url || r} target="_blank" rel="noopener noreferrer" style={{ fontSize: 11, color: T.purple, textDecoration: "none", wordBreak: "break-all" }}>📦 {typeof r === "string" ? r : r.url || JSON.stringify(r)}</a></div>)}
                  </div>}
                </div>
              </td></tr>}
            </React.Fragment> })}
          </tbody>
        </table>
      </div>
      {filtered.length === 0 && <div style={{ textAlign: "center", padding: 64, color: T.textDim }}><div style={{ fontSize: 32, marginBottom: 12 }}>∅</div><div style={{ fontSize: 13 }}>No CVEs match your filters</div></div>}
      {totalP > 1 && <div style={{ display: "flex", justifyContent: "center", marginTop: 20 }}><Pager /></div>}
    </main>
  </div>;
}
