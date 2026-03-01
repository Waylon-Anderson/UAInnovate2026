import { useState, useMemo, useEffect, useRef } from "react";
import { Search, X, ChevronDown, ChevronUp, Zap } from "lucide-react";
import { formatTimestamp } from "../utils/formatTime";
import { sanitizeQuery } from "../utils/sanitize";

// Dynamically resolve label/color by keyword match so any filename variant works
// e.g. "malware_alerts_1" → "Malware", "auth_logs_2" → "Auth"
function getSourceLabel(key) {
  const k = key.toLowerCase();
  if (k.includes("malware")) return "Malware";
  if (k.includes("auth"))    return "Auth";
  if (k.includes("dns"))     return "DNS";
  if (k.includes("firewall")) return "Firewall";
  return key;
}

function getSourceColor(key) {
  const k = key.toLowerCase();
  if (k.includes("malware"))  return "var(--red)";
  if (k.includes("auth"))     return "var(--blue)";
  if (k.includes("dns"))      return "var(--cyan)";
  if (k.includes("firewall")) return "var(--yellow)";
  return "var(--text-muted)";
}

// Source tab keys — canonical names used for filtering
const SOURCE_TAB_KEYS = {
  auth:     (key) => key.toLowerCase().includes("auth"),
  dns:      (key) => key.toLowerCase().includes("dns"),
  firewall: (key) => key.toLowerCase().includes("firewall"),
  malware:  (key) => key.toLowerCase().includes("malware"),
};

const QUICK_FILTERS = [
  { label: "Failed Logins",     query: "Failed",    source: "auth_logs" },
  { label: "External IPs",      query: "185.",       source: "all" },
  { label: "Bad Domains",       query: "bad-actor",  source: "dns_logs" },
  { label: "Blocked Traffic",   query: "Block",      source: "firewall_logs" },
  { label: "Malware",           query: "Beacon",     source: "malware_alerts" },
  { label: "Successful Logins", query: "Success",    source: "auth_logs" },
];

function rowMatchesQuery(row, query) {
  if (!query.trim()) return true;
  const q = query.toLowerCase();
  return Object.values(row).some((v) => String(v).toLowerCase().includes(q));
}

function Highlight({ text, query }) {
  if (!query.trim() || !text) return <span>{text}</span>;
  const idx = String(text).toLowerCase().indexOf(query.toLowerCase());
  if (idx === -1) return <span>{text}</span>;
  const str = String(text);
  return (
    <span>
      {str.slice(0, idx)}
      <mark style={{ background: "rgba(0,170,255,0.25)", color: "var(--cyan)", borderRadius: "2px", padding: "0 1px" }}>
        {str.slice(idx, idx + query.length)}
      </mark>
      {str.slice(idx + query.length)}
    </span>
  );
}

const PAGE_SIZE = 20;

export default function LogExplorer({ data, externalFilter, externalFilterTrigger }) {
  const [query,        setQuery]        = useState("");
  const [activeSource, setActiveSource] = useState("all");
  const [page,         setPage]         = useState(1);
  const [expandedRow,  setExpandedRow]  = useState(null);
  const [sortField,    setSortField]    = useState("timestamp");
  const [sortDir,      setSortDir]      = useState("desc");
  const containerRef = useRef(null);

  // Map partial keywords from KillChain to full source key names used by the tab buttons
  const SOURCE_MAP = {
    auth:     "auth_logs",
    dns:      "dns_logs",
    firewall: "firewall_logs",
    malware:  "malware_alerts",
  };

  // Apply external filter (e.g. from Kill Chain "View in Log Explorer")
  useEffect(() => {
    if (!externalFilter || !externalFilterTrigger) return;
    setQuery(externalFilter.query || "");
    const normalized = SOURCE_MAP[externalFilter.source] || externalFilter.source || "all";
    setActiveSource(normalized);
    setPage(1);
    setTimeout(() => containerRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 100);
  }, [externalFilterTrigger]); // eslint-disable-line react-hooks/exhaustive-deps

  const allRows = useMemo(() =>
    Object.entries(data).flatMap(([source, rows]) =>
      (rows || []).map((row) => ({ ...row, _source: source }))
    ),
  [data]);

  const filtered = useMemo(() => {
    setPage(1);
    return allRows.filter((row) => {
      const sourceMatch = activeSource === "all" ||
        (SOURCE_TAB_KEYS[activeSource] && SOURCE_TAB_KEYS[activeSource](row._source));
      const queryMatch  = rowMatchesQuery(row, query);
      return sourceMatch && queryMatch;
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [allRows, query, activeSource]);

  const sorted = useMemo(() =>
    [...filtered].sort((a, b) => {
      const av = a[sortField] || a.timestamp || "";
      const bv = b[sortField] || b.timestamp || "";
      return sortDir === "asc" ? av.localeCompare(bv) : bv.localeCompare(av);
    }),
  [filtered, sortField, sortDir]);

  const totalPages = Math.ceil(sorted.length / PAGE_SIZE);
  const paginated  = sorted.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const columns = useMemo(() => {
    const keys = new Set();
    paginated.forEach((row) => Object.keys(row).forEach((k) => { if (k !== "_source") keys.add(k); }));
    return [...keys];
  }, [paginated]);

  function toggleSort(field) {
    if (sortField === field) setSortDir((d) => d === "asc" ? "desc" : "asc");
    else { setSortField(field); setSortDir("asc"); }
  }

  function applyQuickFilter(qf) {
    setQuery(qf.query);
    setActiveSource(qf.source);
    setPage(1);
  }

  function clearSearch() {
    setQuery(""); setActiveSource("all"); setPage(1);
  }

  const sourceCounts = useMemo(() => {
    const counts = { all: allRows.length };
    Object.entries(SOURCE_TAB_KEYS).forEach(([cat, matchFn]) => {
      counts[cat] = allRows.filter((r) => matchFn(r._source)).length;
    });
    return counts;
  }, [allRows]);

  return (
    <div className="card col-span-2" ref={containerRef}>
      <div className="card-title" style={{ marginBottom: "14px" }}>
        <Search size={14} />
        Log Explorer
        <span style={{ marginLeft: "auto", fontSize: "11px", color: "var(--text-muted)", fontFamily: "'Share Tech Mono', monospace" }}>
          {filtered.length.toLocaleString()} results
        </span>
      </div>

      {/* Quick filter buttons */}
      <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", marginBottom: "10px" }}>
        <span style={{ fontSize: "10px", color: "var(--text-muted)", letterSpacing: "0.1em", textTransform: "uppercase", alignSelf: "center", fontFamily: "'Share Tech Mono', monospace", marginRight: "2px" }}>
          <Zap size={10} style={{ display: "inline", marginRight: "4px" }} />Quick
        </span>
        {QUICK_FILTERS.map((qf) => (
          <button
            key={qf.label}
            onClick={() => applyQuickFilter(qf)}
            style={{
              background: query === qf.query && activeSource === qf.source ? "var(--blue-bg)" : "transparent",
              border: `1px solid ${query === qf.query && activeSource === qf.source ? "var(--blue)" : "var(--border)"}`,
              borderRadius: "3px",
              color: query === qf.query && activeSource === qf.source ? "var(--blue)" : "var(--text-muted)",
              padding: "4px 10px",
              fontSize: "11px",
              fontFamily: "'Rajdhani', sans-serif",
              fontWeight: 600,
              letterSpacing: "0.06em",
              textTransform: "uppercase",
              cursor: "pointer",
              transition: "all 0.15s",
            }}
          >
            {qf.label}
          </button>
        ))}
      </div>

      {/* Search bar + source tabs */}
      <div style={{ display: "flex", gap: "10px", marginBottom: "12px", flexWrap: "wrap" }}>
        <div style={{ flex: 1, minWidth: "200px", position: "relative" }}>
          <Search size={13} style={{ position: "absolute", left: "10px", top: "50%", transform: "translateY(-50%)", color: "var(--text-muted)", pointerEvents: "none" }} />
          <input
            type="text"
            value={query}
            onChange={(e) => { setQuery(sanitizeQuery(e.target.value)); setPage(1); }}
            placeholder="Search by IP, user, domain, action..."
            style={{
              width: "100%", background: "var(--bg-secondary)",
              border: "1px solid var(--border)", borderRadius: "4px",
              padding: "8px 32px", color: "var(--text-primary)",
              fontFamily: "'Share Tech Mono', monospace", fontSize: "12px",
              outline: "none", transition: "border-color 0.2s",
            }}
            onFocus={(e) => (e.target.style.borderColor = "var(--blue)")}
            onBlur={(e)  => (e.target.style.borderColor = "var(--border)")}
          />
          {query && (
            <button onClick={clearSearch} style={{ position: "absolute", right: "8px", top: "50%", transform: "translateY(-50%)", background: "none", border: "none", cursor: "pointer", color: "var(--text-muted)", padding: "2px", display: "flex" }}>
              <X size={13} />
            </button>
          )}
        </div>

        <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
          {[["all", "All", "var(--blue)"], ...Object.keys(SOURCE_TAB_KEYS).map((k) => [k, getSourceLabel(k), getSourceColor(k)])].map(([key, label, color]) => {
            const isActive = activeSource === key;
            return (
              <button key={key} onClick={() => { setActiveSource(key); setPage(1); }}
                style={{
                  background: isActive ? `color-mix(in srgb, ${color} 15%, transparent)` : "transparent",
                  border: `1px solid ${isActive ? color : "var(--border)"}`,
                  borderRadius: "4px", color: isActive ? color : "var(--text-secondary)",
                  padding: "6px 12px", fontSize: "11px", fontFamily: "'Rajdhani', sans-serif",
                  fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase",
                  cursor: "pointer", transition: "all 0.15s", whiteSpace: "nowrap",
                }}
              >
                {label}
                <span style={{ marginLeft: "6px", fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", opacity: 0.65 }}>
                  {sourceCounts[key]?.toLocaleString()}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Table */}
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px", fontFamily: "'Share Tech Mono', monospace" }}>
          <thead>
            <tr style={{ borderBottom: "1px solid var(--border)" }}>
              <th style={{ padding: "7px 10px", textAlign: "left", color: "var(--text-muted)", fontSize: "10px", letterSpacing: "0.1em", textTransform: "uppercase", fontWeight: 400, whiteSpace: "nowrap", width: "80px" }}>
                Source
              </th>
              {columns.map((col) => (
                <th key={col} onClick={() => toggleSort(col)}
                  style={{ padding: "7px 10px", textAlign: "left", color: sortField === col ? "var(--blue)" : "var(--text-muted)", fontSize: "10px", letterSpacing: "0.1em", textTransform: "uppercase", fontWeight: 400, cursor: "pointer", whiteSpace: "nowrap", userSelect: "none" }}
                >
                  <span style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                    {col}
                    {sortField === col
                      ? sortDir === "asc" ? <ChevronUp size={10} /> : <ChevronDown size={10} />
                      : <ChevronDown size={10} style={{ opacity: 0.3 }} />}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {paginated.length === 0 && (
              <tr>
                <td colSpan={columns.length + 1} style={{ padding: "24px", textAlign: "center", color: "var(--text-muted)" }}>
                  No results found{query ? ` for "${query}"` : ""}.
                </td>
              </tr>
            )}
            {paginated.map((row, i) => {
              const isExpanded = expandedRow === i;
              const srcColor   = getSourceColor(row._source);
              return (
                <>
                  <tr key={i}
                    onClick={() => setExpandedRow(isExpanded ? null : i)}
                    style={{ borderBottom: "1px solid var(--border)", cursor: "pointer", background: isExpanded ? "rgba(0,170,255,0.05)" : "transparent", transition: "background 0.15s" }}
                    onMouseEnter={(e) => { if (!isExpanded) e.currentTarget.style.background = "var(--bg-secondary)"; }}
                    onMouseLeave={(e) => { if (!isExpanded) e.currentTarget.style.background = "transparent"; }}
                  >
                    <td style={{ padding: "7px 10px", whiteSpace: "nowrap" }}>
                      <span className="badge" style={{ background: `color-mix(in srgb, ${srcColor} 15%, transparent)`, color: srcColor, border: `1px solid color-mix(in srgb, ${srcColor} 35%, transparent)`, fontSize: "10px" }}>
                        {getSourceLabel(row._source)}
                      </span>
                    </td>
                    {columns.map((col) => {
                      // RED = bad values, GREEN = good values
                      const val = row[col];
                      const displayVal = col === "timestamp" ? formatTimestamp(val) : val;
                      const cellColor =
                        (col === "action" && String(val).includes("Failed"))  ? "var(--red)"
                        : (col === "action" && String(val).includes("Block")) ? "var(--yellow)"
                        : (col === "action" && String(val).includes("Success")) ? "var(--green)"
                        : "var(--text-primary)";
                      return (
                        <td key={col} style={{ padding: "7px 10px", color: cellColor, maxWidth: "200px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          <Highlight text={displayVal ?? "—"} query={query} />
                        </td>
                      );
                    })}
                  </tr>
                  {isExpanded && (
                    <tr key={`${i}-exp`} style={{ background: "rgba(0,170,255,0.04)" }}>
                      <td colSpan={columns.length + 1} style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: "12px 24px" }}>
                          {Object.entries(row).filter(([k]) => k !== "_source").map(([k, v]) => (
                            <div key={k}>
                              <div style={{ fontSize: "9px", color: "var(--text-muted)", letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: "2px" }}>{k}</div>
                              <div style={{ fontSize: "13px", color: "var(--cyan)" }}>
                                <Highlight text={k === "timestamp" ? formatTimestamp(v) : String(v ?? "—")} query={query} />
                              </div>
                            </div>
                          ))}
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginTop: "12px", paddingTop: "12px", borderTop: "1px solid var(--border)", flexWrap: "wrap", gap: "8px" }}>
          <span style={{ fontSize: "11px", color: "var(--text-muted)", fontFamily: "'Share Tech Mono', monospace" }}>
            Page {page} of {totalPages} — {((page-1)*PAGE_SIZE)+1}–{Math.min(page*PAGE_SIZE, filtered.length)} of {filtered.length.toLocaleString()}
          </span>
          <div style={{ display: "flex", gap: "6px" }}>
            <button className="btn" style={{ padding: "4px 12px", fontSize: "11px" }} onClick={() => setPage((p) => Math.max(1, p-1))} disabled={page === 1}>← Prev</button>
            {Array.from({ length: totalPages }, (_, i) => i+1)
              .filter((p) => p === 1 || p === totalPages || Math.abs(p - page) <= 2)
              .reduce((acc, p, idx, arr) => { if (idx > 0 && p - arr[idx-1] > 1) acc.push("..."); acc.push(p); return acc; }, [])
              .map((p, i) =>
                p === "..." ? (
                  <span key={`e${i}`} style={{ padding: "4px 6px", color: "var(--text-muted)", fontSize: "11px" }}>…</span>
                ) : (
                  <button key={p} className="btn"
                    style={{ padding: "4px 10px", fontSize: "11px", background: p === page ? "var(--blue-bg)" : "transparent", borderColor: p === page ? "var(--blue)" : "var(--border)" }}
                    onClick={() => setPage(p)}
                  >{p}</button>
                )
              )}
            <button className="btn" style={{ padding: "4px 12px", fontSize: "11px" }} onClick={() => setPage((p) => Math.min(totalPages, p+1))} disabled={page === totalPages}>Next →</button>
          </div>
        </div>
      )}
    </div>
  );
}