import { useState, useMemo } from "react";
import useLogData from "./hooks/useLogData";
import { correlateEvents } from "./utils/correlate";

import StatusBanner     from "./components/StatusBanner";
import PrimaryThreat    from "./components/PrimaryThreat";
import SeverityFeed     from "./components/SeverityFeed";
import TimelineChart    from "./components/TimelineChart";
import KillChain        from "./components/KillChain";
import LogExplorer      from "./components/LogExplorer";
import AIVerdict        from "./components/AIVerdict";
import SOARWorkbench    from "./components/SOARWorkbench";

import { Shield, Radio, LayoutDashboard, Search, Bot, ClipboardList, ArrowRight } from "lucide-react";
import "./App.css";

const STORAGE_KEY = "soar_cases";

function loadCases() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}"); }
  catch { return {}; }
}

function incidentId(inc) {
  return `${inc.type}__${inc.ip}__${inc.detail}`.replace(/\s+/g, "_");
}

const TABS = [
  { id: "overview",    label: "1. Overview",    icon: LayoutDashboard, next: "investigate", nextLabel: "Start Investigation" },
  { id: "investigate", label: "2. Investigate", icon: Search,          next: "ai",          nextLabel: "Generate AI Analysis" },
  { id: "ai",          label: "3. AI Analysis", icon: Bot,             next: "soar",        nextLabel: "Open SOAR Workbench"  },
  { id: "soar",        label: "4. SOAR",        icon: ClipboardList,   next: null,          nextLabel: null },
];

function StatPill({ label, value, color }) {
  return (
    <div className="stat-pill">
      <span className="stat-value" style={{ color }}>{value}</span>
      <span className="stat-label">{label}</span>
    </div>
  );
}

function StatDivider() {
  return <div style={{ width: "1px", height: "32px", background: "var(--border)", flexShrink: 0 }} />;
}

function NextStepBanner({ currentTab, onNavigate }) {
  const tab = TABS.find((t) => t.id === currentTab);
  if (!tab?.next) return null;
  return (
    <div style={{
      display: "flex", alignItems: "center", justifyContent: "flex-end",
      padding: "8px 28px", background: "var(--bg-secondary)",
      borderTop: "1px solid var(--border)",
    }}>
      <span style={{ fontSize: "11px", color: "var(--text-muted)", marginRight: "10px", fontFamily: "'Share Tech Mono', monospace" }}>
        Next step:
      </span>
      <button
        onClick={() => onNavigate(tab.next)}
        style={{
          background: "transparent", border: "1px solid var(--blue)",
          color: "var(--blue)", borderRadius: "4px", padding: "5px 14px",
          fontFamily: "'Rajdhani', sans-serif", fontSize: "12px", fontWeight: 600,
          letterSpacing: "0.08em", textTransform: "uppercase", cursor: "pointer",
          display: "flex", alignItems: "center", gap: "6px", transition: "all 0.2s",
        }}
        onMouseEnter={(e) => { e.currentTarget.style.background = "var(--blue-bg)"; }}
        onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
      >
        {tab.nextLabel}
        <ArrowRight size={12} />
      </button>
    </div>
  );
}

export default function App() {
  const { data, loading } = useLogData();
  const [activeTab,        setActiveTab]        = useState("overview");
  const [logFilter,        setLogFilter]        = useState({ query: "", source: "all" });
  const [logFilterTrigger, setLogFilterTrigger] = useState(0);

  // Shared SOAR case state — lifted so Overview reacts when cases are closed
  const [cases, setCases] = useState(loadCases);

  function saveCase(id, caseData) {
    const updated = { ...cases, [id]: caseData };
    setCases(updated);
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(updated)); }
    catch { console.warn("Could not persist cases."); }
  }

  const { incidents, ipScores } = useMemo(() => {
    if (loading || !Object.keys(data).length) return { incidents: [], ipScores: {} };
    return correlateEvents(data);
  }, [data, loading]);

  // Incidents closed in SOAR are hidden from Overview
  const openIncidents = useMemo(() =>
    incidents.filter((inc) => !cases[incidentId(inc)]?.verdict),
  [incidents, cases]);

  // Only show IPs that still have at least one open incident on the Overview
  const openIpScores = useMemo(() => {
    const openIPs = new Set(openIncidents.map((inc) => inc.ip));
    return Object.fromEntries(
      Object.entries(ipScores).filter(([ip]) => openIPs.has(ip))
    );
  }, [ipScores, openIncidents]);

  const criticalCount = openIncidents.filter((i) => i.severity === "CRITICAL").length;
  const totalEvents   = Object.values(data).reduce((sum, arr) => sum + (arr?.length || 0), 0);
  const uniqueIPs     = new Set([
    ...(data.auth_logs     || []).map((r) => r.source_ip),
    ...(data.firewall_logs || []).map((r) => r.source_ip),
  ]).size;

  function handleKillChainFilter(query, source) {
    setLogFilter({ query, source });
    setLogFilterTrigger((n) => n + 1);
    setActiveTab("investigate");
  }

  function handleInvestigateTopIP() {
    const topIP = Object.entries(ipScores).sort((a, b) => b[1] - a[1])[0];
    if (topIP) {
      setLogFilter({ query: topIP[0], source: "all" });
      setLogFilterTrigger((n) => n + 1);
    }
    setActiveTab("investigate");
  }

  if (loading) {
    return (
      <div className="loading-screen">
        <div className="spinner" />
        <span>INGESTING LOG DATA...</span>
      </div>
    );
  }

  return (
    <div className="app">
      <header className="header">
        <div className="header-left">
          <Shield size={22} color="var(--blue)" />
          <div>
            <h1 className="header-title">SOC DASHBOARD</h1>
            <p className="header-subtitle">A Little Bit of Hope — Security Operations Center</p>
          </div>
        </div>
        <div className="header-stats">
          <StatPill label="Total Events"   value={totalEvents.toLocaleString()} color="var(--blue)" />
          <StatDivider />
          <StatPill label="Unique IPs"     value={uniqueIPs}                    color="var(--cyan)" />
          <StatDivider />
          <StatPill
            label="Critical Alerts"
            value={criticalCount}
            color={criticalCount > 0 ? "var(--red)" : "var(--green)"}
          />
          <StatDivider />
          <div className="live-indicator">
            <Radio size={12} />
            <span>LIVE</span>
          </div>
        </div>
      </header>

      <StatusBanner incidents={openIncidents} />

      <nav className="tab-nav">
        {TABS.map((tab) => {
          const Icon  = tab.icon;
          const isDot = (tab.id === "overview" || tab.id === "soar") && criticalCount > 0;
          return (
            <button
              key={tab.id}
              className={`tab-btn ${activeTab === tab.id ? "active" : ""}`}
              onClick={() => setActiveTab(tab.id)}
            >
              <Icon size={13} />
              {tab.label}
              {isDot && <span className="tab-dot" style={{ background: "var(--red)" }} />}
            </button>
          );
        })}
      </nav>

      <main className="tab-content">

        {activeTab === "overview" && (
          <>
            {openIncidents.length > 0 && (
              <PrimaryThreat
                incidents={openIncidents}
                ipScores={openIpScores}
                onInvestigate={handleInvestigateTopIP}
              />
            )}
            {openIncidents.length === 0 && (
              <div className="card col-span-2" style={{
                border: "1px solid var(--green-border)",
                background: "var(--green-bg)",
                padding: "20px 24px",
                display: "flex", alignItems: "center", gap: "16px",
              }}>
                <span style={{ fontSize: "28px" }}>✓</span>
                <div>
                  <div style={{ fontWeight: 700, fontSize: "15px", color: "var(--green)", fontFamily: "'Rajdhani', sans-serif", letterSpacing: "0.1em", textTransform: "uppercase" }}>
                    All Incidents Resolved
                  </div>
                  <div style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "3px", fontFamily: "'Share Tech Mono', monospace" }}>
                    All correlated incidents have been closed in the SOAR workbench.
                  </div>
                </div>
              </div>
            )}
            <SeverityFeed incidents={openIncidents} limit={10} />
          </>
        )}

        {activeTab === "investigate" && (
          <>
            {openIncidents.length > 0 && (
              <KillChain data={data} onFilterSelect={handleKillChainFilter} />
            )}
            <TimelineChart data={data} />
            <LogExplorer
              data={data}
              externalFilter={logFilter}
              externalFilterTrigger={logFilterTrigger}
            />
          </>
        )}

        {activeTab === "ai" && (
          <AIVerdict incidents={incidents} data={data} />
        )}

        {activeTab === "soar" && (
          <SOARWorkbench
            incidents={incidents}
            cases={cases}
            onSaveCase={saveCase}
          />
        )}

      </main>

      <NextStepBanner currentTab={activeTab} onNavigate={setActiveTab} />
    </div>
  );
}