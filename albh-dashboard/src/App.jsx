import { useState, useMemo } from "react";
import useLogData from "./hooks/useLogData";
import { correlateEvents } from "./utils/correlate";

import StatusBanner     from "./components/StatusBanner";
import ThreatScoreboard from "./components/ThreatScoreboard";
import SeverityFeed     from "./components/SeverityFeed";
import TimelineChart    from "./components/TimelineChart";
import KillChain        from "./components/KillChain";
import LogExplorer      from "./components/LogExplorer";
import AIVerdict        from "./components/AIVerdict";
import SOARWorkbench    from "./components/SOARWorkbench";

import { Shield, Radio, LayoutDashboard, Search, Bot, ClipboardList } from "lucide-react";
import "./App.css";

function StatPill({ label, value, color }) {
  return (
    <div className="stat-pill">
      <span className="stat-value" style={{ color }}>{value}</span>
      <span className="stat-label">{label}</span>
    </div>
  );
}

const TABS = [
  { id: "overview",    label: "Overview",    icon: LayoutDashboard },
  { id: "soar",        label: "SOAR",        icon: ClipboardList },
  { id: "investigate", label: "Investigate", icon: Search },
  { id: "ai",          label: "AI Analysis", icon: Bot },
];

export default function App() {
  const { data, loading, stats } = useLogData();
  const [activeTab, setActiveTab] = useState("overview");

  const { incidents, ipScores } = useMemo(() => {
    if (loading || !Object.keys(data).length) return { incidents: [], ipScores: {} };
    return correlateEvents(data);
  }, [data, loading]);

  const criticalCount = incidents.filter((i) => i.severity === "CRITICAL").length;
  const totalEvents   = Object.values(data).reduce((sum, arr) => sum + (arr?.length || 0), 0);
  const uniqueIPs     = new Set([
    ...(data.auth_logs     || []).map((r) => r.source_ip),
    ...(data.firewall_logs || []).map((r) => r.source_ip),
  ]).size;

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
      {/* ── Persistent Header ─────────────────────────────── */}
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
          <StatPill label="Unique IPs"     value={uniqueIPs}                    color="var(--cyan)" />
          <StatPill
            label="Critical Alerts"
            value={criticalCount}
            color={criticalCount > 0 ? "var(--red)" : "var(--green)"}
          />
          <div className="live-indicator">
            <Radio size={12} />
            <span>LIVE</span>
          </div>
        </div>
      </header>

      {/* ── Status Banner (always visible) ────────────────── */}
      <StatusBanner incidents={incidents} />

      {/* ── Tab Navigation ────────────────────────────────── */}
      <nav className="tab-nav">
        {TABS.map((tab) => {
          const Icon    = tab.icon;
          const hasDot  = tab.id === "overview" && criticalCount > 0;
          const soarDot = tab.id === "soar"     && criticalCount > 0;
          return (
            <button
              key={tab.id}
              className={`tab-btn ${activeTab === tab.id ? "active" : ""}`}
              onClick={() => setActiveTab(tab.id)}
            >
              <Icon size={13} />
              {tab.label}
              {(hasDot || soarDot) && (
                <span className="tab-dot" style={{ background: "var(--red)" }} />
              )}
            </button>
          );
        })}
      </nav>

      {/* ── Tab Content ───────────────────────────────────── */}
      <main className="tab-content">

        {/* TAB 1: OVERVIEW */}
        {activeTab === "overview" && (
          <div className="grid-2">
            <ThreatScoreboard ipScores={ipScores} />
            <SeverityFeed incidents={incidents} limit={5} />
          </div>
        )}

        {/* TAB 2: INVESTIGATE */}
        {activeTab === "investigate" && (
          <>
            <KillChain data={data} />
            <TimelineChart data={data} />
            <LogExplorer data={data} />
          </>
        )}

        {/* TAB 3: AI ANALYSIS */}
        {activeTab === "ai" && (
          <AIVerdict incidents={incidents} data={data} />
        )}

        {/* TAB 4: SOAR */}
        {activeTab === "soar" && (
          <SOARWorkbench incidents={incidents} />
        )}

      </main>
    </div>
  );
}