import { AlertOctagon, ArrowRight, Crosshair } from "lucide-react";
import { formatTimestamp } from "../utils/formatTime";

export default function PrimaryThreat({ incidents, ipScores, onInvestigate }) {
  const topIP = Object.entries(ipScores)
    .sort((a, b) => b[1] - a[1])[0];
  const topIncidents = incidents.filter((i) => i.severity === "CRITICAL");
  const primary      = topIncidents[0];
  if (!primary && !topIP) return null;

  const ip       = topIP?.[0] || primary?.ip;
  const relatedIncidents = incidents.filter((i) => i.ip === ip || i.ip?.includes(ip?.split(".")[2] || ""));
  const types    = [...new Set(relatedIncidents.map((i) => i.type))];

  return (
    <div className="card col-span-2" style={{
      border: "1px solid var(--red-border)",
      background: "linear-gradient(135deg, rgba(255,59,92,0.06) 0%, var(--bg-card) 60%)",
      boxShadow: "var(--red-glow)",
    }}>
      <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: "2px", background: "linear-gradient(90deg, transparent, var(--red), transparent)" }} />
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: "16px", flexWrap: "wrap" }}>
        <div style={{ display: "flex", alignItems: "flex-start", gap: "14px", flex: 1 }}>
          <div style={{
            width: "44px", height: "44px", borderRadius: "50%", flexShrink: 0,
            background: "var(--red-bg)", border: "1px solid var(--red-border)",
            display: "flex", alignItems: "center", justifyContent: "center",
          }}>
            <AlertOctagon size={22} style={{ color: "var(--red)" }} />
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: "10px", color: "var(--red)", letterSpacing: "0.15em", textTransform: "uppercase", fontFamily: "'Share Tech Mono', monospace", marginBottom: "4px", display: "flex", alignItems: "center", gap: "8px" }}>
              <span style={{ width: "7px", height: "7px", borderRadius: "50%", background: "var(--red)", display: "inline-block", animation: "pulse 1.5s ease-in-out infinite" }} />
              Primary Threat — Immediate Attention Required
            </div>
            <div style={{ display: "flex", alignItems: "baseline", gap: "12px", flexWrap: "wrap", marginBottom: "8px" }}>
              <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "22px", color: "var(--red)", letterSpacing: "0.05em" }}>{ip}</span>
            </div>
            <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "10px" }}>
              {types.map((t) => (
                <span key={t} className="badge badge-critical" style={{ fontSize: "10px" }}>{t}</span>
              ))}
              <span className="badge badge-critical">{topIncidents.length} critical alert{topIncidents.length !== 1 ? "s" : ""}</span>
            </div>
            <div style={{ display: "flex", gap: "20px", flexWrap: "wrap" }}>
              {relatedIncidents.slice(0, 3).map((inc, i) => (
                <div key={i} style={{ fontSize: "11px", color: "var(--text-secondary)", fontFamily: "'Share Tech Mono', monospace" }}>
                  <span style={{ color: "var(--text-muted)", marginRight: "4px" }}>›</span>
                  {inc.type}: {inc.detail?.slice(0, 40)}{inc.detail?.length > 40 ? "…" : ""}
                  {inc.timestamp && (
                    <span style={{ color: "var(--text-muted)", marginLeft: "6px" }}>{formatTimestamp(inc.timestamp)}</span>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
        <button
          onClick={onInvestigate}
          style={{
            background: "var(--red-bg)", border: "1px solid var(--red-border)",
            color: "var(--red)", borderRadius: "5px", padding: "10px 18px",
            fontFamily: "'Rajdhani', sans-serif", fontSize: "13px", fontWeight: 700,
            letterSpacing: "0.1em", textTransform: "uppercase", cursor: "pointer",
            display: "flex", alignItems: "center", gap: "8px", transition: "all 0.2s",
            whiteSpace: "nowrap", flexShrink: 0,
          }}
          onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(255,59,92,0.2)"; e.currentTarget.style.boxShadow = "var(--red-glow)"; }}
          onMouseLeave={(e) => { e.currentTarget.style.background = "var(--red-bg)"; e.currentTarget.style.boxShadow = "none"; }}
        >
          <Crosshair size={13} />
          Investigate
          <ArrowRight size={13} />
        </button>
      </div>
    </div>
  );
}
