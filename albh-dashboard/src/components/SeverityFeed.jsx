import { AlertTriangle, ShieldAlert, Wifi, Bug, Flame } from "lucide-react";
import { relativeTime, formatTimestamp } from "../utils/formatTime";

const typeIcons = {
  "Brute Force":    ShieldAlert,
  "Malicious DNS":  Wifi,
  "Malware":        Bug,
  "Firewall Block": Flame,
};

// RED = bad, YELLOW = concern
const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

const ACTION_MAP = {
  "Brute Force":    ["BLOCK IP", "RESET CREDENTIALS"],
  "Malicious DNS":  ["BLOCK DOMAIN", "ISOLATE HOST"],
  "Malware":        ["ISOLATE HOST", "RUN FULL SCAN"],
  "Firewall Block": ["REVIEW RULE"],
};

export default function SeverityFeed({ incidents, limit }) {
  const sorted = [...incidents]
    .sort((a, b) => (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9));

  const displayed = limit ? sorted.slice(0, limit) : sorted;
  const criticalCount = incidents.filter((i) => i.severity === "CRITICAL").length;

  return (
    <div className="card">
      <div className="card-title">
        <AlertTriangle size={14} />
        Active Incidents
        {criticalCount > 0 && (
          <span className="badge badge-critical" style={{ marginLeft: "auto" }}>
            {criticalCount} critical
          </span>
        )}
        {criticalCount === 0 && incidents.length > 0 && (
          <span className="badge badge-low" style={{ marginLeft: "auto" }}>
            No critical
          </span>
        )}
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: "8px", maxHeight: limit ? "none" : "380px", overflowY: limit ? "visible" : "auto" }}>
        {displayed.length === 0 && (
          <p style={{ color: "var(--text-muted)", fontSize: "13px" }}>No incidents detected.</p>
        )}

        {displayed.map((inc, i) => {
          const Icon       = typeIcons[inc.type] || AlertTriangle;
          const actions    = ACTION_MAP[inc.type] || [];
          const badgeClass = inc.severity === "CRITICAL" ? "badge-critical"
                           : inc.severity === "HIGH"     ? "badge-high"
                           : inc.severity === "MEDIUM"   ? "badge-medium"
                           :                               "badge-low";
          // Color: RED = critical/high (bad), YELLOW = medium (concern), GREEN = low (ok)
          const iconColor  = inc.severity === "CRITICAL" ? "var(--red)"
                           : inc.severity === "HIGH"     ? "var(--yellow)"
                           : inc.severity === "MEDIUM"   ? "var(--yellow)"
                           :                               "var(--green)";

          const borderColor = inc.severity === "CRITICAL" ? "rgba(255,59,92,0.25)"
                            : inc.severity === "HIGH"     ? "rgba(255,193,7,0.2)"
                            :                               "var(--border)";

          return (
            <div
              key={i}
              className="animate-in"
              style={{
                animationDelay: `${i * 40}ms`,
                background: "var(--bg-secondary)",
                border: `1px solid ${borderColor}`,
                borderRadius: "4px",
                padding: "10px 12px",
                display: "flex",
                alignItems: "flex-start",
                gap: "10px",
              }}
            >
              <Icon size={15} style={{ marginTop: "3px", flexShrink: 0, color: iconColor }} />
              <div style={{ flex: 1, minWidth: 0 }}>
                {/* Top row */}
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px", flexWrap: "wrap" }}>
                  <span style={{ fontWeight: 700, fontSize: "13px" }}>{inc.type}</span>
                  <span className={`badge ${badgeClass}`}>{inc.severity}</span>
                  {inc.timestamp && (
                    <span style={{ marginLeft: "auto", fontSize: "10px", color: "var(--text-muted)", fontFamily: "'Share Tech Mono', monospace", whiteSpace: "nowrap" }}>
                      {relativeTime(inc.timestamp)}
                    </span>
                  )}
                </div>
                {/* IP / detail */}
                <div className="mono" style={{ fontSize: "11px", color: "var(--text-secondary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginBottom: "6px" }}>
                  {inc.ip} — {inc.detail}
                </div>
                {/* Action chips */}
                {actions.length > 0 && (
                  <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                    {actions.map((a) => (
                      <span key={a} className="action-chip">{a}</span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          );
        })}

        {limit && incidents.length > limit && (
          <p style={{ fontSize: "11px", color: "var(--text-muted)", textAlign: "center", paddingTop: "4px" }}>
            +{incidents.length - limit} more — see Investigate tab
          </p>
        )}
      </div>
    </div>
  );
}