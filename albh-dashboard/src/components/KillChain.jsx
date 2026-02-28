import { Crosshair, Unlock, Cpu, Radio, Database } from "lucide-react";

const STAGES = [
  {
    id:    "recon",
    label: "Reconnaissance",
    icon:  Crosshair,
    desc:  "Attacker probing / scanning",
    detect: ({ auth_logs = [] }) =>
      auth_logs.filter((r) => r.action?.includes("Failed")).length >= 5,
  },
  {
    id:    "access",
    label: "Initial Access",
    icon:  Unlock,
    desc:  "Credential brute-force / phishing",
    detect: ({ auth_logs = [] }) =>
      auth_logs.filter((r) => r.action?.includes("Failed")).length >= 50,
  },
  {
    id:    "execution",
    label: "Execution",
    icon:  Cpu,
    desc:  "Malware installed / run",
    detect: ({ malware_alerts = [] }) => malware_alerts.length > 0,
  },
  {
    id:    "c2",
    label: "C2 Beacon",
    icon:  Radio,
    desc:  "Callback to attacker infrastructure",
    detect: ({ dns_logs = [] }) => {
      const bad = ["bad-actor", "phish", "malware", "c2", ".ru", ".xyz", ".tk", ".pw"];
      return dns_logs.some((r) => bad.some((d) => r.domain_queried?.includes(d)));
    },
  },
  {
    id:    "exfil",
    label: "Exfiltration",
    icon:  Database,
    desc:  "Data leaving the network",
    detect: ({ firewall_logs = [] }) =>
      firewall_logs.filter((r) => r.action === "Block" && r.destination_port === "443").length > 20,
  },
];

export default function KillChain({ data }) {
  const activeStages = new Set(
    STAGES.filter((s) => s.detect(data)).map((s) => s.id)
  );

  const activeCount = activeStages.size;

  return (
    <div className="card col-span-2">
      <div className="card-title" style={{ marginBottom: "18px" }}>
        <Crosshair size={14} />
        Attack Kill Chain
        {activeCount > 0 && (
          <span className="badge badge-critical" style={{ marginLeft: "auto" }}>
            {activeCount} stage{activeCount > 1 ? "s" : ""} detected
          </span>
        )}
        {activeCount === 0 && (
          <span className="badge badge-low" style={{ marginLeft: "auto" }}>
            No stages detected
          </span>
        )}
      </div>

      <div className="kill-chain">
        {STAGES.map((stage, i) => {
          const isActive   = activeStages.has(stage.id);
          const isLast     = i === STAGES.length - 1;
          const Icon       = stage.icon;
          const arrowActive = isActive && !isLast && activeStages.has(STAGES[i + 1]?.id);

          return (
            <div key={stage.id} className="kill-chain-step">
              <div className={`kill-chain-node ${isActive ? "active" : "inactive"}`}>
                <Icon
                  size={18}
                  style={{ color: isActive ? "var(--red)" : "var(--text-muted)" }}
                />
                <span style={{
                  fontSize: "10px",
                  fontWeight: 700,
                  letterSpacing: "0.06em",
                  textTransform: "uppercase",
                  color: isActive ? "var(--red)" : "var(--text-muted)",
                  fontFamily: "'Share Tech Mono', monospace",
                }}>
                  {stage.label}
                </span>
                <span style={{
                  fontSize: "10px",
                  color: isActive ? "var(--text-secondary)" : "var(--text-muted)",
                  lineHeight: 1.3,
                }}>
                  {stage.desc}
                </span>
                {isActive && (
                  <span className="badge badge-critical" style={{ fontSize: "9px", padding: "1px 6px" }}>
                    DETECTED
                  </span>
                )}
              </div>
              {!isLast && (
                <div className={`kill-chain-arrow ${arrowActive ? "active" : "inactive"}`} />
              )}
            </div>
          );
        })}
      </div>

      {activeCount > 0 && (
        <p style={{
          marginTop: "14px",
          fontSize: "12px",
          color: "var(--text-secondary)",
          fontFamily: "'Share Tech Mono', monospace",
          borderTop: "1px solid var(--border)",
          paddingTop: "12px",
        }}>
          ⚠ Attack progression detected across {activeCount} kill chain stage{activeCount > 1 ? "s" : ""}.
          {activeStages.has("c2") && " C2 beacon confirmed — host isolation recommended immediately."}
          {activeStages.has("execution") && !activeStages.has("c2") && " Malware execution confirmed — initiate endpoint investigation."}
        </p>
      )}
    </div>
  );
}